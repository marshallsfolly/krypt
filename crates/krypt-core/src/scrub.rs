//! Removes location and camera metadata from photos and videos before they
//! are sent.
//!
//! Phones write where a photo was taken, and with what, into the file
//! itself: EXIF and XMP in images, `udta` and `meta` boxes in videos. krypt
//! strips them on the sender's device, so recipients (and anyone a file is
//! forwarded to) get the picture and nothing else.
//!
//! Nothing is re-encoded. JPEG, PNG and WebP are rewritten without their
//! metadata, byte for byte identical otherwise. MP4 and QuickTime files are
//! edited in place: each metadata box becomes padding (`free`) of the same
//! size, so no offset in the file moves, and a long video's `moov` box can be
//! scrubbed on its own. The one piece of EXIF kept is a JPEG's orientation,
//! without which photos display rotated.
//!
//! Every parser here reads hostile input: lengths are checked before use,
//! every step consumes input, and a file that does not parse is refused
//! rather than sent half scrubbed.

/// Largest image the scrubber reads whole (larger photos are rejected).
pub const IMAGE_MAX: usize = 32 * 1024 * 1024;
/// MP4 boxes visited per call. A real video has a few thousand.
const MP4_BOXES_MAX: usize = 1 << 20;
/// Box nesting the MP4 walk follows; `moov/trak/mdia` is three deep.
const MP4_DEPTH_MAX: usize = 16;
/// The most a scrubbed image grows by: the EXIF segment carrying only the
/// orientation.
const ORIENTATION_SEGMENT_SIZE: usize = 36;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ScrubError {
    #[error("unsupported format")]
    Unsupported,
    #[error("malformed file")]
    Malformed,
    #[error("too large")]
    TooLarge,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Jpeg,
    Png,
    Webp,
    Mp4,
    Gif,
    /// WebM or Matroska (EBML).
    Webm,
    /// HEIF, AVIF and other still images in ISO-BMFF boxes: cleaned only
    /// by drawing them again.
    StillImage,
}

use ScrubError::{Malformed, TooLarge, Unsupported};

/// ISO-BMFF brands of still images (HEIF, AVIF, Canon raw). They share
/// MP4's box structure, but their top-level `meta` box *is* the image, so
/// they must never be scrubbed as video.
const STILL_IMAGE_BRANDS: [&[u8; 4]; 11] = [
    b"heic", b"heix", b"hevc", b"hevx", b"heim", b"heis", b"mif1", b"msf1", b"avif", b"avis",
    b"crx ",
];

/// Detects the format from magic bytes (MP4/MOV: an `ftyp` box first, or a
/// top-level box type of moov/mdat/wide/free/skip for old QuickTime).
pub fn detect(prefix: &[u8]) -> Option<Format> {
    if prefix.starts_with(&[0xFF, JPEG_SOI, 0xFF]) {
        return Some(Format::Jpeg);
    }
    if prefix.starts_with(PNG_SIGNATURE) {
        return Some(Format::Png);
    }
    if prefix.get(..4) == Some(&b"RIFF"[..]) && prefix.get(8..12) == Some(&b"WEBP"[..]) {
        return Some(Format::Webp);
    }
    if prefix.starts_with(b"GIF87a") || prefix.starts_with(b"GIF89a") {
        return Some(Format::Gif);
    }
    if prefix.starts_with(&[0x1A, 0x45, 0xDF, 0xA3]) {
        return Some(Format::Webm);
    }
    match prefix.get(4..8)? {
        b"ftyp" => {
            let brand = prefix.get(8..12)?;
            Some(
                if STILL_IMAGE_BRANDS.iter().any(|b| b.as_slice() == brand) {
                    Format::StillImage
                } else {
                    Format::Mp4
                },
            )
        }
        b"moov" | b"mdat" | b"wide" | b"free" | b"skip" | b"pnot" => Some(Format::Mp4),
        _ => None,
    }
}

/// JPEG, PNG and WebP: returns the image without metadata.
pub fn scrub_image(bytes: &[u8]) -> Result<Vec<u8>, ScrubError> {
    if bytes.len() > IMAGE_MAX {
        return Err(TooLarge);
    }
    let out = match detect(bytes) {
        Some(Format::Jpeg) => scrub_jpeg(bytes)?,
        Some(Format::Png) => scrub_png(bytes)?,
        Some(Format::Webp) => scrub_webp(bytes)?,
        Some(Format::Gif) => scrub_gif(bytes)?,
        Some(Format::Mp4 | Format::Webm | Format::StillImage) | None => return Err(Unsupported),
    };
    assert!(out.len() <= bytes.len() + ORIENTATION_SEGMENT_SIZE);
    Ok(out)
}

fn array<const N: usize>(bytes: &[u8], at: usize) -> Result<[u8; N], ScrubError> {
    let end = at.checked_add(N).ok_or(Malformed)?;
    let slice = bytes.get(at..end).ok_or(Malformed)?;
    Ok(slice.try_into().expect("slice of length N"))
}

fn length(n: u32) -> Result<usize, ScrubError> {
    usize::try_from(n).map_err(|_| Malformed)
}

// ---- JPEG -------------------------------------------------------------------

const JPEG_SOI: u8 = 0xD8;
const JPEG_EOI: u8 = 0xD9;
const JPEG_SOS: u8 = 0xDA;
const JPEG_APP0: u8 = 0xE0;
const JPEG_APP1: u8 = 0xE1;
const JPEG_APP2: u8 = 0xE2;
const JPEG_APP14: u8 = 0xEE;
const JPEG_COM: u8 = 0xFE;
const EXIF_HEADER: &[u8] = b"Exif\0\0";
const ICC_HEADER: &[u8] = b"ICC_PROFILE\0";
const ADOBE_HEADER: &[u8] = b"Adobe";
const ORIENTATION_TAG: u16 = 0x0112;
const TIFF_SHORT: u16 = 3;

/// Keeps the segments a decoder needs (tables, frame and scan headers, the
/// scans themselves), APP0 (JFIF), the ICC colour profile and the Adobe
/// colour-transform flag; drops every other APPn segment (EXIF, XMP, IPTC,
/// maker data) and comments. Anything after the end-of-image marker (on
/// phones: preview, depth and gain-map images, each with metadata of its
/// own) is dropped too.
fn scrub_jpeg(bytes: &[u8]) -> Result<Vec<u8>, ScrubError> {
    if bytes.get(..2) != Some(&[0xFF, JPEG_SOI][..]) {
        return Err(Malformed);
    }
    let mut out = Vec::with_capacity(bytes.len() + ORIENTATION_SEGMENT_SIZE);
    out.extend_from_slice(&[0xFF, JPEG_SOI]);
    // The orientation goes after SOI and the APP0 segments leading the file.
    let mut insert_at = out.len();
    let mut leading = true;
    let mut orientation = None;
    let mut exif_seen = false;
    let mut scanned = false;
    let mut pos = 2;
    loop {
        // A marker: 0xFF, any number of fill bytes (0xFF), then its code.
        if bytes.get(pos) != Some(&0xFF) {
            return Err(Malformed);
        }
        while bytes.get(pos) == Some(&0xFF) {
            pos += 1;
        }
        let Some(&marker) = bytes.get(pos) else {
            return Err(Malformed);
        };
        pos += 1;
        match marker {
            0x00 | JPEG_SOI => return Err(Malformed),
            JPEG_EOI => {
                out.extend_from_slice(&[0xFF, JPEG_EOI]);
                break;
            }
            // Markers without a length: TEM, and restarts outside a scan.
            0x01 | 0xD0..=0xD7 => {
                out.extend_from_slice(&[0xFF, marker]);
                leading = false;
                continue;
            }
            _ => {}
        }
        let size = usize::from(u16::from_be_bytes(array(bytes, pos)?));
        if size < 2 {
            return Err(Malformed);
        }
        let end = pos
            .checked_add(size)
            .filter(|end| *end <= bytes.len())
            .ok_or(Malformed)?;
        let payload = &bytes[pos + 2..end];
        let keep = match marker {
            JPEG_APP0 => true,
            JPEG_APP1 => {
                if !exif_seen && payload.starts_with(EXIF_HEADER) {
                    exif_seen = true;
                    orientation = tiff_orientation(&payload[EXIF_HEADER.len()..]);
                }
                false
            }
            JPEG_APP2 => payload.starts_with(ICC_HEADER),
            JPEG_APP14 => payload.starts_with(ADOBE_HEADER),
            0xE3..=0xEF | JPEG_COM => false,
            _ => true,
        };
        if keep {
            out.extend_from_slice(&[0xFF, marker]);
            out.extend_from_slice(&bytes[pos..end]);
            if leading && marker == JPEG_APP0 {
                insert_at = out.len();
            } else {
                leading = false;
            }
        }
        pos = end;
        if marker == JPEG_SOS {
            scanned = true;
            let data_end = entropy_end(bytes, pos);
            out.extend_from_slice(&bytes[pos..data_end]);
            pos = data_end;
            // A file cut off inside its last scan keeps what there is.
            if pos == bytes.len() {
                break;
            }
        }
    }
    if !scanned {
        return Err(Malformed);
    }
    if let Some(orientation) = orientation.filter(|o| *o != 1) {
        out.splice(insert_at..insert_at, orientation_segment(orientation));
    }
    Ok(out)
}

/// Where the entropy-coded data starting at `pos` ends: at the next marker
/// that is neither a stuffed zero (0xFF00) nor a restart (RSTn), or at the
/// end of the input.
fn entropy_end(bytes: &[u8], mut pos: usize) -> usize {
    while let Some(offset) = bytes[pos..].iter().position(|b| *b == 0xFF) {
        pos += offset;
        match bytes.get(pos + 1) {
            Some(0x00 | 0xD0..=0xD7) => pos += 2,
            Some(_) => return pos,
            None => break,
        }
    }
    bytes.len()
}

/// The orientation in an EXIF TIFF structure's first IFD, if valid (1-8).
fn tiff_orientation(tiff: &[u8]) -> Option<u16> {
    let big = match tiff.get(..2)? {
        b"MM" => true,
        b"II" => false,
        _ => return None,
    };
    let u16_at = |at: usize| -> Option<u16> {
        let bytes = array(tiff, at).ok()?;
        Some(if big {
            u16::from_be_bytes(bytes)
        } else {
            u16::from_le_bytes(bytes)
        })
    };
    let u32_at = |at: usize| -> Option<u32> {
        let bytes = array(tiff, at).ok()?;
        Some(if big {
            u32::from_be_bytes(bytes)
        } else {
            u32::from_le_bytes(bytes)
        })
    };
    if u16_at(2)? != 42 {
        return None;
    }
    let ifd = usize::try_from(u32_at(4)?).ok()?;
    for i in 0..usize::from(u16_at(ifd)?) {
        let entry = ifd.checked_add(2 + i * 12)?;
        if u16_at(entry)? == ORIENTATION_TAG {
            let value = u16_at(entry + 8)?;
            let valid = u16_at(entry + 2)? == TIFF_SHORT
                && u32_at(entry + 4)? >= 1
                && (1..=8).contains(&value);
            return valid.then_some(value);
        }
    }
    None
}

/// An APP1 segment whose EXIF holds only the orientation.
fn orientation_segment(orientation: u16) -> [u8; ORIENTATION_SEGMENT_SIZE] {
    assert!((2..=8).contains(&orientation));
    let mut segment = [0u8; ORIENTATION_SEGMENT_SIZE];
    let [high, low] = orientation.to_be_bytes();
    let parts: [&[u8]; 7] = [
        &[0xFF, JPEG_APP1, 0, 34], // marker, then the length after it
        EXIF_HEADER,
        b"MM\0\x2a\0\0\0\x08", // big-endian TIFF, IFD0 right after
        &[0, 1],               // one entry
        &[0x01, 0x12, 0, 3, 0, 0, 0, 1],
        &[high, low, 0, 0],
        &[0, 0, 0, 0], // no next IFD
    ];
    let mut at = 0;
    for part in parts {
        segment[at..at + part.len()].copy_from_slice(part);
        at += part.len();
    }
    assert_eq!(at, ORIENTATION_SEGMENT_SIZE);
    segment
}

// ---- PNG --------------------------------------------------------------------

const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
/// Chunks a PNG keeps: the critical ones, colour and transparency, pixel
/// density and animation. Text, EXIF, timestamps and private chunks go.
const PNG_KEPT: [&[u8; 4]; 18] = [
    b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"gAMA", b"cHRM", b"sRGB", b"iCCP", b"sBIT",
    b"bKGD", b"pHYs", b"acTL", b"fcTL", b"fdAT", b"cICP", b"mDCV", b"cLLi",
];
/// The largest chunk length the PNG specification allows.
const PNG_CHUNK_MAX: usize = 0x7FFF_FFFF;

fn scrub_png(bytes: &[u8]) -> Result<Vec<u8>, ScrubError> {
    if !bytes.starts_with(PNG_SIGNATURE) {
        return Err(Malformed);
    }
    let mut out = Vec::with_capacity(bytes.len());
    out.extend_from_slice(PNG_SIGNATURE);
    let mut pos = PNG_SIGNATURE.len();
    loop {
        let size = length(u32::from_be_bytes(array(bytes, pos)?))?;
        let kind: [u8; 4] = array(bytes, pos + 4)?;
        if size > PNG_CHUNK_MAX || !kind.iter().all(u8::is_ascii_alphabetic) {
            return Err(Malformed);
        }
        if pos == PNG_SIGNATURE.len() && &kind != b"IHDR" {
            return Err(Malformed);
        }
        // Length, type, data, CRC.
        let end = pos
            .checked_add(12 + size)
            .filter(|end| *end <= bytes.len())
            .ok_or(Malformed)?;
        if PNG_KEPT.contains(&&kind) {
            out.extend_from_slice(&bytes[pos..end]);
        }
        pos = end;
        if &kind == b"IEND" {
            return Ok(out);
        }
    }
}

// ---- WebP -------------------------------------------------------------------

const VP8X_EXIF: u8 = 0x08;
const VP8X_XMP: u8 = 0x04;
const VP8X_SIZE: usize = 10;

/// Keeps the image chunks (lossy, lossless, alpha, animation) and the ICC
/// profile; drops EXIF, XMP and unknown chunks, and clears the extended
/// header's flags for the dropped metadata.
fn scrub_webp(bytes: &[u8]) -> Result<Vec<u8>, ScrubError> {
    if bytes.get(..4) != Some(&b"RIFF"[..]) || bytes.get(8..12) != Some(&b"WEBP"[..]) {
        return Err(Malformed);
    }
    // Anything past the RIFF size is not part of the image.
    let end = length(u32::from_le_bytes(array(bytes, 4)?))?
        .checked_add(8)
        .filter(|end| (12..=bytes.len()).contains(end))
        .ok_or(Malformed)?;
    let mut out = Vec::with_capacity(end + 1);
    out.extend_from_slice(b"RIFF\0\0\0\0WEBP");
    let mut image = false;
    let mut pos = 12;
    while pos < end {
        if end - pos < 8 {
            return Err(Malformed);
        }
        let kind: [u8; 4] = array(bytes, pos)?;
        let size = length(u32::from_le_bytes(array(bytes, pos + 4)?))?;
        let data_end = (pos + 8)
            .checked_add(size)
            .filter(|data_end| *data_end <= end)
            .ok_or(Malformed)?;
        let keep = match &kind {
            b"VP8 " | b"VP8L" | b"ANMF" => {
                image = true;
                true
            }
            b"VP8X" => {
                if size < VP8X_SIZE {
                    return Err(Malformed);
                }
                true
            }
            b"ALPH" | b"ANIM" | b"ICCP" => true,
            _ => false,
        };
        if keep {
            let at = out.len();
            out.extend_from_slice(&bytes[pos..data_end]);
            if &kind == b"VP8X" {
                out[at + 8] &= !(VP8X_EXIF | VP8X_XMP);
            }
            // Chunks are padded to an even size.
            if size % 2 == 1 {
                out.push(0);
            }
        }
        pos = (data_end + size % 2).min(end);
    }
    if !image {
        return Err(Malformed);
    }
    let riff_size = u32::try_from(out.len() - 8).expect("no larger than the input");
    out[4..8].copy_from_slice(&riff_size.to_le_bytes());
    Ok(out)
}

// ---- MP4 / QuickTime ----------------------------------------------------------

/// Boxes that hold metadata: user data (QuickTime's `©xyz` location, camera
/// make and model), `meta` (iPhones' location keys) and `uuid` (XMP).
const MP4_METADATA: [&[u8; 4]; 3] = [b"udta", b"meta", b"uuid"];
/// Containers the walk enters: those metadata boxes can sit in. The sample
/// tables below `minf` hold no metadata and are left unread.
const MP4_CONTAINERS: [&[u8; 4]; 5] = [b"moov", b"trak", b"mdia", b"moof", b"traf"];

/// MP4/MOV, in place: every metadata box becomes a `free` box of the same
/// size with zeroed contents, so no offsets change. `bytes` is either the
/// whole file or just one top-level box (the parent passes the `moov` box
/// alone for large videos, read by slicing). Returns how many boxes were
/// blanked.
pub fn scrub_mp4(bytes: &mut [u8]) -> Result<usize, ScrubError> {
    let mut walk = Mp4Walk {
        boxes: 0,
        blanked: 0,
    };
    walk.run(bytes, 0)?;
    Ok(walk.blanked)
}

struct Mp4Walk {
    boxes: usize,
    blanked: usize,
}

impl Mp4Walk {
    fn run(&mut self, region: &mut [u8], depth: usize) -> Result<(), ScrubError> {
        if depth > MP4_DEPTH_MAX {
            return Err(Malformed);
        }
        let mut pos = 0;
        while pos < region.len() {
            let rest = region.len() - pos;
            if rest < 8 {
                // QuickTime may end a list of atoms with a 32-bit zero.
                if region[pos..].iter().all(|b| *b == 0) {
                    break;
                }
                return Err(Malformed);
            }
            self.boxes += 1;
            if self.boxes > MP4_BOXES_MAX {
                return Err(TooLarge);
            }
            let kind: [u8; 4] = array(region, pos + 4)?;
            let (header, size) = match u32::from_be_bytes(array(region, pos)?) {
                // To the end of the enclosing region.
                0 => (8, rest),
                1 => {
                    let large = u64::from_be_bytes(array(region, pos + 8)?);
                    (16, usize::try_from(large).map_err(|_| Malformed)?)
                }
                n => (8, length(n)?),
            };
            if size < header || size > rest {
                return Err(Malformed);
            }
            let (head, body) = region[pos..pos + size].split_at_mut(header);
            if MP4_METADATA.contains(&&kind) {
                head[4..8].copy_from_slice(b"free");
                body.fill(0);
                self.blanked += 1;
            } else if MP4_CONTAINERS.contains(&&kind) {
                self.run(body, depth + 1)?;
            }
            pos += size;
        }
        Ok(())
    }
}

// ---- WebM / Matroska ----------------------------------------------------------

/// EBML element ids, with their length-marker bits, as they appear.
const EBML_HEADER: u32 = 0x1A45_DFA3;
const SEGMENT: u32 = 0x1853_8067;
const SEEK_HEAD: u32 = 0x114D_9B74;
const INFO: u32 = 0x1549_A966;
const TRACKS: u32 = 0x1654_AE6B;
const TRACK_ENTRY: u32 = 0xAE;
const CLUSTER: u32 = 0x1F43_B675;
const CUES: u32 = 0x1C53_BB6B;
const TAGS: u32 = 0x1254_C367;
const CHAPTERS: u32 = 0x1043_A770;
const ATTACHMENTS: u32 = 0x1941_A469;
const EBML_VOID: u32 = 0xEC;
const EBML_CRC32: u32 = 0xBF;
/// What a recorder writes about itself and the recording: the app, the
/// browser, a title, the time, a track's name.
const WEBM_TEXT: [u32; 4] = [0x4D80, 0x5741, 0x7BA9, 0x536E];
const DATE_UTC: u32 = 0x4461;
/// Segment-level elements that are metadata through and through.
const WEBM_METADATA: [u32; 3] = [TAGS, CHAPTERS, ATTACHMENTS];
/// Segment-level elements kept as they are.
const WEBM_KEPT: [u32; 4] = [SEEK_HEAD, CUES, EBML_VOID, EBML_CRC32];
/// What a cluster holds: its timestamp, blocks, position and padding.
const CLUSTER_CHILDREN: [u32; 7] = [0xE7, 0xA3, 0xA0, 0xA7, 0xAB, EBML_VOID, EBML_CRC32];
/// Elements visited per call. A 15-minute voice message has a few thousand.
const WEBM_ELEMENTS_MAX: usize = 1 << 20;

/// An element's header: id, where its contents start, and their size (none
/// for "unknown", which only segments and clusters may use).
struct Element {
    id: u32,
    data: usize,
    size: Option<usize>,
}

fn webm_element(bytes: &[u8], at: usize) -> Result<Element, ScrubError> {
    let first = *bytes.get(at).ok_or(Malformed)?;
    let id_len = first.leading_zeros() as usize + 1;
    if id_len > 4 {
        return Err(Malformed);
    }
    let id_bytes = bytes.get(at..at + id_len).ok_or(Malformed)?;
    let id = id_bytes
        .iter()
        .fold(0u32, |acc, b| (acc << 8) | u32::from(*b));
    let size_at = at + id_len;
    let lead = *bytes.get(size_at).ok_or(Malformed)?;
    let size_len = lead.leading_zeros() as usize + 1;
    if size_len > 8 {
        return Err(Malformed);
    }
    let raw = bytes.get(size_at..size_at + size_len).ok_or(Malformed)?;
    let marker = 1u64 << (7 * size_len);
    let value = raw.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b)) & (marker - 1);
    let size = if value == marker - 1 {
        None
    } else {
        Some(usize::try_from(value).map_err(|_| Malformed)?)
    };
    Ok(Element {
        id,
        data: size_at + size_len,
        size,
    })
}

/// WebM (Matroska), in place: the recorder's name, the browser's, a title,
/// the date and track names are zeroed (strings may be zero-padded), and
/// tags, chapters and attachments become padding (`Void`) of the same size,
/// so nothing moves. Returns how many elements were scrubbed. Anything that
/// does not parse as the WebM a recorder writes is refused.
pub fn scrub_webm(bytes: &mut [u8]) -> Result<usize, ScrubError> {
    let mut walk = WebmWalk {
        elements: 0,
        scrubbed: 0,
    };
    let header = webm_element(bytes, 0)?;
    if header.id != EBML_HEADER {
        return Err(Unsupported);
    }
    let mut at = header
        .data
        .checked_add(header.size.ok_or(Malformed)?)
        .ok_or(Malformed)?;
    let segment = webm_element(bytes, at)?;
    if segment.id != SEGMENT {
        return Err(Malformed);
    }
    let end = match segment.size {
        Some(size) => segment
            .data
            .checked_add(size)
            .filter(|e| *e <= bytes.len())
            .ok_or(Malformed)?,
        None => bytes.len(),
    };
    at = segment.data;
    while at < end {
        at = walk.segment_child(bytes, at, end)?;
    }
    Ok(walk.scrubbed)
}

struct WebmWalk {
    elements: usize,
    scrubbed: usize,
}

impl WebmWalk {
    /// An element of known size inside `[at, end)`: its contents' range.
    fn known(
        &mut self,
        bytes: &[u8],
        at: usize,
        end: usize,
    ) -> Result<(Element, usize), ScrubError> {
        self.elements += 1;
        if self.elements > WEBM_ELEMENTS_MAX {
            return Err(TooLarge);
        }
        let element = webm_element(bytes, at)?;
        let stop = element
            .data
            .checked_add(element.size.ok_or(Malformed)?)
            .filter(|stop| *stop <= end)
            .ok_or(Malformed)?;
        Ok((element, stop))
    }

    /// One child of the segment at `at`; returns where the next one starts.
    fn segment_child(
        &mut self,
        bytes: &mut [u8],
        at: usize,
        end: usize,
    ) -> Result<usize, ScrubError> {
        let element = webm_element(bytes, at)?;
        if element.id == CLUSTER && element.size.is_none() {
            return self.open_cluster(bytes, element.data, end);
        }
        let (element, stop) = self.known(bytes, at, end)?;
        match element.id {
            INFO => self.text_in(bytes, element.data, stop)?,
            TRACKS => {
                let mut child = element.data;
                while child < stop {
                    let (entry, next) = self.known(bytes, child, stop)?;
                    if entry.id == TRACK_ENTRY {
                        self.text_in(bytes, entry.data, next)?;
                    }
                    child = next;
                }
            }
            id if WEBM_METADATA.contains(&id) => {
                void(bytes, at, stop)?;
                self.scrubbed += 1;
            }
            id if id == CLUSTER || WEBM_KEPT.contains(&id) => {}
            _ => return Err(Malformed),
        }
        Ok(stop)
    }

    /// A cluster of unknown size (as a recorder streams them): its blocks
    /// run until the next segment-level element, or the end.
    fn open_cluster(
        &mut self,
        bytes: &[u8],
        mut at: usize,
        end: usize,
    ) -> Result<usize, ScrubError> {
        while at < end {
            let next = webm_element(bytes, at)?;
            if !CLUSTER_CHILDREN.contains(&next.id) {
                return Ok(at);
            }
            at = self.known(bytes, at, end)?.1;
        }
        Ok(at)
    }

    /// Zeroes the recorder's text and the date among the children in
    /// `[at, stop)`.
    fn text_in(&mut self, bytes: &mut [u8], mut at: usize, stop: usize) -> Result<(), ScrubError> {
        while at < stop {
            let (child, next) = self.known(bytes, at, stop)?;
            if WEBM_TEXT.contains(&child.id) || child.id == DATE_UTC {
                bytes[child.data..next].fill(0);
                self.scrubbed += 1;
            }
            at = next;
        }
        Ok(())
    }
}

/// Rewrites `[at, stop)` as a `Void` element of the same length.
fn void(bytes: &mut [u8], at: usize, stop: usize) -> Result<(), ScrubError> {
    let total = stop - at;
    // The size field's length: the shortest that fits what is left.
    let size_len = (1..=8usize)
        .find(|len| {
            total
                .checked_sub(1 + len)
                .is_some_and(|payload| (payload as u64) < (1u64 << (7 * len)) - 1)
        })
        .ok_or(Malformed)?;
    let payload = (total - 1 - size_len) as u64;
    bytes[at] = 0xEC;
    let field = (payload | (1u64 << (7 * size_len))).to_be_bytes();
    bytes[at + 1..at + 1 + size_len].copy_from_slice(&field[8 - size_len..]);
    bytes[at + 1 + size_len..stop].fill(0);
    Ok(())
}

// ---- GIF --------------------------------------------------------------------

const GIF_IMAGE: u8 = 0x2C;
const GIF_EXTENSION: u8 = 0x21;
const GIF_TRAILER: u8 = 0x3B;
const GIF_GRAPHIC_CONTROL: u8 = 0xF9;
const GIF_APPLICATION: u8 = 0xFF;
/// Application extensions kept: how many times an animation loops.
const GIF_LOOPING: [&[u8; 11]; 2] = [b"NETSCAPE2.0", b"ANIMEXTS1.0"];
const GIF_BLOCKS_MAX: usize = 1 << 20;

/// A GIF's frames, colours and timing, and nothing else: comments, plain
/// text, XMP and other application data, and anything after the end, go.
fn scrub_gif(bytes: &[u8]) -> Result<Vec<u8>, ScrubError> {
    // Header and logical screen descriptor, then the global colour table.
    let mut at = 13;
    let packed = *bytes.get(10).ok_or(Malformed)?;
    if packed & 0x80 != 0 {
        at += 3 << ((packed & 7) + 1);
    }
    let mut out = bytes.get(..at).ok_or(Malformed)?.to_vec();
    // The sub-blocks from `at` (each a length byte and data, a zero length
    // ending them): where they end.
    let sub_blocks = |mut at: usize| -> Result<usize, ScrubError> {
        loop {
            let len = usize::from(*bytes.get(at).ok_or(Malformed)?);
            at += 1;
            if len == 0 {
                return Ok(at);
            }
            at = at
                .checked_add(len)
                .filter(|&end| end <= bytes.len())
                .ok_or(Malformed)?;
        }
    };
    for _ in 0..GIF_BLOCKS_MAX {
        let Some(&introducer) = bytes.get(at) else {
            // Ended without a trailer, as some writers do.
            out.push(GIF_TRAILER);
            return Ok(out);
        };
        match introducer {
            GIF_IMAGE => {
                let packed = *bytes.get(at + 9).ok_or(Malformed)?;
                let mut data = at + 10;
                if packed & 0x80 != 0 {
                    data += 3 << ((packed & 7) + 1);
                }
                // The LZW code size, then the image's sub-blocks.
                let end = sub_blocks(data + 1)?;
                out.extend_from_slice(bytes.get(at..end).ok_or(Malformed)?);
                at = end;
            }
            GIF_EXTENSION => {
                let label = *bytes.get(at + 1).ok_or(Malformed)?;
                let end = sub_blocks(at + 2)?;
                let keep = match label {
                    GIF_GRAPHIC_CONTROL => true,
                    GIF_APPLICATION => {
                        bytes.get(at + 2) == Some(&11)
                            && bytes
                                .get(at + 3..at + 14)
                                .is_some_and(|id| GIF_LOOPING.iter().any(|l| l.as_slice() == id))
                    }
                    _ => false,
                };
                if keep {
                    out.extend_from_slice(&bytes[at..end]);
                }
                at = end;
            }
            GIF_TRAILER => {
                out.push(GIF_TRAILER);
                return Ok(out);
            }
            _ => return Err(Malformed),
        }
    }
    Err(TooLarge)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 1×1 GIF89a with a comment, XMP, a looping extension, a graphic
    /// control block, one frame, and bytes hidden after its end.
    fn gif() -> Vec<u8> {
        let mut g = b"GIF89a".to_vec();
        g.extend_from_slice(&[1, 0, 1, 0, 0x80, 0, 0]); // 1x1, 2-colour table
        g.extend_from_slice(&[0, 0, 0, 255, 255, 255]);
        g.extend_from_slice(&[0x21, 0xFE, 5]);
        g.extend_from_slice(b"hello");
        g.push(0);
        g.extend_from_slice(&[0x21, 0xFF, 11]);
        g.extend_from_slice(b"XMP DataXMP");
        g.extend_from_slice(&[4]);
        g.extend_from_slice(b"gps!");
        g.push(0);
        g.extend_from_slice(&[0x21, 0xFF, 11]);
        g.extend_from_slice(b"NETSCAPE2.0");
        g.extend_from_slice(&[3, 1, 0, 0, 0]);
        g.extend_from_slice(&[0x21, 0xF9, 4, 0, 10, 0, 0, 0]);
        g.extend_from_slice(&[0x2C, 0, 0, 0, 0, 1, 0, 1, 0, 0]);
        g.extend_from_slice(&[2, 2, 0x4C, 0x01, 0]);
        g.push(0x3B);
        g.extend_from_slice(b"secret");
        g
    }

    #[test]
    fn a_gif_keeps_its_frames_and_loses_everything_else() {
        let clean = scrub_image(&gif()).expect("scrubs");
        let text = String::from_utf8_lossy(&clean);
        for gone in ["hello", "XMP", "gps!", "secret"] {
            assert!(!text.contains(gone), "{gone} survived");
        }
        assert!(text.contains("NETSCAPE2.0"), "the loop count stays");
        assert_eq!(clean.last(), Some(&0x3B));
        // Clean already: nothing more to take.
        assert_eq!(scrub_image(&clean).expect("scrubs again"), clean);
        // Damaged ones are refused, not passed through.
        let mut cut = gif();
        cut.truncate(40);
        assert!(scrub_image(&cut).is_err());
    }

    #[test]
    fn detects_what_it_must_not_pass_through() {
        assert_eq!(detect(b"GIF89a\x01\x00"), Some(Format::Gif));
        assert_eq!(detect(&[0x1A, 0x45, 0xDF, 0xA3, 0x9F]), Some(Format::Webm));
        assert_eq!(
            detect(b"\0\0\0\x18ftypheic\0\0\0\0"),
            Some(Format::StillImage)
        );
        assert_eq!(
            detect(b"\0\0\0\x18ftypavif\0\0\0\0"),
            Some(Format::StillImage)
        );
        assert_eq!(detect(b"\0\0\0\x18ftypisom\0\0\0\0"), Some(Format::Mp4));
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    // ---- JPEG fixtures ----

    fn segment(marker: u8, payload: &[u8]) -> Vec<u8> {
        let size = u16::try_from(payload.len() + 2).unwrap();
        [&[0xFF, marker][..], &size.to_be_bytes(), payload].concat()
    }

    /// A TIFF structure with IFD0 holding the orientation and a pointer to a
    /// GPS IFD with a latitude reference.
    fn tiff(big: bool, orientation: u16) -> Vec<u8> {
        let u16b = |n: u16| {
            if big {
                n.to_be_bytes()
            } else {
                n.to_le_bytes()
            }
        };
        let u32b = |n: u32| {
            if big {
                n.to_be_bytes()
            } else {
                n.to_le_bytes()
            }
        };
        let mut t = Vec::new();
        t.extend_from_slice(if big { b"MM" } else { b"II" });
        t.extend_from_slice(&u16b(42));
        t.extend_from_slice(&u32b(8));
        // IFD0: Make, Orientation, GPS pointer.
        t.extend_from_slice(&u16b(3));
        t.extend_from_slice(&u16b(0x010F));
        t.extend_from_slice(&u16b(2));
        t.extend_from_slice(&u32b(4));
        t.extend_from_slice(b"Cam\0");
        t.extend_from_slice(&u16b(ORIENTATION_TAG));
        t.extend_from_slice(&u16b(TIFF_SHORT));
        t.extend_from_slice(&u32b(1));
        t.extend_from_slice(&u16b(orientation));
        t.extend_from_slice(&[0, 0]);
        t.extend_from_slice(&u16b(0x8825));
        t.extend_from_slice(&u16b(4));
        t.extend_from_slice(&u32b(1));
        t.extend_from_slice(&u32b(50));
        t.extend_from_slice(&u32b(0));
        assert_eq!(t.len(), 50);
        // GPS IFD: one ASCII entry, then the coordinates as text.
        t.extend_from_slice(&u16b(1));
        t.extend_from_slice(&u16b(1));
        t.extend_from_slice(&u16b(2));
        t.extend_from_slice(&u32b(2));
        t.extend_from_slice(b"N\0\0\0");
        t.extend_from_slice(&u32b(0));
        t.extend_from_slice(b"GPS 37.7749 -122.4194");
        t
    }

    fn exif(big: bool, orientation: u16) -> Vec<u8> {
        segment(JPEG_APP1, &[EXIF_HEADER, &tiff(big, orientation)].concat())
    }

    const SCAN: &[u8] = &[0x12, 0xFF, 0x00, 0x34, 0xFF, 0xD3, 0x56, 0xFF, 0x00, 0x78];

    fn tables() -> Vec<u8> {
        [
            segment(0xDB, &[0; 65]),
            segment(0xC0, &[8, 0, 16, 0, 16, 1, 1, 0x11, 0]),
            segment(0xC4, &[0; 20]),
        ]
        .concat()
    }

    /// An EBML element: id bytes, an 8-byte size (or unknown), contents.
    fn ebml(id: &[u8], data: &[u8]) -> Vec<u8> {
        let mut out = id.to_vec();
        out.push(0x01);
        out.extend_from_slice(&(data.len() as u64).to_be_bytes()[1..]);
        out.extend_from_slice(data);
        out
    }

    fn ebml_open(id: &[u8], data: &[u8]) -> Vec<u8> {
        [id, &[0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], data].concat()
    }

    /// What a browser's recorder writes, with every kind of metadata.
    fn webm() -> Vec<u8> {
        let info = [
            ebml(&[0x2A, 0xD7, 0xB1], &[0x0F, 0x42, 0x40]),
            ebml(&[0x4D, 0x80], b"KRYPTLEAK muxer"),
            ebml(&[0x57, 0x41], b"KRYPTLEAK browser"),
            ebml(&[0x7B, 0xA9], b"KRYPTLEAK title"),
            ebml(&[0x44, 0x61], &[0x7F; 8]),
        ]
        .concat();
        let track = [
            ebml(&[0xD7], &[1]),
            ebml(&[0x53, 0x6E], b"KRYPTLEAK mic"),
            ebml(&[0x86], b"A_OPUS"),
        ]
        .concat();
        let tags = ebml(&[0x73, 0x73], &ebml(&[0x67, 0xC8], b"KRYPTLEAK tag"));
        let cluster = [ebml(&[0xE7], &[0]), ebml(&[0xA3], b"opus frames")].concat();
        let segment = [
            ebml(&[0x15, 0x49, 0xA9, 0x66], &info),
            ebml(&[0x16, 0x54, 0xAE, 0x6B], &ebml(&[0xAE], &track)),
            ebml(&[0x12, 0x54, 0xC3, 0x67], &tags),
            ebml_open(&[0x1F, 0x43, 0xB6, 0x75], &cluster),
            ebml_open(&[0x1F, 0x43, 0xB6, 0x75], &cluster),
        ]
        .concat();
        [
            ebml(&[0x1A, 0x45, 0xDF, 0xA3], &ebml(&[0x42, 0x82], b"webm")),
            ebml_open(&[0x18, 0x53, 0x80, 0x67], &segment),
        ]
        .concat()
    }

    #[test]
    fn scrub_webm_zeroes_text_and_voids_tags_in_place() {
        let original = webm();
        let mut file = original.clone();
        assert_eq!(scrub_webm(&mut file), Ok(6));
        assert_eq!(file.len(), original.len(), "nothing moves");
        assert!(!file.windows(9).any(|w| w == b"KRYPTLEAK"), "metadata left");
        assert!(
            file.windows(11).any(|w| w == b"opus frames"),
            "the audio stays"
        );
        assert!(file.windows(6).any(|w| w == b"A_OPUS"));
        // What it wrote still parses, and has nothing left to scrub but the
        // zeroed fields.
        let mut again = file.clone();
        assert_eq!(scrub_webm(&mut again), Ok(5));
        assert_eq!(again, file);
    }

    #[test]
    fn scrub_webm_refuses_what_it_cannot_read() {
        assert_eq!(
            scrub_webm(&mut b"not a webm at all".to_vec()),
            Err(Unsupported)
        );
        let file = webm();
        for cut in [5, 40, file.len() - 3] {
            let mut short = file[..cut].to_vec();
            assert!(scrub_webm(&mut short).is_err(), "cut at {cut}");
        }
        // An element the recorder never writes, at segment level.
        let header = ebml(&[0x1A, 0x45, 0xDF, 0xA3], &[]);
        let odd = [
            header,
            ebml_open(
                &[0x18, 0x53, 0x80, 0x67],
                &ebml(&[0x1B, 0x00, 0x00, 0x01], b"?"),
            ),
        ]
        .concat();
        assert_eq!(scrub_webm(&mut odd.clone()), Err(Malformed));
        // An element claiming more than the file holds.
        let mut long = webm();
        let at = long.len() - 12;
        long.truncate(at);
        long.extend_from_slice(&[0xA3, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00]);
        assert_eq!(scrub_webm(&mut long), Err(Malformed));
    }

    fn sos() -> Vec<u8> {
        segment(JPEG_SOS, &[1, 1, 0, 0, 63, 0])
    }

    fn icc() -> Vec<u8> {
        segment(JPEG_APP2, b"ICC_PROFILE\0\x01\x01colour")
    }

    fn jpeg(orientation: u16) -> Vec<u8> {
        [
            vec![0xFF, JPEG_SOI],
            segment(JPEG_APP0, b"JFIF\0\x01\x02\0\0\x01\0\x01\0\0"),
            exif(true, orientation),
            segment(
                JPEG_APP1,
                b"http://ns.adobe.com/xap/1.0/\0<x:xmpmeta>GPS</x:xmpmeta>",
            ),
            icc(),
            segment(JPEG_APP13, b"Photoshop 3.0\0GPS IPTC"),
            segment(0xE2, b"MPF\0GPS index"),
            segment(JPEG_COM, b"comment GPS"),
            tables(),
            sos(),
            SCAN.to_vec(),
            vec![0xFF, JPEG_EOI],
            b"GPS trailing preview".to_vec(),
        ]
        .concat()
    }

    const JPEG_APP13: u8 = 0xED;

    fn orientation_of(jpeg: &[u8]) -> Option<u16> {
        let at = jpeg
            .windows(EXIF_HEADER.len())
            .position(|w| w == EXIF_HEADER)?;
        tiff_orientation(&jpeg[at + EXIF_HEADER.len()..])
    }

    #[test]
    fn scrub_jpeg_drops_metadata_and_keeps_orientation() {
        let input = jpeg(6);
        assert_eq!(detect(&input), Some(Format::Jpeg));
        let out = scrub_image(&input).unwrap();
        for leak in [
            &b"GPS"[..],
            b"xmpmeta",
            b"comment",
            b"Cam\0",
            b"Photoshop",
            b"MPF",
        ] {
            assert!(contains(&input, leak));
            assert!(!contains(&out, leak), "{}", String::from_utf8_lossy(leak));
        }
        assert!(contains(&out, b"ICC_PROFILE\0\x01\x01colour"));
        assert_eq!(orientation_of(&out), Some(6));
        let expected = [
            vec![0xFF, JPEG_SOI],
            segment(JPEG_APP0, b"JFIF\0\x01\x02\0\0\x01\0\x01\0\0"),
            orientation_segment(6).to_vec(),
            icc(),
            tables(),
            sos(),
            SCAN.to_vec(),
            vec![0xFF, JPEG_EOI],
        ]
        .concat();
        assert_eq!(out, expected);
        assert_eq!(scrub_image(&out).unwrap(), out);
    }

    #[test]
    fn scrub_jpeg_reads_little_endian_exif() {
        let input = [
            vec![0xFF, JPEG_SOI],
            exif(false, 8),
            tables(),
            sos(),
            SCAN.to_vec(),
            vec![0xFF, JPEG_EOI],
        ]
        .concat();
        let out = scrub_image(&input).unwrap();
        assert!(!contains(&out, b"GPS"));
        assert_eq!(orientation_of(&out), Some(8));
        // No APP0: the orientation goes right after SOI.
        assert_eq!(&out[2..4], &[0xFF, JPEG_APP1]);
        assert_eq!(scrub_image(&out).unwrap(), out);
    }

    #[test]
    fn scrub_jpeg_upright_photos_get_no_exif() {
        let out = scrub_image(&jpeg(1)).unwrap();
        assert!(!contains(&out, EXIF_HEADER));
        assert_eq!(orientation_of(&out), None);
    }

    #[test]
    fn scrub_jpeg_progressive_keeps_every_scan() {
        let scan = |n: u8| vec![n, 0xFF, 0x00, n, 0xFF, 0xD0 + n % 8, n];
        let input = [
            vec![0xFF, JPEG_SOI],
            segment(0xDB, &[0; 65]),
            segment(0xC2, &[8, 0, 16, 0, 16, 1, 1, 0x11, 0]),
            segment(0xC4, &[1; 20]),
            sos(),
            scan(1),
            segment(0xC4, &[2; 20]),
            sos(),
            scan(2),
            // An APP1 between scans, behind fill bytes.
            vec![0xFF, 0xFF],
            exif(true, 3),
            segment(0xDD, &[0, 4]),
            sos(),
            scan(3),
            vec![0xFF, 0xFF, 0xFF, JPEG_EOI],
        ]
        .concat();
        let out = scrub_image(&input).unwrap();
        let expected = [
            vec![0xFF, JPEG_SOI],
            orientation_segment(3).to_vec(),
            segment(0xDB, &[0; 65]),
            segment(0xC2, &[8, 0, 16, 0, 16, 1, 1, 0x11, 0]),
            segment(0xC4, &[1; 20]),
            sos(),
            scan(1),
            segment(0xC4, &[2; 20]),
            sos(),
            scan(2),
            segment(0xDD, &[0, 4]),
            sos(),
            scan(3),
            vec![0xFF, JPEG_EOI],
        ]
        .concat();
        assert_eq!(out, expected);
        assert_eq!(scrub_image(&out).unwrap(), out);
    }

    #[test]
    fn scrub_jpeg_refuses_what_is_not_an_image() {
        // Tables but no scan.
        let no_scan = [vec![0xFF, JPEG_SOI], tables(), vec![0xFF, JPEG_EOI]].concat();
        assert_eq!(scrub_image(&no_scan), Err(Malformed));
        // Cut off before the first scan.
        let input = jpeg(6);
        assert_eq!(scrub_image(&input[..40]), Err(Malformed));
        // Cut off inside the scan: what there is is kept.
        let at = input.len() - b"GPS trailing preview".len() - 4;
        let out = scrub_image(&input[..at]).unwrap();
        assert!(!contains(&out, b"GPS"));
        assert_eq!(scrub_image(b"\xFF\xD8\xFF"), Err(Malformed));
        assert_eq!(scrub_image(b"not an image"), Err(Unsupported));
    }

    // ---- PNG fixtures ----

    fn chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
        let size = u32::try_from(data.len()).unwrap();
        [
            &size.to_be_bytes()[..],
            kind,
            data,
            &[0xC0, 0xC1, 0xC2, 0xC3],
        ]
        .concat()
    }

    fn png() -> Vec<u8> {
        [
            PNG_SIGNATURE.to_vec(),
            chunk(b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0]),
            chunk(b"tEXt", b"Comment\0GPS"),
            chunk(b"iCCP", b"profile\0\0data"),
            chunk(b"iTXt", b"XML:com.adobe.xmp\0\0\0\0\0<x:xmpmeta>GPS"),
            chunk(b"eXIf", &tiff(true, 6)),
            chunk(b"IDAT", b"pixels-1"),
            chunk(b"tIME", &[7, 234, 11, 6, 12, 0, 0]),
            chunk(b"IDAT", b"pixels-2"),
            chunk(b"prVt", b"GPS private"),
            chunk(b"IEND", &[]),
            b"GPS trailer".to_vec(),
        ]
        .concat()
    }

    #[test]
    fn scrub_png_drops_text_exif_and_time() {
        let input = png();
        assert_eq!(detect(&input), Some(Format::Png));
        let out = scrub_image(&input).unwrap();
        let expected = [
            PNG_SIGNATURE.to_vec(),
            chunk(b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0]),
            chunk(b"iCCP", b"profile\0\0data"),
            chunk(b"IDAT", b"pixels-1"),
            chunk(b"IDAT", b"pixels-2"),
            chunk(b"IEND", &[]),
        ]
        .concat();
        assert_eq!(out, expected);
        assert!(!contains(&out, b"GPS"));
        assert_eq!(scrub_image(&out).unwrap(), out);
        // No IEND, or IHDR not first.
        assert_eq!(scrub_image(&input[..input.len() - 30]), Err(Malformed));
        let headless = [
            PNG_SIGNATURE.to_vec(),
            chunk(b"IDAT", b"x"),
            chunk(b"IEND", &[]),
        ];
        assert_eq!(scrub_image(&headless.concat()), Err(Malformed));
    }

    // ---- WebP fixtures ----

    fn riff_chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
        let size = u32::try_from(data.len()).unwrap();
        let pad: &[u8] = if data.len() % 2 == 1 { &[0] } else { &[] };
        [kind, &size.to_le_bytes()[..], data, pad].concat()
    }

    fn riff(chunks: &[Vec<u8>]) -> Vec<u8> {
        let body = chunks.concat();
        let size = u32::try_from(body.len() + 4).unwrap();
        [&b"RIFF"[..], &size.to_le_bytes(), b"WEBP", &body].concat()
    }

    fn vp8x(flags: u8) -> Vec<u8> {
        riff_chunk(b"VP8X", &[flags, 0, 0, 0, 9, 0, 0, 9, 0, 0])
    }

    #[test]
    fn scrub_webp_drops_exif_and_xmp() {
        let input = riff(&[
            vp8x(0x20 | VP8X_EXIF | VP8X_XMP | 0x10),
            riff_chunk(b"ICCP", b"icc"),
            riff_chunk(b"ALPH", b"alpha"),
            riff_chunk(b"VP8 ", b"lossy-frame"),
            riff_chunk(b"EXIF", &tiff(false, 6)),
            riff_chunk(b"XMP ", b"<x:xmpmeta>GPS</x:xmpmeta>!"),
            riff_chunk(b"zzzz", b"GPS"),
        ]);
        assert_eq!(detect(&input), Some(Format::Webp));
        let out = scrub_image(&input).unwrap();
        let expected = riff(&[
            vp8x(0x20 | 0x10),
            riff_chunk(b"ICCP", b"icc"),
            riff_chunk(b"ALPH", b"alpha"),
            riff_chunk(b"VP8 ", b"lossy-frame"),
        ]);
        assert_eq!(out, expected);
        assert!(!contains(&out, b"GPS"));
        assert_eq!(scrub_image(&out).unwrap(), out);
    }

    #[test]
    fn scrub_webp_refuses_broken_files() {
        // A chunk running past the RIFF size, and metadata without an image.
        let input = riff(&[riff_chunk(b"VP8L", b"lossless")]);
        let mut long = input.clone();
        long[16] = 200;
        assert_eq!(scrub_image(&long), Err(Malformed));
        let only_exif = riff(&[vp8x(VP8X_EXIF), riff_chunk(b"EXIF", b"GPS")]);
        assert_eq!(scrub_image(&only_exif), Err(Malformed));
        // Data past the RIFF size is dropped.
        let trailing = [input.clone(), b"GPS".to_vec()].concat();
        assert_eq!(scrub_image(&trailing).unwrap(), input);
    }

    // ---- MP4 fixtures ----

    fn mp4_box(kind: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let size = u32::try_from(body.len() + 8).unwrap();
        [&size.to_be_bytes()[..], kind, body].concat()
    }

    fn moov() -> Vec<u8> {
        let location = mp4_box(b"\xa9xyz", b"\0\x12\x15\xc7+37.7749-122.4194/");
        let keys = mp4_box(b"keys", b"com.apple.quicktime.location.ISO6709");
        let ilst = mp4_box(b"ilst", b"+37.7749-122.4194+010.000/");
        let mdia = mp4_box(
            b"mdia",
            &[
                mp4_box(b"mdhd", &[0; 24]),
                mp4_box(b"hdlr", b"\0\0\0\0vide"),
                mp4_box(b"minf", &mp4_box(b"stbl", &mp4_box(b"stco", &[0; 8]))),
            ]
            .concat(),
        );
        let trak = mp4_box(
            b"trak",
            &[
                mp4_box(b"tkhd", &[0; 84]),
                mdia,
                mp4_box(b"udta", &mp4_box(b"\xa9mak", b"Camera Co")),
            ]
            .concat(),
        );
        mp4_box(
            b"moov",
            &[
                mp4_box(b"mvhd", &[0; 100]),
                trak,
                mp4_box(b"udta", &location),
                mp4_box(b"meta", &[mp4_box(b"hdlr", b"mdta"), keys, ilst].concat()),
                // QuickTime's terminating zero.
                vec![0, 0, 0, 0],
            ]
            .concat(),
        )
    }

    const MDAT: &[u8] = b"video samples, untouched: udta meta";

    fn mp4() -> Vec<u8> {
        [
            mp4_box(b"ftyp", b"qt  \0\0\0\0qt  "),
            mp4_box(b"wide", &[]),
            moov(),
            mp4_box(
                b"uuid",
                b"\xbe\x7a\xcf\xcb\x97\xa9\x42\xe8\x9c\x71\x99\x94\x91\xe3\xaf\xac<x:xmpmeta>",
            ),
            mp4_box(b"mdat", MDAT),
        ]
        .concat()
    }

    #[test]
    fn scrub_mp4_blanks_metadata_in_place() {
        let input = mp4();
        assert_eq!(detect(&input), Some(Format::Mp4));
        assert_eq!(scrub_image(&input), Err(Unsupported));
        let mut out = input.clone();
        assert_eq!(scrub_mp4(&mut out).unwrap(), 4);
        assert_eq!(out.len(), input.len());
        for leak in [&b"37.7749"[..], b"Camera Co", b"xmpmeta", b"location"] {
            assert!(contains(&input, leak));
            assert!(!contains(&out, leak), "{}", String::from_utf8_lossy(leak));
        }
        assert!(out.ends_with(&mp4_box(b"mdat", MDAT)));
        assert!(contains(&out, b"stco"));
        // Again: nothing left to blank.
        let mut again = out.clone();
        assert_eq!(scrub_mp4(&mut again).unwrap(), 0);
        assert_eq!(again, out);
        // The moov box alone scrubs the same.
        let mut alone = moov();
        let at = input.windows(4).position(|w| w == b"moov").unwrap() - 4;
        assert_eq!(scrub_mp4(&mut alone).unwrap(), 3);
        assert_eq!(&out[at..at + alone.len()], &alone[..]);
    }

    #[test]
    fn scrub_mp4_reads_large_and_open_ended_sizes() {
        let location = b"+37.7749-122.4/";
        let large = [
            &1u32.to_be_bytes()[..],
            b"udta",
            &(16 + location.len() as u64).to_be_bytes(),
            location,
        ]
        .concat();
        let mut input = [
            mp4_box(b"ftyp", b"isom\0\0\0\0isom"),
            large,
            // Size 0: to the end of the file.
            [&0u32.to_be_bytes()[..], b"mdat", MDAT].concat(),
        ]
        .concat();
        assert_eq!(scrub_mp4(&mut input).unwrap(), 1);
        assert!(!contains(&input, b"37.7749"));
        assert!(contains(&input, b"free"));
        assert!(input.ends_with(MDAT));
    }

    #[test]
    fn scrub_mp4_refuses_broken_files() {
        let mut short = mp4_box(b"moov", &[1, 2, 3]);
        short[3] = 200;
        assert_eq!(scrub_mp4(&mut short), Err(Malformed));
        let mut tiny = [0, 0, 0, 4, b'f', b'r', b'e', b'e'];
        assert_eq!(scrub_mp4(&mut tiny), Err(Malformed));
        // Deep nesting stops at the limit.
        let mut nested = mp4_box(b"udta", b"x");
        for _ in 0..=MP4_DEPTH_MAX {
            nested = mp4_box(b"moov", &nested);
        }
        assert_eq!(scrub_mp4(&mut nested), Err(Malformed));
    }

    #[test]
    fn detect_tells_still_images_from_video() {
        let heic = mp4_box(b"ftyp", b"heic\0\0\0\0mif1heic");
        assert_eq!(detect(&heic), Some(Format::StillImage));
        let avif = mp4_box(b"ftyp", b"avif\0\0\0\0avif");
        assert_eq!(detect(&avif), Some(Format::StillImage));
        assert_eq!(detect(&mp4_box(b"ftyp", b"isom")), Some(Format::Mp4));
        assert_eq!(detect(&[0xFF, 0xD8]), None);
        assert_eq!(detect(&[]), None);
    }

    // ---- Hostile input ----

    fn fixtures() -> Vec<Vec<u8>> {
        vec![
            jpeg(6),
            jpeg(1),
            png(),
            riff(&[vp8x(0x2C), riff_chunk(b"VP8 ", b"x")]),
            mp4(),
        ]
    }

    /// Scrubbing must end without a panic, and within its bounds, whatever
    /// the input.
    fn survive(input: &[u8]) {
        if let Ok(out) = scrub_image(input) {
            assert!(out.len() <= input.len() + ORIENTATION_SEGMENT_SIZE);
        }
        let mut copy = input.to_vec();
        let _ = scrub_mp4(&mut copy);
        assert_eq!(copy.len(), input.len());
    }

    #[test]
    fn scrub_survives_truncation_and_corruption() {
        for fixture in fixtures() {
            for end in 0..=fixture.len() {
                survive(&fixture[..end]);
            }
            for at in 0..fixture.len() {
                for flip in [0x01, 0x80, 0xFF] {
                    let mut bad = fixture.clone();
                    bad[at] ^= flip;
                    survive(&bad);
                }
            }
        }
    }

    #[test]
    fn scrub_survives_random_mutations() {
        // xorshift64*, seeded: deterministic.
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move || {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };
        let fixtures = fixtures();
        for _ in 0..20_000 {
            let mut bad = fixtures[usize::try_from(next() % 5).unwrap()].clone();
            for _ in 0..1 + next() % 4 {
                let at = usize::try_from(next() % bad.len() as u64).unwrap();
                bad[at] = u8::try_from(next() & 0xFF).unwrap();
            }
            let end = bad.len() - usize::try_from(next() % 8).unwrap().min(bad.len());
            survive(&bad[..end]);
        }
    }
}
