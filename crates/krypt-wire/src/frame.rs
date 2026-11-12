//! The frame: a fixed 64-byte header followed by a body of `body_len` bytes.
//!
//! The header carries two BLAKE3 checksums (truncated to 128 bits): one over
//! the body, and one over the rest of the header (which includes the body
//! checksum), so a single check at the front authenticates the layout of the
//! whole frame against corruption. These checksums detect accidental damage
//! (torn writes, bit rot, bugs); confidentiality and authenticity come from
//! MLS and the transport, not from here.

use zerocopy::byteorder::little_endian::{U32, U64};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::limits::FRAME_BODY_MAX;

pub const MAGIC: [u8; 2] = *b"KR";
pub const VERSION: u8 = 1;
pub const HEADER_SIZE: usize = 64;

/// Opaque 128-bit routing identifier: a conversation log or an inbox.
pub type Route = [u8; 16];

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
#[repr(C)]
pub struct Header {
    /// BLAKE3 of `header[16..]`, truncated.
    pub checksum: [u8; 16],
    /// BLAKE3 of the body, truncated.
    pub checksum_body: [u8; 16],
    pub magic: [u8; 2],
    pub version: u8,
    pub kind: u8,
    pub body_len: U32,
    /// Kind-specific: a request id for requests and their responses.
    pub seq: U64,
    pub route: Route,
}

const _: () = assert!(size_of::<Header>() == HEADER_SIZE);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Kind {
    // Client to mailbox.
    Submit = 1,
    Fetch = 2,
    PublishKeyPackages = 3,
    ClaimKeyPackage = 4,
    Watch = 5,
    /// From the edge, for a device uploading part of a file: may it be
    /// stored under this conversation?
    AuthorizeFile = 6,
    /// From the edge, for a device asking for call relay credentials: is it
    /// a member of this conversation, within the day's allowance?
    AuthorizeTurn = 7,
    /// A signal (typing, online) for the members connected right now: relayed,
    /// never stored.
    Signal = 8,
    /// An admin opens (or keeps open) a group's requests log, for its invite
    /// link: `OpenRequests`.
    OpenRequests = 9,
    /// Someone with the invite link asks to join: `JoinRequest`.
    JoinRequest = 10,
    /// What the invite link points at: the requests log's header.
    JoinHeader = 11,
    // Mailbox to client.
    Accepted = 16,
    Rejected = 17,
    Entries = 18,
    KeyPackage = 19,
    /// Unsolicited: the route's log has new entries. The body is an
    /// `Entries`: the new tip, and the new entries themselves when small.
    Notify = 20,
    /// Unsolicited: a member's `Signal`, relayed as it came. The body is a
    /// `Signal`.
    Signaled = 21,
    /// A requests log's header (the answer to `JoinHeader`).
    Header = 22,
    // 32 was the retired peer-to-peer `Direct`.
}

impl Kind {
    pub fn from_u8(byte: u8) -> Option<Kind> {
        Some(match byte {
            1 => Kind::Submit,
            2 => Kind::Fetch,
            3 => Kind::PublishKeyPackages,
            4 => Kind::ClaimKeyPackage,
            5 => Kind::Watch,
            6 => Kind::AuthorizeFile,
            7 => Kind::AuthorizeTurn,
            8 => Kind::Signal,
            9 => Kind::OpenRequests,
            10 => Kind::JoinRequest,
            11 => Kind::JoinHeader,
            16 => Kind::Accepted,
            17 => Kind::Rejected,
            18 => Kind::Entries,
            19 => Kind::KeyPackage,
            20 => Kind::Notify,
            21 => Kind::Signaled,
            22 => Kind::Header,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    TooShort,
    BadMagic,
    BadVersion(u8),
    BadKind(u8),
    BodyTooLarge(u32),
    LengthMismatch { expected: usize, actual: usize },
    BadHeaderChecksum,
    BadBodyChecksum,
}

/// A decoded frame borrowing its body from the input buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame<'a> {
    pub kind: Kind,
    pub seq: u64,
    pub route: Route,
    pub body: &'a [u8],
}

fn checksum(bytes: &[u8]) -> [u8; 16] {
    let hash = blake3::hash(bytes);
    let mut out = [0u8; 16];
    out.copy_from_slice(&hash.as_bytes()[..16]);
    out
}

/// Appends one encoded frame to `out`.
pub fn encode(out: &mut Vec<u8>, kind: Kind, seq: u64, route: Route, body: &[u8]) {
    assert!(
        body.len() <= FRAME_BODY_MAX as usize,
        "frame body exceeds FRAME_BODY_MAX"
    );
    let mut header = Header {
        checksum: [0; 16],
        checksum_body: checksum(body),
        magic: MAGIC,
        version: VERSION,
        kind: kind as u8,
        body_len: U32::new(u32::try_from(body.len()).expect("checked above")),
        seq: U64::new(seq),
        route,
    };
    header.checksum = checksum(&header.as_bytes()[16..]);

    out.reserve(HEADER_SIZE + body.len());
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(body);
}

/// Encodes one frame into a fresh buffer.
pub fn encode_vec(kind: Kind, seq: u64, route: Route, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_SIZE + body.len());
    encode(&mut out, kind, seq, route, body);
    out
}

/// Validates a header and returns the total frame length it announces.
/// Stream readers call this on the first `HEADER_SIZE` bytes to learn how much
/// more to read, rejecting garbage before buffering any body.
pub fn frame_len(header_bytes: &[u8]) -> Result<usize, FrameError> {
    let header = parse_header(header_bytes)?;
    Ok(HEADER_SIZE + header.body_len.get() as usize)
}

fn parse_header(bytes: &[u8]) -> Result<&Header, FrameError> {
    let Some(head) = bytes.get(..HEADER_SIZE) else {
        return Err(FrameError::TooShort);
    };
    let header = Header::ref_from_bytes(head).map_err(|_| FrameError::TooShort)?;
    if header.checksum != checksum(&head[16..]) {
        return Err(FrameError::BadHeaderChecksum);
    }
    if header.magic != MAGIC {
        return Err(FrameError::BadMagic);
    }
    if header.version != VERSION {
        return Err(FrameError::BadVersion(header.version));
    }
    if Kind::from_u8(header.kind).is_none() {
        return Err(FrameError::BadKind(header.kind));
    }
    if header.body_len.get() > FRAME_BODY_MAX {
        return Err(FrameError::BodyTooLarge(header.body_len.get()));
    }
    Ok(header)
}

/// Decodes exactly one frame occupying all of `bytes`.
pub fn decode(bytes: &[u8]) -> Result<Frame<'_>, FrameError> {
    let header = parse_header(bytes)?;
    let expected = HEADER_SIZE + header.body_len.get() as usize;
    if bytes.len() != expected {
        return Err(FrameError::LengthMismatch {
            expected,
            actual: bytes.len(),
        });
    }
    let body = &bytes[HEADER_SIZE..];
    if header.checksum_body != checksum(body) {
        return Err(FrameError::BadBodyChecksum);
    }
    let kind = Kind::from_u8(header.kind).ok_or(FrameError::BadKind(header.kind))?;
    Ok(Frame {
        kind,
        seq: header.seq.get(),
        route: header.route,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let route = [7u8; 16];
        let bytes = encode_vec(Kind::Submit, 42, route, b"hello");
        assert_eq!(bytes.len(), HEADER_SIZE + 5);
        assert_eq!(frame_len(&bytes).unwrap(), bytes.len());
        let frame = decode(&bytes).unwrap();
        assert_eq!(
            frame,
            Frame {
                kind: Kind::Submit,
                seq: 42,
                route,
                body: b"hello"
            }
        );
    }

    #[test]
    fn empty_body() {
        let bytes = encode_vec(Kind::ClaimKeyPackage, 0, [0; 16], &[]);
        assert_eq!(decode(&bytes).unwrap().body, &[] as &[u8]);
    }

    #[test]
    fn every_single_byte_flip_is_detected() {
        let bytes = encode_vec(Kind::Submit, u64::MAX, [0xAB; 16], b"some body bytes");
        for i in 0..bytes.len() {
            for bit in 0..8 {
                let mut damaged = bytes.clone();
                damaged[i] ^= 1 << bit;
                assert!(
                    decode(&damaged).is_err(),
                    "flip at byte {i} bit {bit} went undetected"
                );
            }
        }
    }

    #[test]
    fn truncation_and_extension_are_detected() {
        let bytes = encode_vec(Kind::Entries, 1, [1; 16], b"abc");
        for len in 0..bytes.len() {
            assert!(decode(&bytes[..len]).is_err());
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(matches!(
            decode(&longer),
            Err(FrameError::LengthMismatch { .. })
        ));
    }

    #[test]
    #[should_panic(expected = "FRAME_BODY_MAX")]
    fn oversized_body_is_a_programming_error() {
        encode_vec(
            Kind::Submit,
            0,
            [0; 16],
            &vec![0; FRAME_BODY_MAX as usize + 1],
        );
    }
}
