//! Writes seed corpora for every fuzz target from real encodings: the
//! frames, bodies and records of a real conversation, cards and
//! certificates, and small photos and videos laid out as phones write them.
//!
//! `seeds [--fixture] <dir>` writes `<dir>/<target>/<hash>`. With
//! `--fixture` it first rewrites the committed client fixture; client seeds
//! are always made against the fixture on disk, so they stay meaningful.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use krypt_core::hash16;
use krypt_core::identity::Identity;
use krypt_core::link::LinkInvite;
use krypt_core::provider::Rand;
use krypt_core::mailbox::{LogKind, Meta};
use krypt_fuzz::client::{self, Device, RESPONSES, api, edit, op};
use krypt_fuzz::fixture::{Fixture, PATH};
use krypt_fuzz::input::{Input, Script};
use krypt_fuzz::mailbox::{ROUTE_GIVEN, flag};
use krypt_fuzz::scenario;
use krypt_wire::frame::{self, Kind};
use krypt_wire::msg::{
    Accepted, AppMessage, Body, FilePart, FileRef, InboxWelcome, MessageRef, Platform, PushTarget,
    ReadThrough, Reject, Rejected, Signal, VoiceRef, Watch,
};

struct Out {
    dir: PathBuf,
    written: usize,
}

impl Out {
    fn seed(&mut self, target: &str, bytes: &[u8]) {
        let dir = self.dir.join(target);
        std::fs::create_dir_all(&dir).expect("creates the corpus directory");
        let name: String = hash16(bytes).iter().map(|b| format!("{b:02x}")).collect();
        std::fs::write(dir.join(name), bytes).expect("writes a seed");
        self.written += 1;
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let rewrite = args.iter().any(|a| a == "--fixture");
    let dir = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .expect("usage: seeds [--fixture] <dir>");
    let mut out = Out {
        dir: PathBuf::from(dir),
        written: 0,
    };

    let scenario = scenario::run();
    if rewrite || !Path::new(PATH).exists() {
        std::fs::write(PATH, scenario.fixture.encode()).expect("writes the fixture");
        eprintln!("wrote {PATH}");
    }
    let fixture = Fixture::get();

    wire(&mut out, &scenario);
    mailbox(&mut out, &scenario);
    identity(&mut out, &scenario);
    media(&mut out);
    client_receive(&mut out, fixture);
    client_restore(&mut out, fixture);
    eprintln!("wrote {} seeds to {}", out.written, out.dir.display());
}

// ---- Wire ---------------------------------------------------------------

/// Selector bytes of the `wire_msg` target, by body type.
mod msg {
    pub const SUBMIT: u8 = 0;
    pub const FETCH: u8 = 1;
    pub const ACCEPTED: u8 = 2;
    pub const REJECTED: u8 = 3;
    pub const ENTRIES: u8 = 4;
    pub const INBOX_WELCOME: u8 = 5;
    pub const KEY_PACKAGES: u8 = 6;
    pub const PUSH_TARGET: u8 = 7;
    pub const WATCH: u8 = 8;
    pub const FILE_PART: u8 = 9;
    pub const APP_MESSAGE: u8 = 10;
    pub const SIGNAL: u8 = 11;
    pub const META: u8 = 12;
}

fn wire(out: &mut Out, scenario: &scenario::Scenario) {
    let world = &scenario.world;
    let frames = world.requests.iter().map(|(_, f)| f).chain(&world.frames);
    let mut seen = BTreeSet::new();
    for bytes in frames {
        let f = frame::decode(bytes).expect("real frames decode");
        // One seed per kind and size class is plenty.
        if !seen.insert((f.kind, bytes.len().ilog2())) {
            continue;
        }
        out.seed("wire_frame", bytes);
        let sel = match f.kind {
            Kind::Submit => msg::SUBMIT,
            Kind::Fetch => msg::FETCH,
            Kind::PublishKeyPackages => msg::KEY_PACKAGES,
            Kind::Watch => msg::WATCH,
            Kind::Accepted => msg::ACCEPTED,
            Kind::Rejected => msg::REJECTED,
            Kind::Entries | Kind::Notify => msg::ENTRIES,
            Kind::Signal | Kind::Signaled => msg::SIGNAL,
            _ => continue,
        };
        out.seed("wire_msg", &[&[sel], f.body].concat());
    }
    for entry in &scenario.fixture.stash {
        if InboxWelcome::decode(&entry.data).is_ok() {
            out.seed(
                "wire_msg",
                &[&[msg::INBOX_WELCOME], &entry.data[..]].concat(),
            );
        }
    }
    let rejected = Rejected {
        reason: Reject::TooOld,
        epoch: 3,
    };
    let target = PushTarget {
        platform: Platform::WebPush,
        address: b"https://fcm.googleapis.com/fcm/send/abc",
    };
    let watch = Watch {
        enable: true,
        target,
        proof: &[7; 64],
    };
    let part = FilePart {
        file: [1; 16],
        part: 2,
        len: 1 << 20,
        epoch: 5,
        auth: [3; 16],
    };
    let file = FileRef {
        id: [1; 16],
        key: [2; 32],
        size: 3_000_000,
        name: "IMG_0001.jpg",
        media_type: "image/jpeg",
        width: 4032,
        height: 3024,
        thumbnail: &[0xFF, 0xD8, 0xFF, 0xD9],
    };
    let meta = Meta {
        kind: LogKind::Conversation,
        epoch: 4,
        evicted_through: 0,
        touched_ms: 1_793_000_000_000,
    };
    let text = AppMessage {
        sender_seq: 1,
        sent_at_ms: 1_793_000_000_000,
        expires_after_s: 0,
        body: Body::Text("hej ✓"),
    };
    let shared = AppMessage {
        body: Body::File(file),
        ..text
    };
    let to = MessageRef {
        device: [3; 32],
        seq: 7,
    };
    let receipts = ReadThrough::encode(&[to]);
    let waveform = [40u8; 64];
    let voice = VoiceRef {
        file: FileRef {
            media_type: "audio/webm",
            width: 0,
            height: 0,
            thumbnail: &[],
            size: 20_000,
            ..file
        },
        duration_ms: 4_000,
        waveform: &waveform,
    };
    let referring = [
        Body::Reply { to, text: "yes" },
        Body::React { to, emoji: "👍" },
        Body::Edit { to, text: "fixed" },
        Body::Delete { to },
        Body::Receipt(ReadThrough::parse(&receipts).expect("valid")),
        Body::Voice(voice),
    ]
    .map(|body| AppMessage { body, ..text }.encode());
    let signal = Signal {
        epoch: 3,
        auth: [4; 16],
        sealed: &[5; 96],
    };
    for (sel, body) in [
        (msg::ACCEPTED, Accepted { seq: 42 }.encode()),
        (msg::REJECTED, rejected.encode()),
        (msg::PUSH_TARGET, target.encode()),
        (msg::WATCH, watch.encode()),
        (msg::FILE_PART, part.encode()),
        (msg::APP_MESSAGE, text.encode()),
        (msg::APP_MESSAGE, shared.encode()),
        (msg::SIGNAL, signal.encode()),
        (msg::META, meta.encode()),
    ] {
        out.seed("wire_msg", &[&[sel], &body[..]].concat());
    }
    for body in referring {
        out.seed("wire_msg", &[&[msg::APP_MESSAGE], &body[..]].concat());
    }
}

// ---- Mailbox ------------------------------------------------------------

/// The scenario's requests as `mailbox` scripts: all of them, and the
/// opening stretches of it.
fn mailbox(out: &mut Out, scenario: &scenario::Scenario) {
    let requests = &scenario.world.requests;
    let mut script = Script::new();
    let mut last = krypt_fuzz::mailbox::START_MS;
    for (i, (at, bytes)) in requests.iter().enumerate() {
        let f = frame::decode(bytes).expect("real frames decode");
        let dt = at - last;
        last = *at;
        let (flags, units) = match dt {
            0 => (0, 0),
            ms if ms <= u64::from(u16::MAX) => (flag::TIME_MS, ms),
            ms if ms / 1_000 <= u64::from(u16::MAX) => (flag::TIME_S, ms / 1_000),
            ms => (flag::TIME_10_MIN, ms / 600_000),
        };
        let mut request = Script::new();
        request
            .u8(f.kind as u8)
            .u8(ROUTE_GIVEN)
            .u64(f.seq)
            .bytes(&f.route)
            .bytes(f.body);
        if request.len() > usize::from(u16::MAX) {
            continue;
        }
        script.u8(flags);
        if flags != 0 {
            script.u16(u16::try_from(units).expect("fits"));
        }
        script.chunk(request.as_slice());
        if [10, 25, 50, 100].contains(&i) {
            out.seed("mailbox", script.as_slice());
        }
    }
    // A day and a month later, with expiry.
    script
        .u8(flag::TIME_10_MIN | flag::EXPIRE)
        .u16(144)
        .chunk(&[]);
    script
        .u8(flag::TIME_10_MIN | flag::EXPIRE)
        .u16(4320)
        .chunk(&[]);
    out.seed("mailbox", &script.finish());
}

// ---- Identity -----------------------------------------------------------

/// Selector bytes of the `identity` target.
mod id {
    pub const CERT: u8 = 0;
    pub const CARD: u8 = 1;
    pub const TEXT: u8 = 2;
    pub const LINK_CODE: u8 = 3;
    pub const LINK_OPEN: u8 = 4;
}

fn identity(out: &mut Out, scenario: &scenario::Scenario) {
    let identity = Identity::from_seed([5; 32]);
    let cert = identity.certify([6; 32], [7; 32], [8; 16]);
    out.seed("identity", &[&[id::CERT], &cert.encode()[..]].concat());
    let invite = LinkInvite::new(&Rand::seeded(9));
    out.seed(
        "identity",
        &[&[id::LINK_CODE], invite.code.to_text().as_bytes()].concat(),
    );
    out.seed("identity", &[&[id::LINK_OPEN], invite.public_key()].concat());
    for node in &scenario.world.nodes {
        let card = node.client.contact_card();
        out.seed("identity", &[&[id::CARD], &card.encode()[..]].concat());
        out.seed(
            "identity",
            &[&[id::TEXT], card.to_text().as_bytes()].concat(),
        );
    }
}

// ---- Media --------------------------------------------------------------

fn media(out: &mut Out) {
    for image in [files::jpeg(6), files::jpeg(1), files::png(), files::webp()] {
        out.seed("scrub_image", &image);
    }
    // A GIF with a comment, XMP, a loop count, a frame, and bytes after it.
    let mut gif = b"GIF89a".to_vec();
    gif.extend_from_slice(&[1, 0, 1, 0, 0x80, 0, 0, 0, 0, 0, 255, 255, 255]);
    gif.extend_from_slice(b"\x21\xFE\x05hello\x00");
    gif.extend_from_slice(b"\x21\xFF\x0BXMP DataXMP\x04gps!\x00");
    gif.extend_from_slice(b"\x21\xFF\x0BNETSCAPE2.0\x03\x01\x00\x00\x00");
    gif.extend_from_slice(&[0x21, 0xF9, 4, 0, 10, 0, 0, 0]);
    gif.extend_from_slice(&[0x2C, 0, 0, 0, 0, 1, 0, 1, 0, 0, 2, 2, 0x4C, 0x01, 0, 0x3B]);
    gif.extend_from_slice(b"secret");
    out.seed("scrub_image", &gif);
    let icons = Path::new(env!("CARGO_MANIFEST_DIR")).join("../apps/web/public");
    for name in ["icon-192.png", "apple-touch-icon.png"] {
        if let Ok(png) = std::fs::read(icons.join(name)) {
            out.seed("scrub_image", &png);
        }
    }
    out.seed("scrub_mp4", &files::mp4());
    out.seed("scrub_mp4", &files::moov());
    out.seed("scrub_mp4", &files::mp4_large());
    out.seed("scrub_webm", &files::webm());
}

/// Photos and videos as phones lay them out, metadata included (as in
/// krypt-core's scrub tests).
mod files {
    fn segment(marker: u8, payload: &[u8]) -> Vec<u8> {
        let size = u16::try_from(payload.len() + 2).expect("a segment");
        [&[0xFF, marker][..], &size.to_be_bytes(), payload].concat()
    }

    /// TIFF (big-endian): orientation, a camera make and a GPS IFD.
    fn tiff(orientation: u16) -> Vec<u8> {
        let mut t = b"MM\0\x2a\0\0\0\x08".to_vec();
        t.extend_from_slice(&3u16.to_be_bytes());
        t.extend_from_slice(&[0x01, 0x0F, 0, 2, 0, 0, 0, 4]);
        t.extend_from_slice(b"Cam\0");
        t.extend_from_slice(&[0x01, 0x12, 0, 3, 0, 0, 0, 1]);
        t.extend_from_slice(&orientation.to_be_bytes());
        t.extend_from_slice(&[0, 0]);
        t.extend_from_slice(&[0x88, 0x25, 0, 4, 0, 0, 0, 1, 0, 0, 0, 50]);
        t.extend_from_slice(&[0, 0, 0, 0]);
        t.extend_from_slice(&[0, 1, 0, 1, 0, 2, 0, 0, 0, 2]);
        t.extend_from_slice(b"N\0\0\0\0\0\0\0GPS 37.7749 -122.4194");
        t
    }

    pub fn jpeg(orientation: u16) -> Vec<u8> {
        [
            vec![0xFF, 0xD8],
            segment(0xE0, b"JFIF\0\x01\x02\0\0\x01\0\x01\0\0"),
            segment(0xE1, &[&b"Exif\0\0"[..], &tiff(orientation)].concat()),
            segment(
                0xE1,
                b"http://ns.adobe.com/xap/1.0/\0<x:xmpmeta>GPS</x:xmpmeta>",
            ),
            segment(0xE2, b"ICC_PROFILE\0\x01\x01colour"),
            segment(0xED, b"Photoshop 3.0\0GPS IPTC"),
            segment(0xFE, b"comment GPS"),
            segment(0xDB, &[0; 65]),
            segment(0xC0, &[8, 0, 16, 0, 16, 1, 1, 0x11, 0]),
            segment(0xC4, &[0; 20]),
            segment(0xDA, &[1, 1, 0, 0, 63, 0]),
            vec![0x12, 0xFF, 0x00, 0x34, 0xFF, 0xD3, 0x56, 0xFF, 0x00, 0x78],
            vec![0xFF, 0xD9],
            b"trailing preview".to_vec(),
        ]
        .concat()
    }

    fn chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
        let size = u32::try_from(data.len()).expect("a chunk");
        [
            &size.to_be_bytes()[..],
            kind,
            data,
            &[0xC0, 0xC1, 0xC2, 0xC3],
        ]
        .concat()
    }

    pub fn png() -> Vec<u8> {
        [
            b"\x89PNG\r\n\x1a\n".to_vec(),
            chunk(b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0]),
            chunk(b"tEXt", b"Comment\0GPS"),
            chunk(b"iCCP", b"profile\0\0data"),
            chunk(b"eXIf", &tiff(6)),
            chunk(b"IDAT", b"pixels"),
            chunk(b"tIME", &[7, 234, 11, 6, 12, 0, 0]),
            chunk(b"IEND", &[]),
        ]
        .concat()
    }

    fn riff_chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
        let size = u32::try_from(data.len()).expect("a chunk");
        let pad: &[u8] = if data.len() % 2 == 1 { &[0] } else { &[] };
        [kind, &size.to_le_bytes()[..], data, pad].concat()
    }

    pub fn webp() -> Vec<u8> {
        let body = [
            riff_chunk(b"VP8X", &[0x3C, 0, 0, 0, 9, 0, 0, 9, 0, 0]),
            riff_chunk(b"ICCP", b"icc"),
            riff_chunk(b"VP8 ", b"lossy-frame"),
            riff_chunk(b"EXIF", &tiff(3)),
            riff_chunk(b"XMP ", b"<x:xmpmeta>GPS</x:xmpmeta>!"),
        ]
        .concat();
        let size = u32::try_from(body.len() + 4).expect("a file");
        [&b"RIFF"[..], &size.to_le_bytes(), b"WEBP", &body].concat()
    }

    fn mp4_box(kind: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let size = u32::try_from(body.len() + 8).expect("a box");
        [&size.to_be_bytes()[..], kind, body].concat()
    }

    pub fn moov() -> Vec<u8> {
        let mdia = mp4_box(
            b"mdia",
            &[
                mp4_box(b"mdhd", &[0; 24]),
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
                mp4_box(b"udta", &mp4_box(b"\xa9xyz", b"+37.7749-122.4194/")),
                mp4_box(b"meta", &mp4_box(b"keys", b"com.apple.quicktime.location")),
                vec![0, 0, 0, 0],
            ]
            .concat(),
        )
    }

    pub fn mp4() -> Vec<u8> {
        [
            mp4_box(b"ftyp", b"qt  \0\0\0\0qt  "),
            mp4_box(b"wide", &[]),
            moov(),
            mp4_box(b"uuid", b"\xbe\x7a\xcf\xcb\x97\xa9\x42\xe8<x:xmpmeta>"),
            mp4_box(b"mdat", b"video samples"),
        ]
        .concat()
    }

    /// A 64-bit box size, and a last box that runs to the end.
    fn ebml(id: &[u8], data: &[u8]) -> Vec<u8> {
        let mut out = id.to_vec();
        out.push(0x01);
        out.extend_from_slice(&(data.len() as u64).to_be_bytes()[1..]);
        out.extend_from_slice(data);
        out
    }

    /// A recorder's WebM: header, then a segment of unknown size holding
    /// info, a track, tags and a streamed cluster.
    pub fn webm() -> Vec<u8> {
        let unknown = [0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let info = [
            ebml(&[0x4D, 0x80], b"Chrome"),
            ebml(&[0x57, 0x41], b"Chrome"),
        ]
        .concat();
        let track = ebml(&[0xAE], &ebml(&[0x86], b"A_OPUS"));
        let cluster = [ebml(&[0xE7], &[0]), ebml(&[0xA3], b"frames")].concat();
        let segment = [
            ebml(&[0x15, 0x49, 0xA9, 0x66], &info),
            ebml(&[0x16, 0x54, 0xAE, 0x6B], &track),
            ebml(&[0x12, 0x54, 0xC3, 0x67], b"tags"),
            [&[0x1F, 0x43, 0xB6, 0x75][..], &unknown, &cluster].concat(),
        ]
        .concat();
        [
            ebml(&[0x1A, 0x45, 0xDF, 0xA3], &ebml(&[0x42, 0x82], b"webm")),
            [&[0x18, 0x53, 0x80, 0x67][..], &unknown, &segment].concat(),
        ]
        .concat()
    }

    pub fn mp4_large() -> Vec<u8> {
        let location = b"+37.7749-122.4/";
        let size = 16 + location.len() as u64;
        [
            mp4_box(b"ftyp", b"isom\0\0\0\0isom"),
            [
                &1u32.to_be_bytes()[..],
                b"udta",
                &size.to_be_bytes(),
                location,
            ]
            .concat(),
            [&0u32.to_be_bytes()[..], b"mdat", b"samples"].concat(),
        ]
        .concat()
    }
}

// ---- Client -------------------------------------------------------------

/// Writes a `client_receive` script one operation at a time, running each
/// on a live device as the target would, so later operations can answer
/// the requests earlier ones caused.
struct Session<'a> {
    fixture: &'a Fixture,
    device: Device,
    script: Script,
}

impl<'a> Session<'a> {
    fn new(fixture: &'a Fixture) -> Session<'a> {
        Session {
            fixture,
            device: Device::from_fixture(fixture),
            script: Script::new(),
        }
    }

    fn push(&mut self, operation: &Script) {
        client::run(
            self.fixture,
            &mut self.device,
            &mut Input::new(operation.as_slice()),
        );
        self.script.bytes(operation.as_slice());
    }

    fn picks(&self, route: &krypt_wire::Route) -> Vec<u8> {
        self.fixture
            .log(route)
            .map(|(i, _)| u8::try_from(i).expect("a small stash"))
            .collect()
    }

    /// Answers the newest fetch of a log with all its stash entries.
    fn fetched(&mut self, route: krypt_wire::Route) -> bool {
        let Some(index) = self.device.find(Kind::Fetch, Some(route)) else {
            return false;
        };
        let picks = self.picks(&route);
        let mut s = Script::new();
        s.u8(op::RESPOND_STASH)
            .u8(index)
            .u8(0)
            .u8(u8::try_from(picks.len()).expect("a small log"))
            .bytes(&picks);
        self.push(&s);
        true
    }

    fn respond(&mut self, kind: Kind, body: &[u8], to: Kind) -> bool {
        let Some(index) = self.device.find(to, None) else {
            return false;
        };
        let sel = RESPONSES
            .iter()
            .position(|k| *k == kind)
            .expect("a response");
        let mut s = Script::new();
        s.u8(op::RESPOND)
            .u8(index)
            .u8(u8::try_from(sel).expect("small"))
            .chunk(body);
        self.push(&s);
        true
    }

    fn finish(self) -> Vec<u8> {
        self.script.finish()
    }
}

/// Units of a tick.
const SECONDS: u8 = 1;
const MINUTES: u8 = 2;
const HOURS: u8 = 3;

fn client_receive(out: &mut Out, fixture: &Fixture) {
    let [first, second] = [fixture.conversations[0], fixture.conversations[1]];

    // Catching up: the log, the inbox (joining the second conversation),
    // the second log, then the claim for Dave and the commit adding him.
    let mut s = Session::new(fixture);
    s.fetched(first);
    out.seed("client_receive", s.script.as_slice());
    s.fetched(fixture.inbox);
    s.fetched(second);
    out.seed("client_receive", s.script.as_slice());
    if let Some(index) = s.device.find(Kind::ClaimKeyPackage, None) {
        let mut step = Script::new();
        step.u8(op::RESPOND_KEY_PACKAGE).u8(index);
        s.push(&step);
    }
    s.respond(Kind::Accepted, &Accepted { seq: 99 }.encode(), Kind::Submit);
    s.respond(
        Kind::Accepted,
        &Accepted { seq: 100 }.encode(),
        Kind::Submit,
    );
    let mut step = Script::new();
    step.u8(op::TICK).u16(10).u8(MINUTES);
    s.push(&step);
    out.seed("client_receive", &s.finish());

    // The same, pushed instead of fetched.
    let mut s = Session::new(fixture);
    for route in [first, fixture.inbox, second] {
        let picks = s.picks(&route);
        let sel = if route == fixture.inbox {
            0
        } else if route == first {
            1
        } else {
            2
        };
        let mut step = Script::new();
        step.u8(op::NOTIFY_STASH)
            .u8(sel)
            .u8(0)
            .u8(u8::try_from(picks.len()).expect("small"))
            .bytes(&picks);
        s.push(&step);
    }
    out.seed("client_receive", &s.finish());

    // Refusals: the stale queued message, then the log evicted.
    let mut s = Session::new(fixture);
    let too_old = Rejected {
        reason: Reject::TooOld,
        epoch: 9,
    };
    s.respond(Kind::Rejected, &too_old.encode(), Kind::Submit);
    s.fetched(first);
    let evicted = Rejected {
        reason: Reject::Evicted,
        epoch: 9,
    };
    s.respond(Kind::Rejected, &evicted.encode(), Kind::Fetch);
    out.seed("client_receive", &s.finish());

    // The user, then a fortnight of silence (retries, key package refresh).
    let mut s = Session::new(fixture);
    s.fetched(first);
    for call in [
        api::SEND,
        api::UPDATE,
        api::PUSH_TARGET,
        api::FILE_AUTH,
        api::SEND_FILE,
        api::INVITE,
        api::REMOVE,
        api::POLL,
    ] {
        let mut step = Script::new();
        step.u8(op::API).u8(call).u8(0);
        s.push(&step);
    }
    for (count, unit) in [(5, SECONDS), (90, SECONDS), (1, HOURS), (15 * 24, HOURS)] {
        let mut step = Script::new();
        step.u8(op::TICK).u16(count).u8(unit);
        s.push(&step);
    }
    out.seed("client_receive", &s.finish());

    // Raw frames: one well formed, one damaged.
    let picks = Session::new(fixture).picks(&first);
    let body = client::stash_entries(fixture, &picks, 0);
    let notify = frame::encode_vec(Kind::Notify, 0, first, &body);
    let mut damaged = notify.clone();
    damaged[70] ^= 1;
    let mut script = Script::new();
    script
        .u8(op::RAW)
        .chunk(&notify)
        .u8(op::RAW)
        .chunk(&damaged);
    out.seed("client_receive", &script.finish());
}

fn client_restore(out: &mut Out, fixture: &Fixture) {
    out.seed("client_restore", &[]);
    for (i, (_, value)) in fixture.records.iter().enumerate() {
        let i = u8::try_from(i).expect("a small disk");
        let half = u32::try_from(value.len() / 2).expect("a record");
        let mut s = Script::new();
        s.u8(edit::DELETE).u8(i);
        out.seed("client_restore", &s.finish());
        let mut s = Script::new();
        s.u8(edit::TRUNCATE).u8(i).u32(half);
        out.seed("client_restore", &s.finish());
        let mut s = Script::new();
        s.u8(edit::XOR).u8(i).u32(half).u8(0xFF);
        out.seed("client_restore", &s.finish());
        let mut s = Script::new();
        s.u8(edit::WRITE_U64).u8(i).u32(1).u64(u64::MAX);
        out.seed("client_restore", &s.finish());
    }
}
