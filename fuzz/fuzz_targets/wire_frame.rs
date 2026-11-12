//! Frames: decoding never panics, a decoded frame re-encodes to exactly its
//! input (the encoding is canonical), and a stream reader splitting input by
//! `frame_len` never reads out of bounds.

#![no_main]

use krypt_wire::frame::{self, HEADER_SIZE};
use krypt_wire::limits::FRAME_BODY_MAX;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(f) = frame::decode(data) {
        let again = frame::encode_vec(f.kind, f.seq, f.route, f.body);
        assert_eq!(again, data, "frame encoding is not canonical");
        assert_eq!(frame::frame_len(data), Ok(data.len()));
    }
    // As a stream reader would: header, then the announced length.
    let mut rest = data;
    while rest.len() >= HEADER_SIZE {
        let Ok(len) = frame::frame_len(rest) else {
            break;
        };
        assert!((HEADER_SIZE..=HEADER_SIZE + FRAME_BODY_MAX as usize).contains(&len));
        let Some(bytes) = rest.get(..len) else {
            break;
        };
        let _ = frame::decode(bytes);
        rest = &rest[len..];
    }
});
