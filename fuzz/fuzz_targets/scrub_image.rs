//! Image scrubbing: never panics, grows an image by at most the
//! orientation segment, keeps its format, and is idempotent:
//! scrub(scrub(x)) == scrub(x), so nothing it leaves behind is metadata it
//! would remove.

#![no_main]

use krypt_core::scrub::{detect, scrub_image};
use libfuzzer_sys::fuzz_target;

/// The EXIF segment holding only a JPEG's orientation.
const ORIENTATION_SEGMENT_SIZE: usize = 36;

fuzz_target!(|data: &[u8]| {
    let Ok(out) = scrub_image(data) else {
        return;
    };
    assert!(out.len() <= data.len() + ORIENTATION_SEGMENT_SIZE);
    assert_eq!(detect(&out), detect(data), "scrubbing changed the format");
    assert_eq!(
        scrub_image(&out).as_ref(),
        Ok(&out),
        "scrubbing is not idempotent"
    );
});
