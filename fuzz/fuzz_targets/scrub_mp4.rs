//! Video scrubbing, in place: never panics, never changes the size, and is
//! idempotent: a second pass finds nothing to blank and changes nothing.

#![no_main]

use krypt_core::scrub::scrub_mp4;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut once = data.to_vec();
    let result = scrub_mp4(&mut once);
    assert_eq!(once.len(), data.len());
    if result.is_err() {
        return;
    }
    let mut twice = once.clone();
    assert_eq!(scrub_mp4(&mut twice), Ok(0), "a second pass blanked boxes");
    assert_eq!(twice, once, "scrubbing is not idempotent");
});
