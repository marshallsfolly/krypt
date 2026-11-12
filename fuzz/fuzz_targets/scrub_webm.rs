//! Voice message scrubbing (WebM), in place: never panics, never changes
//! the size, and is idempotent: a second pass accepts what the first wrote
//! and changes nothing.

#![no_main]

use krypt_core::scrub::scrub_webm;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut once = data.to_vec();
    let result = scrub_webm(&mut once);
    assert_eq!(once.len(), data.len());
    if result.is_err() {
        return;
    }
    let mut twice = once.clone();
    assert!(scrub_webm(&mut twice).is_ok(), "a second pass refused the first's output");
    assert_eq!(twice, once, "scrubbing is not idempotent");
});
