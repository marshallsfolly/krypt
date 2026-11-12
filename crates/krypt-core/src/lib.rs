//! Sans-IO protocol state machines for krypt.
//!
//! Nothing in this crate performs IO, reads a clock or draws OS randomness on
//! its own: time arrives as an argument, randomness through [`provider::Rand`],
//! and every effect is returned to the caller. That is what lets the same code
//! run on a phone, at the edge, and inside a deterministic simulator.

pub mod client;
pub mod file;
pub mod identity;
pub mod join;
pub mod link;
pub mod mailbox;
#[rustfmt::skip]
pub mod mls_store;
pub mod provider;
pub mod scrub;

/// Compares secrets without leaking where they differ through timing.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// BLAKE3 truncated to 128 bits: content identifiers for deduplication.
pub fn hash16(bytes: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&blake3::hash(bytes).as_bytes()[..16]);
    out
}
