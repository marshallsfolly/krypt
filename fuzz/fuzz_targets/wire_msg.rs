//! Frame bodies: the first byte picks a body type, the rest is decoded as
//! one. Decoding never panics, and whatever decodes re-encodes to exactly
//! its input: each value has one encoding, so hashes of encodings (the
//! mailbox's dedup, the client's seen set) identify values.

#![no_main]

use krypt_core::mailbox::Meta;
use krypt_wire::limits::FRAME_BODY_MAX;
use krypt_wire::msg::{
    Accepted, AppMessage, Entries, Fetch, FilePart, InboxWelcome, KeyPackages, PushTarget,
    Rejected, Signal, Submit, Watch,
};
use libfuzzer_sys::fuzz_target;

/// Decodes `body` with `decode`; if that works, `encode` must give it back.
macro_rules! canonical {
    ($ty:ty, $body:expr) => {
        if let Ok(value) = <$ty>::decode($body) {
            assert_eq!(
                value.encode(),
                $body,
                concat!(stringify!($ty), " is not canonical")
            );
            Some(value)
        } else {
            None
        }
    };
}

fuzz_target!(|data: &[u8]| {
    // Every body arrives inside a frame.
    let Some((&sel, body)) = data.split_first() else {
        return;
    };
    if body.len() > FRAME_BODY_MAX as usize {
        return;
    }
    match sel % 13 {
        0 => {
            if let Some(submit) = canonical!(Submit, body) {
                let welcomes = submit.welcomes.iter().map(|w| w.welcome.len());
                assert!(Submit::size_max(submit.message.len(), welcomes) >= body.len());
            }
        }
        1 => drop(canonical!(Fetch, body)),
        2 => drop(canonical!(Accepted, body)),
        3 => drop(canonical!(Rejected, body)),
        4 => {
            if let Some(entries) = canonical!(Entries, body) {
                let size: usize = entries
                    .entries
                    .iter()
                    .map(|e| Entries::entry_size(e.data.len()))
                    .sum();
                assert_eq!(Entries::EMPTY_SIZE + size, body.len());
            }
        }
        5 => drop(canonical!(InboxWelcome, body)),
        6 => drop(canonical!(KeyPackages, body)),
        7 => drop(canonical!(PushTarget, body)),
        8 => {
            if let Some(watch) = canonical!(Watch, body) {
                drop(Watch::signed_bytes(&[0; 16], watch.enable, &watch.target));
            }
        }
        9 => {
            if canonical!(FilePart, body).is_some() {
                assert_eq!(body.len(), FilePart::SIZE);
            }
        }
        10 => {
            // Messages from before disappearing timers (version 1) still
            // decode, and are written in today's version: only the value
            // must survive. Current ones have exactly one encoding.
            let message = if body.first() == Some(&1) {
                AppMessage::decode(body).ok().inspect(|message| {
                    assert_eq!(AppMessage::decode(&message.encode()), Ok(*message));
                })
            } else {
                canonical!(AppMessage, body)
            };
            if let Some(message) = message
                && let krypt_wire::msg::Body::File(file) = message.body
            {
                assert!(file.valid());
            }
        }
        11 => drop(canonical!(Signal, body)),
        _ => drop(canonical!(Meta, body)),
    }
});
