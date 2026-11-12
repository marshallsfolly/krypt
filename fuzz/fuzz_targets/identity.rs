//! Device certificates, contact cards and link codes, as bytes and as text
//! (cards and codes arrive from QR codes and links), and what a new device
//! opens while linking. Decoding never panics, whatever decodes re-encodes
//! to exactly its input, and hostile linking input is refused, not trusted.

#![no_main]

use krypt_core::identity::{ContactCard, DeviceCert, fingerprint, safety_number};
use krypt_core::link::{LinkCode, LinkInvite, LinkOffer};
use krypt_core::provider::Rand;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    match sel % 5 {
        0 => {
            if let Ok(cert) = DeviceCert::decode(rest) {
                assert_eq!(cert.encode(), rest, "certificates are not canonical");
            }
        }
        1 => {
            if let Ok(card) = ContactCard::decode(rest) {
                assert_eq!(card.encode(), rest, "cards are not canonical");
                assert_eq!(ContactCard::from_text(&card.to_text()), Some(card));
            }
        }
        3 => {
            let text = String::from_utf8_lossy(rest);
            if let Ok(code) = LinkCode::from_text(&text) {
                assert_eq!(LinkCode::from_text(&code.to_text()), Ok(code));
            }
        }
        4 => {
            // A new device opening whatever was left at its drop, and an
            // existing device given whatever was left at the key drop.
            let mut invite = LinkInvite::new(&Rand::seeded(u64::from(sel)));
            assert!(invite.open(rest).is_err(), "only its own sealed payload opens");
            assert!(LinkOffer::seal(invite.code, rest, b"payload").is_err() || rest == invite.public_key());
        }
        _ => {
            let text = String::from_utf8_lossy(rest);
            if let Some(card) = ContactCard::from_text(&text) {
                assert_eq!(ContactCard::from_text(&card.to_text()), Some(card));
                assert_eq!(ContactCard::decode(&card.encode()), Ok(card));
            }
        }
    }
    if let (Some(a), Some(b)) = (rest.get(..32), rest.get(32..64)) {
        let (a, b): ([u8; 32], [u8; 32]) = (a.try_into().unwrap(), b.try_into().unwrap());
        drop(fingerprint(&a));
        assert_eq!(safety_number(&a, &b), safety_number(&b, &a));
    }
});
