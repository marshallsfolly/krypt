//! Mailbox behaviour that the simulator relies on but would only surface
//! indirectly (as stalled invites) if it regressed.

use krypt_core::client::{Client, Config, Effect};
use krypt_core::mailbox::LocalMailbox;
use krypt_core::provider::Rand;
use krypt_wire::Kind;
use krypt_wire::frame;
use krypt_wire::msg::{Accepted, Rejected};

fn publish_frames(seed: u64) -> Vec<Vec<u8>> {
    let (_client, step) = Client::create(Config::default(), Rand::seeded(seed), 0);
    step.effects
        .into_iter()
        .filter_map(|e| match e {
            Effect::Mailbox(frame) => Some(frame),
            _ => None,
        })
        .collect()
}

/// Regression: a last-resort key package must declare the LastResort
/// extension in its leaf capabilities, or the mailbox rejects it.
#[test]
fn freshly_created_device_publishes_valid_key_packages() {
    let mut mailbox = LocalMailbox::new();
    for request in publish_frames(1) {
        let response = mailbox.handle(0, &request).expect("a response");
        let f = frame::decode(&response).unwrap();
        assert_eq!(f.kind, Kind::Accepted, "{:?}", Rejected::decode(f.body));
    }
}

/// Regression: a publish retried after a lost response must not store the
/// same single-use key package twice.
#[test]
fn republishing_does_not_duplicate_key_packages() {
    let mut mailbox = LocalMailbox::new();
    let frames = publish_frames(2);
    let first = frame::decode(&mailbox.handle(0, &frames[0]).unwrap())
        .unwrap()
        .body
        .to_vec();
    let again = frame::decode(&mailbox.handle(0, &frames[0]).unwrap())
        .unwrap()
        .body
        .to_vec();
    assert_eq!(
        Accepted::decode(&first).unwrap(),
        Accepted::decode(&again).unwrap()
    );
}
