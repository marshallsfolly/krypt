//! Upgrading to the post-quantum ciphersuite. Key packages published before
//! it are useless (inviters refuse them and the mailbox drops them), so a
//! device upgraded from an older version replaces its set at once rather than
//! at the next fortnightly refresh.

use std::collections::BTreeMap;

use krypt_core::client::{Client, Config, Effect, Step};
use krypt_core::mailbox::LocalMailbox;
use krypt_core::provider::Rand;
use krypt_wire::msg::KeyPackages;
use krypt_wire::{Kind, frame};

/// The self record's key, and the version it was written with before the
/// post-quantum ciphersuite.
const KEY_SELF: &[u8] = &[0, b'S'];
const RECORD_VERSION_CLASSIC: u8 = 2;

/// Persists a step, runs its requests through the mailbox, and returns how
/// many key packages it published.
fn apply(
    client: &mut Client,
    disk: &mut BTreeMap<Vec<u8>, Vec<u8>>,
    mailbox: &mut LocalMailbox,
    now: u64,
    step: Step,
) -> usize {
    let mut published = 0;
    let mut queue = vec![step];
    while let Some(step) = queue.pop() {
        for (key, value) in step.writes {
            match value {
                Some(value) => disk.insert(key, value),
                None => disk.remove(&key),
            };
        }
        for effect in step.effects {
            let Effect::Mailbox(request) = effect else {
                continue;
            };
            let frame = frame::decode(&request).expect("a valid frame");
            if frame.kind == Kind::PublishKeyPackages {
                published += KeyPackages::decode(frame.body).expect("decodes").list.len();
            }
            if let Some(response) = mailbox.handle(now, &request) {
                queue.push(client.receive(now, &response));
            }
        }
    }
    published
}

/// Restarts the device from its disk; returns how many key packages it
/// published on the way up.
fn restart(disk: &mut BTreeMap<Vec<u8>, Vec<u8>>, mailbox: &mut LocalMailbox, now: u64) -> usize {
    let records = disk.clone().into_iter();
    let (mut client, step) =
        Client::restore(Config::default(), Rand::seeded(now), records, now).expect("restores");
    apply(&mut client, disk, mailbox, now, step)
}

#[test]
fn devices_from_before_post_quantum_replace_their_key_packages() {
    let mut mailbox = LocalMailbox::new();
    let mut disk = BTreeMap::new();
    let (mut client, step) = Client::create(Config::default(), Rand::seeded(1), 0);
    let first = apply(&mut client, &mut disk, &mut mailbox, 0, step);
    assert_eq!(
        first,
        Config::default().key_packages + 1,
        "plus a last resort"
    );

    assert_eq!(restart(&mut disk, &mut mailbox, 60_000), 0, "nothing owed");

    disk.get_mut(KEY_SELF).expect("a self record")[0] = RECORD_VERSION_CLASSIC;
    assert_eq!(
        restart(&mut disk, &mut mailbox, 120_000),
        Config::default().key_packages + 1,
        "an upgraded device replaces the whole set"
    );
    assert_eq!(
        restart(&mut disk, &mut mailbox, 180_000),
        0,
        "and only once"
    );
}
