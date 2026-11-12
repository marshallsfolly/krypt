//! A device restarting from damaged storage gets an error, or comes up and
//! carries on; it never panics. Both cases below were found by fuzzing
//! (`fuzz/fuzz_targets/client_restore.rs`).

use std::collections::BTreeMap;

use krypt_core::client::{Client, Config, Effect, Error, Event, Step};
use krypt_core::mailbox::LocalMailbox;
use krypt_core::provider::Rand;

type Disk = BTreeMap<Vec<u8>, Vec<u8>>;

fn apply(client: &mut Client, disk: &mut Disk, mailbox: &mut LocalMailbox, now: u64, step: Step) {
    let mut queue = vec![step];
    while let Some(step) = queue.pop() {
        for (key, value) in step.writes {
            match value {
                Some(value) => disk.insert(key, value),
                None => disk.remove(&key),
            };
        }
        for effect in step.effects {
            if let Effect::Mailbox(request) = effect
                && let Some(response) = mailbox.handle(now, &request)
            {
                queue.push(client.receive(now, &response));
            }
        }
    }
}

/// Bob's disk: in a conversation with Alice, with a message queued but not
/// yet sent.
fn bobs_disk() -> Disk {
    let mut mailbox = LocalMailbox::new();
    let (mut alice, step) = Client::create(Config::default(), Rand::seeded(1), 0);
    let mut alice_disk = Disk::new();
    apply(&mut alice, &mut alice_disk, &mut mailbox, 0, step);
    let (mut bob, step) = Client::create(Config::default(), Rand::seeded(2), 0);
    let mut disk = Disk::new();
    apply(&mut bob, &mut disk, &mut mailbox, 0, step);

    let (conversation, step) = alice
        .start_conversation(0, bob.contact_card())
        .expect("starts");
    apply(&mut alice, &mut alice_disk, &mut mailbox, 0, step);
    for now in (1..10).map(|s| s * 20_000) {
        let step = bob.tick(now);
        apply(&mut bob, &mut disk, &mut mailbox, now, step);
    }
    assert!(bob.is_active(&conversation), "bob joined");
    let (_, step) = bob.send(200_000, conversation, "queued").expect("queues");
    for (key, value) in step.writes {
        if let Some(value) = value {
            disk.insert(key, value);
        }
    }
    disk
}

fn restore(disk: Disk) -> Result<(Client, Step), Error> {
    Client::restore(Config::default(), Rand::seeded(3), disk, 300_000)
}

/// One conversation's records damaged: the device still starts, and that
/// conversation alone is reported out of sync (it used to stop the device).
fn only_the_conversation_stops(disk: Disk) -> bool {
    let Ok((client, step)) = restore(disk) else {
        return false;
    };
    client.conversations().next().is_none()
        && step
            .effects
            .iter()
            .any(|e| matches!(e, Effect::Event(Event::Desync { .. })))
}

/// Any record cut short, emptied or replaced with garbage (JSON or
/// binary): OpenMLS's values used to panic in the vendored store.
#[test]
fn damaged_records_are_errors_not_panics() {
    let disk = bobs_disk();
    for (key, value) in &disk {
        let damages = [
            value[..value.len() / 2].to_vec(),
            Vec::new(),
            b"{".to_vec(),
            vec![0x01],
            vec![0x01, 0xFF, 0xFF, 0xFF],
            [value.as_slice(), &[0]].concat(),
        ];
        for damage in damages {
            let mut damaged = disk.clone();
            damaged.insert(key.clone(), damage);
            if let Ok((mut client, _)) = restore(damaged) {
                drop(client.tick(400_000));
            }
        }
    }
}

/// OpenMLS trusts the group state it stored: an own leaf index outside the
/// tree, or at another member's leaf, failed an assertion inside OpenMLS at
/// the next commit. Now that conversation is out of sync, and the device
/// starts.
#[test]
fn an_own_leaf_that_is_not_ours_stops_its_conversation() {
    let disk = bobs_disk();
    let key = disk
        .keys()
        .find(|k| k.starts_with(b"OwnLeafNodeIndex"))
        .expect("the record exists");
    // JSON, which every build reads: Alice's leaf, and one past the tree.
    for index in [&b"0"[..], b"8"] {
        let mut damaged = disk.clone();
        damaged.insert(key.clone(), index.to_vec());
        assert!(only_the_conversation_stops(damaged));
    }
}

/// Stored counters, log positions and times beyond any an honest device
/// writes: a queued message numbered `u64::MAX` overflowed the send window,
/// and a key package refresh due at `u64::MAX` the refresh check.
#[test]
fn counters_out_of_range_are_errors() {
    let disk = bobs_disk();
    assert!(restore(disk.clone()).is_ok());
    // Record layouts, after a version byte: an outbox entry's sequence
    // number; a conversation's active flag, then its cursor; the device's
    // seeds and certificate, then its inbox cursor, key packages owed, two
    // flags and when it last refreshed its key packages.
    let fields: [(&[u8], usize); 4] = [
        (&[0, b'O'], 1),
        (&[0, b'C'], 2),
        (
            &[0, b'S'],
            1 + 32 + 32 + 4 + krypt_core::identity::CERT_SIZE,
        ),
        (
            &[0, b'S'],
            1 + 32 + 32 + 4 + krypt_core::identity::CERT_SIZE + 8 + 4 + 1 + 1,
        ),
    ];
    for (prefix, at) in fields {
        let key = disk
            .keys()
            .find(|k| k.starts_with(prefix))
            .expect("the record exists");
        let mut damaged = disk.clone();
        damaged.get_mut(key).expect("exists")[at..at + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        // A conversation's records stop that conversation; the device's own,
        // the device.
        let refused = if prefix == [0, b'S'] {
            matches!(restore(damaged), Err(Error::Corrupt(_)))
        } else {
            only_the_conversation_stops(damaged)
        };
        assert!(refused, "{prefix:?} accepted u64::MAX");
    }
}
