//! One identity on several devices, with the mailbox in the loop: a new
//! device is linked through sealed payloads, joins every conversation the
//! identity is in (old and new), is heard by everyone including its sibling,
//! and leaves them all when unlinked. A backup restores the identity.

mod common;

use common::{Device, settle};
use krypt_core::client::{Client, Config, Content, Event};
use krypt_core::link::{Backup, LinkInvite, LinkOffer, LinkPayload};
use krypt_core::mailbox::LocalMailbox;
use krypt_core::provider::Rand;
use std::collections::BTreeMap;

fn texts(device: &Device) -> Vec<(String, [u8; 32])> {
    device
        .events
        .iter()
        .filter_map(|e| match e {
            Event::Message {
                content: Content::Text(text),
                from,
                ..
            } => Some((text.clone(), *from)),
            _ => None,
        })
        .collect()
}

fn joined(device: &Device) -> Vec<[u8; 16]> {
    device
        .events
        .iter()
        .filter_map(|e| match e {
            Event::Joined { conversation, .. } => Some(*conversation),
            _ => None,
        })
        .collect()
}

/// Links a new device to `existing`'s identity, the way the apps do: the
/// payload and the answer travel sealed (here, by hand instead of a drop).
fn link(existing: &mut Device, mailbox: &mut LocalMailbox, seed: u64, now: u64) -> Device {
    let mut invite = LinkInvite::new(&Rand::seeded(seed + 1000));
    let payload = existing.client.link_payload(b"names".to_vec());
    let (offer, sealed) =
        LinkOffer::seal(invite.code, invite.public_key(), &payload.encode()).expect("seals");
    let opened = LinkPayload::decode(&invite.open(&sealed).expect("opens")).expect("decodes");
    assert_eq!(opened.app, b"names");
    let (client, step) = Client::create_linked(Config::default(), Rand::seeded(seed), &opened, now);
    let mut device = Device {
        client,
        disk: BTreeMap::new(),
        events: Vec::new(),
    };
    device.apply(mailbox, now, step);
    let card = offer
        .open_reply(&invite.reply(&device.client.contact_card()))
        .expect("answers");
    let step = existing.client.add_device(now, card).expect("adds");
    existing.apply(mailbox, now, step);
    device
}

#[test]
fn a_linked_device_joins_every_conversation_and_leaves_when_unlinked() {
    let mut mailbox = LocalMailbox::new();
    let mut now = 0;
    let mut phone = Device::new(1, &mut mailbox);
    let mut bob = Device::new(2, &mut mailbox);
    let alice = phone.client.identity();

    // A conversation from before the laptop existed.
    let (old, step) = bob
        .client
        .start_conversation(now, phone.client.contact_card())
        .expect("starts");
    bob.apply(&mut mailbox, now, step);
    settle(&mut [&mut phone, &mut bob], &mut mailbox, &mut now);

    let mut laptop = link(&mut phone, &mut mailbox, 3, now);
    assert_eq!(laptop.client.identity(), alice, "the same identity");
    assert_ne!(laptop.client.device(), phone.client.device());
    settle(
        &mut [&mut phone, &mut bob, &mut laptop],
        &mut mailbox,
        &mut now,
    );
    assert_eq!(joined(&laptop), vec![old], "added to the old conversation");
    assert_eq!(
        bob.client.members(&old).len(),
        2,
        "two identities, three devices"
    );

    // A conversation started after: whichever device joins adds the other.
    let (new, step) = bob
        .client
        .start_conversation(now, laptop.client.contact_card())
        .expect("starts");
    bob.apply(&mut mailbox, now, step);
    settle(
        &mut [&mut phone, &mut bob, &mut laptop],
        &mut mailbox,
        &mut now,
    );
    assert!(phone.client.is_active(&new) && laptop.client.is_active(&new));

    // Everyone hears every device, and each device hears its sibling.
    let (_, step) = laptop
        .client
        .send(now, old, "from the laptop")
        .expect("sends");
    laptop.apply(&mut mailbox, now, step);
    let (_, step) = bob.client.send(now, old, "hi both").expect("sends");
    bob.apply(&mut mailbox, now, step);
    settle(
        &mut [&mut phone, &mut bob, &mut laptop],
        &mut mailbox,
        &mut now,
    );
    assert!(texts(&bob).contains(&("from the laptop".to_owned(), alice)));
    assert!(texts(&phone).contains(&("from the laptop".to_owned(), alice)));
    assert!(texts(&laptop).contains(&("hi both".to_owned(), bob.client.identity())));

    // A restart keeps the siblings.
    phone.restart(&mut mailbox, 11, now);
    assert_eq!(phone.client.devices(), vec![laptop.client.contact_card()]);

    // Unlinked, the laptop leaves every conversation.
    let step = phone
        .client
        .remove_device(now, laptop.client.contact_card().inbox);
    phone.apply(&mut mailbox, now, step);
    settle(
        &mut [&mut phone, &mut bob, &mut laptop],
        &mut mailbox,
        &mut now,
    );
    assert!(!laptop.client.is_active(&old) && !laptop.client.is_active(&new));
    assert!(phone.client.is_active(&old) && phone.client.is_active(&new));
    let (_, step) = bob.client.send(now, old, "phone only").expect("sends");
    bob.apply(&mut mailbox, now, step);
    settle(
        &mut [&mut phone, &mut bob, &mut laptop],
        &mut mailbox,
        &mut now,
    );
    assert!(texts(&phone).iter().any(|(t, _)| t == "phone only"));
    assert!(!texts(&laptop).iter().any(|(t, _)| t == "phone only"));
}

#[test]
fn a_backup_restores_the_identity_and_its_contacts() {
    let mut mailbox = LocalMailbox::new();
    let mut now = 0;
    let mut phone = Device::new(1, &mut mailbox);
    let mut bob = Device::new(2, &mut mailbox);
    let (_, step) = bob
        .client
        .start_conversation(now, phone.client.contact_card())
        .expect("starts");
    bob.apply(&mut mailbox, now, step);
    settle(&mut [&mut phone, &mut bob], &mut mailbox, &mut now);

    let prf = [42u8; 32];
    let sealed = phone
        .client
        .backup(b"app".to_vec())
        .seal(&Rand::seeded(5), &prf);
    let backup = Backup::open(&sealed, &prf).expect("opens");
    assert_eq!(backup.contacts, vec![bob.client.contact_card()]);

    // The phone is lost. A new device restores the identity alone (the old
    // device is not trusted again) and reaches Bob anew; he knows who it is.
    let payload = LinkPayload {
        identity_seed: backup.identity_seed,
        devices: Vec::new(),
        app: backup.app,
    };
    let (client, step) = Client::create_linked(Config::default(), Rand::seeded(6), &payload, now);
    let mut restored = Device {
        client,
        disk: BTreeMap::new(),
        events: Vec::new(),
    };
    restored.apply(&mut mailbox, now, step);
    assert_eq!(restored.client.identity(), phone.client.identity());
    assert!(restored.client.devices().is_empty());
    let (conversation, step) = restored
        .client
        .start_conversation(now, backup.contacts[0])
        .expect("starts");
    restored.apply(&mut mailbox, now, step);
    let (_, step) = restored
        .client
        .send(now, conversation, "it's me, on a new phone")
        .expect("sends");
    restored.apply(&mut mailbox, now, step);
    settle(&mut [&mut restored, &mut bob], &mut mailbox, &mut now);
    assert!(texts(&bob).contains(&(
        "it's me, on a new phone".to_owned(),
        phone.client.identity()
    )));
}

/// With three devices, the one unlinked stays out: the identity's other
/// devices learn of the unlink from the commit and never add it back
/// (they used to, within a minute, and it read on).
#[test]
fn an_unlinked_device_stays_out_with_three_devices() {
    let mut mailbox = LocalMailbox::new();
    let mut now = 1;
    let mut phone = Device::new(1, &mut mailbox);
    let mut bob = Device::new(2, &mut mailbox);
    let (conversation, step) = bob
        .client
        .start_conversation(now, phone.client.contact_card())
        .expect("starts");
    bob.apply(&mut mailbox, now, step);
    settle(&mut [&mut phone, &mut bob], &mut mailbox, &mut now);
    let mut laptop = link(&mut phone, &mut mailbox, 3, now);
    settle(
        &mut [&mut phone, &mut bob, &mut laptop],
        &mut mailbox,
        &mut now,
    );
    let mut tablet = link(&mut phone, &mut mailbox, 4, now);
    for _ in 0..2 {
        settle(
            &mut [&mut phone, &mut bob, &mut laptop, &mut tablet],
            &mut mailbox,
            &mut now,
        );
    }
    assert!(laptop.client.is_active(&conversation));
    assert!(
        tablet
            .client
            .devices()
            .contains(&laptop.client.contact_card())
    );

    // The laptop is stolen; the phone unlinks it.
    let step = phone
        .client
        .remove_device(now, laptop.client.contact_card().inbox);
    phone.apply(&mut mailbox, now, step);
    // Long past the minute after which a missing sibling is added again.
    for _ in 0..4 {
        settle(
            &mut [&mut phone, &mut bob, &mut laptop, &mut tablet],
            &mut mailbox,
            &mut now,
        );
    }
    assert!(!laptop.client.is_active(&conversation));
    assert!(
        !tablet
            .client
            .devices()
            .contains(&laptop.client.contact_card())
    );
    laptop.events.clear();
    let (_, step) = bob
        .client
        .send(now, conversation, "after the unlink")
        .expect("sends");
    bob.apply(&mut mailbox, now, step);
    settle(
        &mut [&mut phone, &mut bob, &mut laptop, &mut tablet],
        &mut mailbox,
        &mut now,
    );
    assert!(
        !laptop
            .events
            .iter()
            .any(|e| matches!(e, Event::Message { .. }))
    );
}
