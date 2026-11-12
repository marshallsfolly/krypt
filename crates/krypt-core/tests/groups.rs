//! Groups like Signal's, with the mailbox in the loop: one started with
//! several people and a name, renamed by a member, joined later by someone
//! who sees the name, and left by a member whom the others then remove.

mod common;

use common::{Device, settle};
use krypt_core::client::Event;
use krypt_core::mailbox::LocalMailbox;

fn renamed(device: &Device) -> Vec<String> {
    device
        .events
        .iter()
        .filter_map(|e| match e {
            Event::Renamed { name, .. } => Some(name.clone()),
            _ => None,
        })
        .collect()
}

#[test]
fn a_named_group_is_shared_renamed_joined_and_left() {
    let mut mailbox = LocalMailbox::new();
    let mut now = 0;
    let mut alice = Device::new(1, &mut mailbox);
    let mut bob = Device::new(2, &mut mailbox);
    let mut carol = Device::new(3, &mut mailbox);
    let mut dave = Device::new(4, &mut mailbox);

    let cards = [bob.client.contact_card(), carol.client.contact_card()];
    let (group, step) = alice
        .client
        .start_group(now, &cards, "Climbing")
        .expect("starts");
    alice.apply(&mut mailbox, now, step);
    settle(
        &mut [&mut alice, &mut bob, &mut carol],
        &mut mailbox,
        &mut now,
    );
    for device in [&alice, &bob, &carol] {
        assert_eq!(device.client.group_name(&group), "Climbing");
        assert_eq!(device.client.members(&group).len(), 3);
    }
    let mut known = alice.client.known_contacts();
    known.sort_by_key(|c| c.identity);
    let mut expected = cards.to_vec();
    expected.sort_by_key(|c| c.identity);
    assert_eq!(known, expected);

    // Any member renames it; everyone hears who did.
    let step = bob
        .client
        .rename(now, group, "Climbing ✦ Sundays")
        .expect("renames");
    bob.apply(&mut mailbox, now, step);
    settle(
        &mut [&mut alice, &mut bob, &mut carol],
        &mut mailbox,
        &mut now,
    );
    for device in [&alice, &bob, &carol] {
        assert_eq!(device.client.group_name(&group), "Climbing ✦ Sundays");
    }
    assert_eq!(renamed(&alice), vec!["Climbing ✦ Sundays".to_owned()]);

    // Someone added later sees the name from the group itself.
    let step = carol
        .client
        .invite(now, group, dave.client.contact_card())
        .expect("invites");
    carol.apply(&mut mailbox, now, step);
    settle(
        &mut [&mut alice, &mut bob, &mut carol, &mut dave],
        &mut mailbox,
        &mut now,
    );
    assert_eq!(dave.client.group_name(&group), "Climbing ✦ Sundays");

    // Carol leaves: the others remove her, once.
    let (_, step) = carol.client.leave(now, group).expect("leaves");
    carol.apply(&mut mailbox, now, step);
    settle(
        &mut [&mut alice, &mut bob, &mut carol, &mut dave],
        &mut mailbox,
        &mut now,
    );
    let carol_id = carol.client.identity();
    for device in [&alice, &bob, &dave] {
        assert!(!device.client.members(&group).contains(&carol_id));
        assert_eq!(
            device.client.intents_len(&group),
            0,
            "nothing left to commit"
        );
    }
    assert!(!carol.client.is_active(&group), "carol is out");
    assert!(
        carol
            .events
            .iter()
            .any(|e| matches!(e, Event::Removed { conversation } if *conversation == group))
    );

    // Names have a limit.
    assert!(alice.client.rename(now, group, &"x".repeat(65)).is_err());
}
