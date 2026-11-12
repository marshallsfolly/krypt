//! Group admins, with the mailbox in the loop: the creator is the admin;
//! admins restrict who may add people and rename the group, and make others
//! admins; this device never commits what the rules forbid; a rename keeps
//! the rules; when the last admin leaves, everyone agrees who is next; and a
//! member whose client breaks the rules stops the group for every honest
//! member, so nobody it added reads a thing.

mod common;

use common::{Device, settle};
use krypt_core::client::{Config, Event, Policy, RULES_BROKEN, Who};
use krypt_core::identity::IdentityKey;
use krypt_core::mailbox::LocalMailbox;

fn refused(device: &Device) -> usize {
    device
        .events
        .iter()
        .filter(|e| matches!(e, Event::Refused { .. }))
        .count()
}

#[test]
fn admins_set_the_rules_and_everyone_keeps_them() {
    let mut mailbox = LocalMailbox::new();
    let mut now = 0;
    let mut alice = Device::new(1, &mut mailbox);
    let mut bob = Device::new(2, &mut mailbox);
    let mut carol = Device::new(3, &mut mailbox);
    let dave = Device::new(4, &mut mailbox);
    let cards = [bob.client.contact_card(), carol.client.contact_card()];
    let (group, step) = alice
        .client
        .start_group(now, &cards, "Trip")
        .expect("starts");
    alice.apply(&mut mailbox, now, step);
    settle(
        &mut [&mut alice, &mut bob, &mut carol],
        &mut mailbox,
        &mut now,
    );
    let a = alice.client.identity();
    let b = bob.client.identity();
    for d in [&alice, &bob, &carol] {
        assert_eq!(d.client.admins(&group), vec![a], "the creator is the admin");
        assert_eq!(d.client.policy(&group), Some(Policy::new(a)));
    }

    // Anyone renames while that is open to everyone.
    let step = bob.client.rename(now, group, "Trip!").expect("renames");
    bob.apply(&mut mailbox, now, step);
    settle(
        &mut [&mut alice, &mut bob, &mut carol],
        &mut mailbox,
        &mut now,
    );
    assert_eq!(carol.client.group_name(&group), "Trip!");

    // Alice keeps adding and renaming to admins.
    let restricted = Policy {
        add: Who::Admins,
        edit: Who::Admins,
        ..Policy::new(a)
    };
    let step = alice
        .client
        .set_policy(now, group, restricted.clone())
        .expect("queues");
    alice.apply(&mut mailbox, now, step);
    settle(
        &mut [&mut alice, &mut bob, &mut carol],
        &mut mailbox,
        &mut now,
    );
    assert!(bob.events.iter().any(|e| matches!(
        e,
        Event::Rules { by, add: Some(Who::Admins), edit: Some(Who::Admins), .. } if *by == a
    )));

    // Bob's device does not even try what he may no longer do.
    let step = bob.client.rename(now, group, "Bob's trip").expect("queues");
    bob.apply(&mut mailbox, now, step);
    let step = bob
        .client
        .invite(now, group, dave.client.contact_card())
        .expect("queues");
    bob.apply(&mut mailbox, now, step);
    settle(
        &mut [&mut alice, &mut bob, &mut carol],
        &mut mailbox,
        &mut now,
    );
    assert_eq!(refused(&bob), 2);
    assert_eq!(carol.client.group_name(&group), "Trip!");
    assert_eq!(carol.client.members(&group).len(), 3);

    // Made an admin, he may; and his rename keeps the rules.
    let step = alice
        .client
        .set_policy(
            now,
            group,
            Policy {
                admins: vec![a, b],
                ..restricted.clone()
            },
        )
        .expect("queues");
    alice.apply(&mut mailbox, now, step);
    settle(
        &mut [&mut alice, &mut bob, &mut carol],
        &mut mailbox,
        &mut now,
    );
    assert!(carol.events.iter().any(|e| matches!(
        e,
        Event::Rules { admins_added, .. } if admins_added == &vec![b]
    )));
    let step = bob
        .client
        .rename(now, group, "Bob's trip")
        .expect("renames");
    bob.apply(&mut mailbox, now, step);
    settle(
        &mut [&mut alice, &mut bob, &mut carol],
        &mut mailbox,
        &mut now,
    );
    assert_eq!(carol.client.group_name(&group), "Bob's trip");
    assert_eq!(
        carol.client.policy(&group).map(|p| p.add),
        Some(Who::Admins)
    );

    // Both admins leave: the member at the lowest leaf is the admin now,
    // and everyone left agrees.
    for leaving in [&mut alice, &mut bob] {
        let (_, step) = leaving.client.leave(now, group).expect("leaves");
        leaving.apply(&mut mailbox, now, step);
    }
    settle(
        &mut [&mut alice, &mut bob, &mut carol],
        &mut mailbox,
        &mut now,
    );
    let c: IdentityKey = carol.client.identity();
    assert_eq!(carol.client.admins(&group), vec![c]);
}

#[test]
fn a_commit_against_the_rules_stops_the_group_for_everyone_honest() {
    let mut mailbox = LocalMailbox::new();
    let mut now = 0;
    let mut alice = Device::new(1, &mut mailbox);
    let mut bob = Device::new(2, &mut mailbox);
    // Mallory's client ignores the rules.
    let rogue = Config {
        break_rules: true,
        ..Config::default()
    };
    let mut mallory = Device::with_config(3, &mut mailbox, rogue);
    let mut eve = Device::new(4, &mut mailbox);
    let cards = [bob.client.contact_card(), mallory.client.contact_card()];
    let (group, step) = alice.client.start_group(now, &cards, "").expect("starts");
    alice.apply(&mut mailbox, now, step);
    settle(
        &mut [&mut alice, &mut bob, &mut mallory],
        &mut mailbox,
        &mut now,
    );
    let restricted = Policy {
        add: Who::Admins,
        ..Policy::new(alice.client.identity())
    };
    let step = alice
        .client
        .set_policy(now, group, restricted)
        .expect("queues");
    alice.apply(&mut mailbox, now, step);
    settle(
        &mut [&mut alice, &mut bob, &mut mallory],
        &mut mailbox,
        &mut now,
    );

    // Mallory adds Eve anyway; the mailbox cannot tell, so it is in the log.
    let step = mallory
        .client
        .invite(now, group, eve.client.contact_card())
        .expect("queues");
    mallory.apply(&mut mailbox, now, step);
    settle(
        &mut [&mut alice, &mut bob, &mut mallory, &mut eve],
        &mut mailbox,
        &mut now,
    );
    for honest in [&mut alice, &mut bob] {
        assert!(!honest.client.is_active(&group), "the group stopped");
        assert!(honest.events.iter().any(|e| matches!(
            e,
            Event::Desync { reason, .. } if reason.starts_with(RULES_BROKEN)
        )));
        assert!(honest.client.send(now, group, "secret").is_err());
    }
    // Whatever Eve joined, no honest member speaks there again.
    assert!(
        !eve.events
            .iter()
            .any(|e| matches!(e, Event::Message { .. }))
    );
}
