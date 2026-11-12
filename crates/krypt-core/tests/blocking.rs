//! Blocking and forgetting, with the mailbox in the loop: a blocked identity
//! cannot pull this device into a conversation, its messages in shared
//! groups are dropped, and a forgotten conversation leaves nothing behind,
//! across restarts.

mod common;

use common::{Device, settle};
use krypt_core::client::{Content, Event};
use krypt_core::mailbox::LocalMailbox;
use krypt_wire::msg::{Platform, PushTarget};

fn texts(device: &Device) -> Vec<String> {
    device
        .events
        .iter()
        .filter_map(|e| match e {
            Event::Message {
                content: Content::Text(text),
                ..
            } => Some(text.clone()),
            _ => None,
        })
        .collect()
}

fn joined(device: &Device) -> usize {
    device
        .events
        .iter()
        .filter(|e| matches!(e, Event::Joined { .. }))
        .count()
}

#[test]
fn a_blocked_identity_reaches_nothing() {
    let mut mailbox = LocalMailbox::new();
    let mut now = 0;
    let mut alice = Device::new(1, &mut mailbox);
    let mut bob = Device::new(2, &mut mailbox);
    let mut carol = Device::new(3, &mut mailbox);

    // Carol starts a group with Alice and Bob.
    let (group, step) = carol
        .client
        .start_conversation(now, alice.client.contact_card())
        .expect("starts");
    carol.apply(&mut mailbox, now, step);
    let step = carol
        .client
        .invite(now, group, bob.client.contact_card())
        .expect("invites");
    carol.apply(&mut mailbox, now, step);
    settle(
        &mut [&mut alice, &mut bob, &mut carol],
        &mut mailbox,
        &mut now,
    );
    assert_eq!(joined(&bob), 1);

    // Bob blocks Alice, and the block survives a restart.
    let step = bob.client.block(alice.client.identity()).expect("blocks");
    bob.apply(&mut mailbox, now, step);
    bob.restart(&mut mailbox, 12, now);
    assert_eq!(
        bob.client.blocked().collect::<Vec<_>>(),
        vec![alice.client.identity()]
    );

    // In the group, Alice's messages no longer reach Bob; Carol's do.
    let (_, step) = alice.client.send(now, group, "from alice").expect("sends");
    alice.apply(&mut mailbox, now, step);
    let (_, step) = carol.client.send(now, group, "from carol").expect("sends");
    carol.apply(&mut mailbox, now, step);
    settle(
        &mut [&mut alice, &mut bob, &mut carol],
        &mut mailbox,
        &mut now,
    );
    assert_eq!(texts(&bob), vec!["from carol".to_owned()]);
    assert!(texts(&carol).contains(&"from alice".to_owned()));

    // Alice cannot start a new conversation with Bob.
    let (direct, step) = alice
        .client
        .start_conversation(now, bob.client.contact_card())
        .expect("starts");
    alice.apply(&mut mailbox, now, step);
    settle(
        &mut [&mut alice, &mut bob, &mut carol],
        &mut mailbox,
        &mut now,
    );
    assert_eq!(joined(&bob), 1, "the welcome was refused");
    assert!(!bob.client.conversations().any(|c| c == direct));

    // Unblocked, she can.
    let step = bob.client.unblock(alice.client.identity());
    bob.apply(&mut mailbox, now, step);
    let (_, step) = alice
        .client
        .start_conversation(now, bob.client.contact_card())
        .expect("starts");
    alice.apply(&mut mailbox, now, step);
    settle(
        &mut [&mut alice, &mut bob, &mut carol],
        &mut mailbox,
        &mut now,
    );
    assert_eq!(joined(&bob), 2);
}

#[test]
fn a_forgotten_conversation_leaves_nothing_behind() {
    let mut mailbox = LocalMailbox::new();
    let mut now = 0;
    let mut alice = Device::new(1, &mut mailbox);
    let mut bob = Device::new(2, &mut mailbox);
    let target = PushTarget {
        platform: Platform::WebPush,
        address: b"https://push.example/bob",
    };
    let step = bob.client.set_push_target(now, Some(target));
    bob.apply(&mut mailbox, now, step);

    let (conversation, step) = alice
        .client
        .start_conversation(now, bob.client.contact_card())
        .expect("starts");
    alice.apply(&mut mailbox, now, step);
    settle(&mut [&mut alice, &mut bob], &mut mailbox, &mut now);
    assert!(bob.client.routes().contains(&conversation));
    assert!(mailbox.watchers(&conversation).contains(&target.encode()));
    let disk_before = bob.disk.len();

    // Bob queues a message, then forgets the conversation before it goes.
    let (_, step) = bob
        .client
        .send(now, conversation, "never sent")
        .expect("queues");
    bob.persist_only(step);
    let step = bob.client.forget(now, conversation).expect("forgets");
    bob.apply(&mut mailbox, now, step);
    assert!(!bob.client.routes().contains(&conversation));
    assert!(
        !mailbox.watchers(&conversation).contains(&target.encode()),
        "no more wakeups from it"
    );
    assert!(bob.disk.len() < disk_before, "its records are gone");
    // Only a tombstone remains: the number its next message would have
    // had, should it ever be invited back.
    let route: Vec<u8> = conversation.to_vec();
    let mentions: Vec<&Vec<u8>> = bob
        .disk
        .keys()
        .filter(|k| k.windows(route.len()).any(|w| w == route.as_slice()))
        .collect();
    assert_eq!(mentions, vec![&[&[0, b'T'][..], &route].concat()]);

    // Alice keeps writing; Bob hears nothing, even after a restart.
    let (_, step) = alice
        .client
        .send(now, conversation, "anyone?")
        .expect("sends");
    alice.apply(&mut mailbox, now, step);
    bob.restart(&mut mailbox, 13, now);
    settle(&mut [&mut alice, &mut bob], &mut mailbox, &mut now);
    assert!(texts(&bob).is_empty());
    assert!(texts(&alice).is_empty(), "the queued message never went");
    assert!(!bob.client.conversations().any(|c| c == conversation));
}

#[test]
fn a_device_invited_back_after_forgetting_is_heard_again() {
    let mut mailbox = LocalMailbox::new();
    let mut now = 0;
    let mut alice = Device::new(1, &mut mailbox);
    let mut bob = Device::new(2, &mut mailbox);
    let mut carol = Device::new(3, &mut mailbox);
    let (group, step) = alice
        .client
        .start_conversation(now, bob.client.contact_card())
        .expect("starts");
    alice.apply(&mut mailbox, now, step);
    let step = alice
        .client
        .invite(now, group, carol.client.contact_card())
        .expect("invites");
    alice.apply(&mut mailbox, now, step);
    settle(
        &mut [&mut alice, &mut bob, &mut carol],
        &mut mailbox,
        &mut now,
    );
    for text in ["one", "two"] {
        let (_, step) = bob.client.send(now, group, text).expect("sends");
        bob.apply(&mut mailbox, now, step);
    }
    settle(
        &mut [&mut alice, &mut bob, &mut carol],
        &mut mailbox,
        &mut now,
    );

    // Bob forgets the group; Alice removes him and, later, adds him back.
    let step = bob.client.forget(now, group).expect("forgets");
    bob.apply(&mut mailbox, now, step);
    let step = alice
        .client
        .remove(now, group, bob.client.identity())
        .expect("removes");
    alice.apply(&mut mailbox, now, step);
    settle(
        &mut [&mut alice, &mut bob, &mut carol],
        &mut mailbox,
        &mut now,
    );
    let step = alice
        .client
        .invite(now, group, bob.client.contact_card())
        .expect("invites");
    alice.apply(&mut mailbox, now, step);
    settle(
        &mut [&mut alice, &mut bob, &mut carol],
        &mut mailbox,
        &mut now,
    );
    assert!(bob.client.is_active(&group), "bob rejoined");

    // His numbering carried on, so nobody drops his messages as repeats.
    let (seq, step) = bob.client.send(now, group, "back").expect("sends");
    assert_eq!(seq, 3);
    bob.apply(&mut mailbox, now, step);
    settle(
        &mut [&mut alice, &mut bob, &mut carol],
        &mut mailbox,
        &mut now,
    );
    for device in [&alice, &carol] {
        assert_eq!(texts(device), vec!["one", "two", "back"]);
    }
}
