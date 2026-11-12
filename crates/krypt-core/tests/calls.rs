//! Calls and disappearing messages end to end, with the mailbox in the loop:
//! call signals reach the right device and survive a restart before they
//! are sent, only members get relay credentials, and every member (and
//! anyone who joins later) agrees on a conversation's timer, even when two
//! change it at once.

mod common;

use common::{Device, authorize, settle};
use krypt_core::client::{Call, Content, Event};
use krypt_core::mailbox::LocalMailbox;
use krypt_wire::frame::Kind;
use krypt_wire::msg::{CallEnd, CallKind, Reject};

const EVERYONE: [u8; 32] = [0; 32];

/// The call signals a device received, in order.
fn calls(device: &Device) -> Vec<(Call, [u8; 32])> {
    device
        .events
        .iter()
        .filter_map(|e| match e {
            Event::Message {
                content: Content::Call(call),
                device,
                ..
            } => Some(((**call).clone(), *device)),
            _ => None,
        })
        .collect()
}

/// The texts a device received, with their timers.
fn texts(device: &Device) -> Vec<(String, u32)> {
    device
        .events
        .iter()
        .filter_map(|e| match e {
            Event::Message {
                content: Content::Text(text),
                expires_after_s,
                ..
            } => Some((text.clone(), *expires_after_s)),
            _ => None,
        })
        .collect()
}

#[test]
fn a_call_is_set_up_answered_and_ended() {
    let mut mailbox = LocalMailbox::new();
    let mut now = 0;
    let mut alice = Device::new(1, &mut mailbox);
    let mut bob = Device::new(2, &mut mailbox);
    let card = bob.client.contact_card();
    let (conversation, step) = alice.client.start_conversation(now, card).expect("starts");
    alice.apply(&mut mailbox, now, step);
    settle(&mut [&mut alice, &mut bob], &mut mailbox, &mut now);

    let offer = Call {
        call: [7; 16],
        to: EVERYONE,
        kind: CallKind::Offer,
        video: true,
        sdp: "v=0 offer".to_owned(),
    };
    // Alice crashes after queueing the offer; it still goes out, once.
    let (_, step) = alice
        .client
        .send_call(now, conversation, offer.clone())
        .expect("queues");
    alice.persist_only(step);
    alice.restart(&mut mailbox, 11, now);
    settle(&mut [&mut alice, &mut bob], &mut mailbox, &mut now);
    let received = calls(&bob);
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].0, offer);
    assert_eq!(received[0].1, alice.client.device(), "from alice's device");

    let answer = Call {
        to: alice.client.device(),
        kind: CallKind::Answer,
        video: true,
        sdp: "v=0 answer".to_owned(),
        ..offer.clone()
    };
    let (_, step) = bob
        .client
        .send_call(now, conversation, answer.clone())
        .expect("queues");
    bob.apply(&mut mailbox, now, step);
    let hangup = Call {
        to: EVERYONE,
        kind: CallKind::End(CallEnd::Hangup),
        sdp: String::new(),
        ..offer.clone()
    };
    let (_, step) = bob
        .client
        .send_call(now, conversation, hangup.clone())
        .expect("queues");
    bob.apply(&mut mailbox, now, step);
    settle(&mut [&mut alice, &mut bob], &mut mailbox, &mut now);
    let received: Vec<Call> = calls(&alice).into_iter().map(|(c, _)| c).collect();
    assert_eq!(received, vec![answer, hangup], "in order, exactly once");

    // Signals that break their kind's rules are refused before sending.
    let bad = Call {
        sdp: String::new(),
        ..offer
    };
    assert!(bob.client.send_call(now, conversation, bad).is_err());
}

#[test]
fn only_members_get_relay_credentials() {
    let mut mailbox = LocalMailbox::new();
    let mut now = 0;
    let mut alice = Device::new(1, &mut mailbox);
    let mut bob = Device::new(2, &mut mailbox);
    let mut carol = Device::new(3, &mut mailbox);
    let card = bob.client.contact_card();
    let (conversation, step) = alice.client.start_conversation(now, card).expect("starts");
    alice.apply(&mut mailbox, now, step);
    settle(&mut [&mut alice, &mut bob], &mut mailbox, &mut now);

    let grant = alice.client.turn_auth(conversation).expect("a member");
    let turn = |mailbox: &mut LocalMailbox, grant: &[u8]| {
        authorize(mailbox, Kind::AuthorizeTurn, conversation, grant)
    };
    assert_eq!(turn(&mut mailbox, &grant.encode()), Ok(()));
    let bobs = bob.client.turn_auth(conversation).expect("a member");
    assert_eq!(turn(&mut mailbox, &bobs.encode()), Ok(()));
    assert!(carol.client.turn_auth(conversation).is_err());

    // After a commit, the old proof is stale; a fresh one works.
    let step = bob.client.update_keys(now, conversation).expect("updates");
    bob.apply(&mut mailbox, now, step);
    settle(
        &mut [&mut alice, &mut bob, &mut carol],
        &mut mailbox,
        &mut now,
    );
    assert_eq!(turn(&mut mailbox, &grant.encode()), Err(Reject::StaleEpoch));
    let fresh = alice.client.turn_auth(conversation).expect("a member");
    assert_eq!(turn(&mut mailbox, &fresh.encode()), Ok(()));
}

/// The timer changes a device was told about, as (who, seconds).
fn timers(device: &Device) -> Vec<([u8; 32], u32)> {
    device
        .events
        .iter()
        .filter_map(|e| match e {
            Event::Timer { by, seconds, .. } => Some((*by, *seconds)),
            _ => None,
        })
        .collect()
}

#[test]
fn every_member_agrees_on_the_timer() {
    let mut mailbox = LocalMailbox::new();
    let mut now = 0;
    let mut alice = Device::new(1, &mut mailbox);
    let mut bob = Device::new(2, &mut mailbox);
    let card = bob.client.contact_card();
    let (conversation, step) = alice.client.start_conversation(now, card).expect("starts");
    alice.apply(&mut mailbox, now, step);
    settle(&mut [&mut alice, &mut bob], &mut mailbox, &mut now);
    assert_eq!(alice.client.timer(&conversation), 0);

    // Alice turns it on; her messages carry it at once, and Bob's after he
    // has seen her change.
    let step = alice
        .client
        .set_timer(now, conversation, 3600)
        .expect("sets");
    alice.apply(&mut mailbox, now, step);
    assert_eq!(alice.client.timer(&conversation), 3600);
    let (_, step) = alice.client.send(now, conversation, "one").expect("sends");
    alice.apply(&mut mailbox, now, step);
    settle(&mut [&mut alice, &mut bob], &mut mailbox, &mut now);
    assert_eq!(bob.client.timer(&conversation), 3600);
    assert_eq!(timers(&bob), vec![(alice.client.identity(), 3600)]);
    assert_eq!(texts(&bob), vec![("one".to_owned(), 3600)]);
    let (_, step) = bob.client.send(now, conversation, "two").expect("sends");
    bob.apply(&mut mailbox, now, step);
    settle(&mut [&mut alice, &mut bob], &mut mailbox, &mut now);
    assert_eq!(texts(&alice), vec![("two".to_owned(), 3600)]);

    // Someone who joins later learns it from the group itself.
    let mut carol = Device::new(3, &mut mailbox);
    let card = carol.client.contact_card();
    let step = alice
        .client
        .invite(now, conversation, card)
        .expect("invites");
    alice.apply(&mut mailbox, now, step);
    settle(
        &mut [&mut alice, &mut bob, &mut carol],
        &mut mailbox,
        &mut now,
    );
    assert_eq!(carol.client.timer(&conversation), 3600);

    // Two change it at once: both commits race for the epoch, and every
    // member ends up with the same timer, across a restart too.
    let step = alice.client.set_timer(now, conversation, 60).expect("sets");
    alice.apply(&mut mailbox, now, step);
    let step = bob.client.set_timer(now, conversation, 0).expect("sets");
    bob.apply(&mut mailbox, now, step);
    settle(
        &mut [&mut alice, &mut bob, &mut carol],
        &mut mailbox,
        &mut now,
    );
    let agreed = alice.client.timer(&conversation);
    assert_eq!(bob.client.timer(&conversation), agreed);
    assert_eq!(carol.client.timer(&conversation), agreed);
    alice.restart(&mut mailbox, 12, now);
    bob.restart(&mut mailbox, 13, now);
    settle(
        &mut [&mut alice, &mut bob, &mut carol],
        &mut mailbox,
        &mut now,
    );
    assert_eq!(alice.client.timer(&conversation), agreed);
    assert_eq!(bob.client.timer(&conversation), agreed);
    assert_eq!(
        timers(&carol).last().map(|(_, s)| *s),
        Some(agreed),
        "the last change carol heard of is the one that holds"
    );

    assert!(
        alice
            .client
            .set_timer(now, conversation, 29 * 24 * 3600)
            .is_err()
    );
}
