//! Signals (typing, online) with the mailbox in the loop: relayed to the
//! members connected now and stored nowhere, shown to the others but not to
//! the sender, and dropped when replayed, tampered with, stale, or sent by
//! someone who is not a member.

mod common;

use common::{Device, authorize, settle};
use krypt_core::client::Event;
use krypt_core::identity::IdentityKey;
use krypt_core::mailbox::LocalMailbox;
use krypt_wire::frame::{self, Kind};
use krypt_wire::limits::SIGNAL_SKEW_MS;
use krypt_wire::msg::{Reject, Signal, SignalKind};

fn signals(device: &Device) -> Vec<(IdentityKey, SignalKind)> {
    device
        .events
        .iter()
        .filter_map(|e| match e {
            Event::Signal { from, kind, .. } => Some((*from, *kind)),
            _ => None,
        })
        .collect()
}

#[test]
fn signals_reach_the_others_connected_now_and_nothing_else() {
    let mut mailbox = LocalMailbox::new();
    let mut now = 0;
    let mut alice = Device::new(1, &mut mailbox);
    let mut bob = Device::new(2, &mut mailbox);
    let (conversation, step) = alice
        .client
        .start_conversation(now, bob.client.contact_card())
        .expect("starts");
    alice.apply(&mut mailbox, now, step);
    settle(&mut [&mut alice, &mut bob], &mut mailbox, &mut now);
    let stored: Vec<Vec<u8>> = mailbox.values().map(<[u8]>::to_vec).collect();

    // Alice types: the mailbox relays it once, stores nothing.
    let step = alice
        .client
        .signal(now, conversation, SignalKind::Typing)
        .expect("signals");
    alice.apply(&mut mailbox, now, step);
    let relayed = mailbox.take_notifications();
    assert_eq!(relayed.len(), 1);
    let signaled = relayed[0].1.clone();
    assert_eq!(
        frame::decode(&signaled).expect("decodes").kind,
        Kind::Signaled
    );
    let after: Vec<Vec<u8>> = mailbox.values().map(<[u8]>::to_vec).collect();
    assert_eq!(stored, after, "a signal is never stored");

    for device in [&mut alice, &mut bob] {
        let step = device.client.receive(now, &signaled);
        device.apply(&mut mailbox, now, step);
    }
    assert_eq!(
        signals(&bob),
        vec![(alice.client.identity(), SignalKind::Typing)]
    );
    assert!(signals(&alice).is_empty(), "not shown to its sender");

    // The same signal again says nothing new.
    let step = bob.client.receive(now + 10, &signaled);
    bob.apply(&mut mailbox, now + 10, step);
    assert_eq!(signals(&bob).len(), 1, "a replay is dropped");

    // Changed in transit (in a frame that is otherwise well formed), it
    // does not open.
    let original = frame::decode(&signaled).expect("decodes");
    let mut body = original.body.to_vec();
    let last = body.len() - 1;
    body[last] ^= 1;
    let tampered = frame::encode_vec(original.kind, original.seq, original.route, &body);
    let step = bob.client.receive(now + 20, &tampered);
    bob.apply(&mut mailbox, now + 20, step);
    assert_eq!(signals(&bob).len(), 1, "a tampered signal is dropped");

    // One sent long ago (or far ahead of the receiver's clock) is dropped.
    now += 1_000;
    let step = alice
        .client
        .signal(now, conversation, SignalKind::Online)
        .expect("signals");
    alice.apply(&mut mailbox, now, step);
    let (_, late) = mailbox.take_notifications().pop().expect("relayed");
    let step = bob.client.receive(now + SIGNAL_SKEW_MS + 1, &late);
    bob.apply(&mut mailbox, now + SIGNAL_SKEW_MS + 1, step);
    assert_eq!(signals(&bob).len(), 1, "a stale signal is dropped");

    // A fresh one goes through.
    now += 1_000;
    let step = alice
        .client
        .signal(now, conversation, SignalKind::Idle)
        .expect("signals");
    alice.apply(&mut mailbox, now, step);
    for (_, notify) in mailbox.take_notifications() {
        let step = bob.client.receive(now, &notify);
        bob.apply(&mut mailbox, now, step);
    }
    assert_eq!(
        signals(&bob).last(),
        Some(&(alice.client.identity(), SignalKind::Idle))
    );

    // Someone who is not a member cannot reach the members' screens.
    let decoded = frame::decode(&signaled).expect("decodes");
    let mut forged = Signal::decode(decoded.body).expect("decodes");
    forged.auth = [7; 16];
    assert_eq!(
        authorize(&mut mailbox, Kind::Signal, conversation, &forged.encode()),
        Err(Reject::Forbidden)
    );
    assert!(mailbox.take_notifications().is_empty(), "nothing relayed");
}

#[test]
fn signals_need_an_active_conversation() {
    let mut mailbox = LocalMailbox::new();
    let mut alice = Device::new(1, &mut mailbox);
    assert!(alice.client.signal(0, [9; 16], SignalKind::Typing).is_err());
}
