//! Muting, with the mailbox in the loop: a muted conversation's wakeups are
//! withdrawn (it still updates whenever the app is open), the mute survives
//! a restart, and unmuting, or the mute running out, registers again.

mod common;

use common::{Device, settle};
use krypt_core::client::MUTED_FOREVER;
use krypt_core::mailbox::LocalMailbox;
use krypt_wire::msg::{Platform, PushTarget};

#[test]
fn a_muted_conversation_wakes_nobody_until_it_is_unmuted() {
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
    let registered =
        |mailbox: &LocalMailbox| mailbox.watchers(&conversation).contains(&target.encode());
    assert!(registered(&mailbox));

    // Muted for good: the registration is withdrawn, and stays withdrawn
    // through a restart and the weekly renewal.
    let step = bob
        .client
        .set_muted(now, conversation, Some(MUTED_FOREVER))
        .expect("mutes");
    bob.apply(&mut mailbox, now, step);
    settle(&mut [&mut alice, &mut bob], &mut mailbox, &mut now);
    assert!(!registered(&mailbox));
    bob.restart(&mut mailbox, 12, now);
    now += 8 * 24 * 60 * 60 * 1000;
    settle(&mut [&mut alice, &mut bob], &mut mailbox, &mut now);
    assert!(!registered(&mailbox));
    assert_eq!(bob.client.muted_until(&conversation), Some(MUTED_FOREVER));
    // Messages still arrive while the app is open.
    let (_, step) = alice
        .client
        .send(now, conversation, "still here")
        .expect("sends");
    alice.apply(&mut mailbox, now, step);
    settle(&mut [&mut alice, &mut bob], &mut mailbox, &mut now);
    assert!(bob.events.iter().any(|e| matches!(
        e,
        krypt_core::client::Event::Message { content: krypt_core::client::Content::Text(t), .. } if t == "still here"
    )));

    // Unmuted: registered again.
    let step = bob
        .client
        .set_muted(now, conversation, None)
        .expect("unmutes");
    bob.apply(&mut mailbox, now, step);
    settle(&mut [&mut alice, &mut bob], &mut mailbox, &mut now);
    assert!(registered(&mailbox));

    // Muted for an hour: once the hour is up, it registers by itself.
    let step = bob
        .client
        .set_muted(now, conversation, Some(now + 60 * 60 * 1000))
        .expect("mutes");
    bob.apply(&mut mailbox, now, step);
    settle(&mut [&mut alice, &mut bob], &mut mailbox, &mut now);
    assert!(!registered(&mailbox));
    now += 61 * 60 * 1000;
    settle(&mut [&mut alice, &mut bob], &mut mailbox, &mut now);
    assert!(registered(&mailbox));
    assert_eq!(bob.client.muted_until(&conversation), None);
}
