//! Replies, reactions, edits, deletions, read receipts and voice messages,
//! with the mailbox in the loop: each arrives as sent, the ones that only
//! refer to a message (receipts, edits, reactions taken back) are submitted
//! quietly so they wake nobody, invalid ones are refused, and unsent ones
//! survive a restart.

mod common;

use common::{Device, settle};
use krypt_core::client::{Content, Effect, Event, SharedFile, SharedVoice};
use krypt_core::mailbox::LocalMailbox;
use krypt_wire::frame::{self, Kind};
use krypt_wire::limits::WAVEFORM_LEN;
use krypt_wire::msg::{MessageRef, Submit};

fn received(device: &Device) -> Vec<Content> {
    device
        .events
        .iter()
        .filter_map(|e| match e {
            Event::Message { content, .. } => Some(content.clone()),
            _ => None,
        })
        .collect()
}

/// Whether each message submit in `effects` is quiet, in order.
fn quietness(effects: &[Effect]) -> Vec<bool> {
    effects
        .iter()
        .filter_map(|e| match e {
            Effect::Mailbox(bytes) => frame::decode(bytes).ok(),
            Effect::Event(_) => None,
        })
        .filter(|f| f.kind == Kind::Submit)
        .filter_map(|f| Submit::decode(f.body).ok().map(|s| s.quiet))
        .collect()
}

#[test]
fn every_kind_of_message_arrives_and_only_some_wake() {
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
    let (seq, step) = alice
        .client
        .send(now, conversation, "lunch?")
        .expect("sends");
    alice.apply(&mut mailbox, now, step);
    settle(&mut [&mut alice, &mut bob], &mut mailbox, &mut now);
    let lunch = MessageRef {
        device: alice.client.device(),
        seq,
    };

    let voice = SharedVoice {
        file: SharedFile {
            id: [1; 16],
            key: [2; 32],
            size: 9_000,
            name: "voice.webm".into(),
            media_type: "audio/webm".into(),
            width: 0,
            height: 0,
            thumbnail: Vec::new(),
        },
        duration_ms: 2_400,
        waveform: vec![9; WAVEFORM_LEN],
    };
    let sent = [
        (
            Content::Reply {
                to: lunch,
                text: "yes!".into(),
            },
            false,
        ),
        (
            Content::React {
                to: lunch,
                emoji: "👍".into(),
            },
            false,
        ),
        (
            Content::React {
                to: lunch,
                emoji: String::new(),
            },
            true,
        ),
        (Content::Receipt(vec![lunch]), true),
        (Content::Voice(Box::new(voice)), false),
    ];
    for (content, quiet) in &sent {
        let (_, step) = bob
            .client
            .send_content(now, conversation, content.clone())
            .expect("sends");
        assert_eq!(quietness(&step.effects), vec![*quiet], "{content:?}");
        bob.apply(&mut mailbox, now, step);
        settle(&mut [&mut alice, &mut bob], &mut mailbox, &mut now);
    }
    let got = received(&alice);
    for (content, _) in &sent {
        assert!(got.contains(content), "alice got {content:?}");
    }

    // Alice edits and deletes her own message; the edit is quiet, the
    // deletion is not (it must reach sleeping devices).
    for (content, quiet) in [
        (
            Content::Edit {
                to: lunch,
                text: "lunch at 1?".into(),
            },
            true,
        ),
        (Content::Delete { to: lunch }, false),
    ] {
        let (_, step) = alice
            .client
            .send_content(now, conversation, content.clone())
            .expect("sends");
        assert_eq!(quietness(&step.effects), vec![quiet]);
        alice.apply(&mut mailbox, now, step);
        settle(&mut [&mut alice, &mut bob], &mut mailbox, &mut now);
        assert!(received(&bob).contains(&content));
    }

    // Invalid content is refused before it is queued.
    for bad in [
        Content::Text("use send".into()),
        Content::Reply {
            to: lunch,
            text: String::new(),
        },
        Content::React {
            to: lunch,
            emoji: "x".repeat(40),
        },
        Content::Receipt(Vec::new()),
        Content::Receipt(vec![lunch, MessageRef { seq: 9, ..lunch }]),
    ] {
        assert!(bob.client.send_content(now, conversation, bad).is_err());
    }
}

#[test]
fn unsent_messages_of_every_kind_survive_a_restart() {
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
    let to = MessageRef {
        device: bob.client.device(),
        seq: 1,
    };
    // Queued while the mailbox is out of reach: persisted, not sent.
    let contents = [
        Content::Reply {
            to,
            text: "later".into(),
        },
        Content::React {
            to,
            emoji: "🙏".into(),
        },
    ];
    for content in &contents {
        let (_, step) = alice
            .client
            .send_content(now, conversation, content.clone())
            .expect("queues");
        alice.persist_only(step);
    }
    alice.restart(&mut mailbox, 11, now);
    settle(&mut [&mut alice, &mut bob], &mut mailbox, &mut now);
    let got = received(&bob);
    for content in &contents {
        assert!(
            got.contains(content),
            "bob got {content:?} after alice restarted"
        );
    }
}
