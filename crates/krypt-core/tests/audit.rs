//! Regressions for what the internal audit of 2026-11-07 found: each test
//! is an attack that used to work, and must not again.

mod common;

use common::{Device, settle};
use krypt_core::client::{Config, Content, Event, Policy, Who};
use krypt_core::join::{LinkKeys, Request};
use krypt_core::mailbox::LocalMailbox;
use krypt_wire::frame::{self, Kind};
use krypt_wire::msg::MessageRef;

fn requests(device: &Device) -> usize {
    device
        .events
        .iter()
        .filter(|e| matches!(e, Event::JoinRequest { .. }))
        .count()
}

/// Mallory, not an admin, removes the only admin: her own device refuses to
/// (and a rogue client doing it stops the group for everyone honest), so
/// she never becomes the admin by being the member left at the lowest leaf.
#[test]
fn a_non_admin_cannot_take_a_group_over_by_removing_its_admin() {
    let mut mailbox = LocalMailbox::new();
    let mut now = 0;
    let mut alice = Device::new(1, &mut mailbox);
    let mut mallory = Device::new(2, &mut mailbox);
    let mut carol = Device::new(3, &mut mailbox);
    // Rex's client ignores the rules.
    let rogue = Config {
        break_rules: true,
        ..Config::default()
    };
    let mut rex = Device::with_config(4, &mut mailbox, rogue);
    let cards = [
        mallory.client.contact_card(),
        carol.client.contact_card(),
        rex.client.contact_card(),
    ];
    let (group, step) = alice
        .client
        .start_group(now, &cards, "Trip")
        .expect("starts");
    alice.apply(&mut mailbox, now, step);
    settle(
        &mut [&mut alice, &mut mallory, &mut carol, &mut rex],
        &mut mailbox,
        &mut now,
    );
    let a = alice.client.identity();
    let restricted = Policy {
        add: Who::Admins,
        edit: Who::Admins,
        ..Policy::new(a)
    };
    let step = alice
        .client
        .set_policy(now, group, restricted)
        .expect("queues");
    alice.apply(&mut mailbox, now, step);
    settle(
        &mut [&mut alice, &mut mallory, &mut carol, &mut rex],
        &mut mailbox,
        &mut now,
    );

    // An honest client does not even try.
    let step = mallory.client.remove(now, group, a).expect("queues");
    mallory.apply(&mut mailbox, now, step);
    settle(
        &mut [&mut alice, &mut mallory, &mut carol, &mut rex],
        &mut mailbox,
        &mut now,
    );
    assert!(carol.client.members(&group).contains(&a));
    assert_eq!(carol.client.admins(&group), vec![a]);

    // A rogue one does, and the group stops for the honest members.
    let step = rex.client.remove(now, group, a).expect("queues");
    rex.apply(&mut mailbox, now, step);
    settle(
        &mut [&mut alice, &mut mallory, &mut carol, &mut rex],
        &mut mailbox,
        &mut now,
    );
    assert!(
        !carol.client.is_active(&group),
        "carol stops at the removal"
    );
    assert!(carol.events.iter().any(|e| matches!(
        e,
        Event::Desync { reason, .. } if reason.contains("only admins may remove an admin")
    )));
}

/// Removals say who made them; leaving is told apart.
#[test]
fn removals_say_who_removed_whom() {
    let mut mailbox = LocalMailbox::new();
    let mut now = 0;
    let mut alice = Device::new(1, &mut mailbox);
    let mut bob = Device::new(2, &mut mailbox);
    let mut carol = Device::new(3, &mut mailbox);
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
    let (a, c) = (alice.client.identity(), carol.client.identity());
    let step = alice.client.remove(now, group, c).expect("queues");
    alice.apply(&mut mailbox, now, step);
    settle(
        &mut [&mut alice, &mut bob, &mut carol],
        &mut mailbox,
        &mut now,
    );
    assert!(bob.events.iter().any(|e| matches!(
        e,
        Event::MembersRemoved { identities, by: Some(by), .. } if *identities == [c] && *by == a
    )));
    let (_, step) = alice.client.leave(now, group).expect("leaves");
    alice.apply(&mut mailbox, now, step);
    settle(&mut [&mut alice, &mut bob], &mut mailbox, &mut now);
    assert!(bob.events.iter().any(|e| matches!(
        e,
        Event::MembersRemoved { identities, by: None, .. } if *identities == [a]
    )));
    // Alice was the admin: she handed the role on before leaving.
    assert_eq!(bob.client.admins(&group), vec![bob.client.identity()]);
}

/// A member reuses the group's link seed in a lookalike group of her own:
/// it is another link there, so her device reads no request meant for the
/// real group, and the real group's admin still sees it.
#[test]
fn a_lookalike_group_with_the_same_seed_gets_no_requests() {
    let mut mailbox = LocalMailbox::new();
    let mut now = 0;
    let mut alice = Device::new(1, &mut mailbox);
    let mut mallory = Device::new(2, &mut mailbox);
    let mut sock = Device::new(5, &mut mailbox);
    let mut dana = Device::new(3, &mut mailbox);
    let (group, step) = alice
        .client
        .start_group(now, &[mallory.client.contact_card()], "Climbing")
        .expect("starts");
    alice.apply(&mut mailbox, now, step);
    settle(&mut [&mut alice, &mut mallory], &mut mailbox, &mut now);
    let rules = Policy {
        link: Some([42; 32]),
        ..Policy::new(alice.client.identity())
    };
    let step = alice.client.set_policy(now, group, rules).expect("queues");
    alice.apply(&mut mailbox, now, step);
    settle(&mut [&mut alice, &mut mallory], &mut mailbox, &mut now);
    let seed = mallory
        .client
        .policy(&group)
        .and_then(|p| p.link)
        .expect("members have the seed");

    let (fake, step) = mallory
        .client
        .start_group(now, &[sock.client.contact_card()], "Climbing")
        .expect("starts");
    mallory.apply(&mut mailbox, now, step);
    settle(&mut [&mut mallory, &mut sock], &mut mailbox, &mut now);
    let theirs = Policy {
        link: Some(seed),
        ..Policy::new(mallory.client.identity())
    };
    let step = mallory
        .client
        .set_policy(now, fake, theirs)
        .expect("queues");
    mallory.apply(&mut mailbox, now, step);
    settle(&mut [&mut mallory, &mut sock], &mut mailbox, &mut now);

    let code = LinkKeys::from_seed(&seed, &group).code;
    assert_ne!(code, LinkKeys::from_seed(&seed, &fake).code);
    let response = mailbox.handle(now, &code.header_frame()).expect("answers");
    let header = code
        .read_header(frame::decode(&response).expect("decodes").body)
        .expect("the real group's header");
    let (request, step) = dana
        .client
        .join_request(now, &code, &header, "Dana")
        .expect("asks");
    dana.persist_only(step);
    mailbox.handle(now, &request).expect("answers");
    settle(
        &mut [&mut alice, &mut mallory, &mut sock, &mut dana],
        &mut mailbox,
        &mut now,
    );
    assert_eq!(requests(&mallory), 0, "the lookalike reads nothing");
    assert_eq!(requests(&alice), 1, "the real admin sees Dana");
}

/// Junk with the link's token hides no request, however much of it comes
/// first; and a request already shown is not shown again after a restart.
#[test]
fn junk_requests_hide_nothing_and_shown_ones_stay_shown() {
    for junk in [0, 63, 64, 200] {
        let mut mailbox = LocalMailbox::new();
        let mut now = 0;
        let mut alice = Device::new(1, &mut mailbox);
        let mut bob = Device::new(2, &mut mailbox);
        let mut dana = Device::new(3, &mut mailbox);
        let (group, step) = alice
            .client
            .start_group(now, &[bob.client.contact_card()], "Climbing")
            .expect("starts");
        alice.apply(&mut mailbox, now, step);
        settle(&mut [&mut alice, &mut bob], &mut mailbox, &mut now);
        let seed = [42; 32];
        let rules = Policy {
            link: Some(seed),
            ..Policy::new(alice.client.identity())
        };
        let step = alice.client.set_policy(now, group, rules).expect("queues");
        alice.apply(&mut mailbox, now, step);
        settle(&mut [&mut alice, &mut bob], &mut mailbox, &mut now);
        let code = LinkKeys::from_seed(&seed, &group).code;
        let response = mailbox.handle(now, &code.header_frame()).expect("answers");
        let header = code
            .read_header(frame::decode(&response).expect("decodes").body)
            .expect("header");
        for i in 0..junk {
            let rubbish = Request {
                card: bob.client.contact_card(),
                name: format!("junk{i}"),
                key_package: vec![0; 64],
                at_ms: now,
                signature: [0; 64],
            };
            let answer = mailbox
                .handle(now, &code.request_frame(&header, &rubbish))
                .expect("answers");
            assert_eq!(
                frame::decode(&answer).expect("decodes").kind,
                Kind::Accepted
            );
        }
        let (request, step) = dana
            .client
            .join_request(now, &code, &header, "Dana")
            .expect("asks");
        dana.persist_only(step);
        mailbox.handle(now, &request).expect("answers");
        // Alice was away: no pushes reached her. She starts again.
        let _ = mailbox.take_notifications();
        alice.restart(&mut mailbox, 11, now);
        let _ = mailbox.take_notifications();
        settle(&mut [&mut alice, &mut bob], &mut mailbox, &mut now);
        assert_eq!(requests(&alice), 1, "after {junk} junk requests");
        alice.events.clear();
        alice.restart(&mut mailbox, 12, now);
        settle(&mut [&mut alice, &mut bob], &mut mailbox, &mut now);
        assert_eq!(requests(&alice), 0, "shown once only");
    }
}

/// Someone with the link asks with a certificate claiming a member's device
/// id: the admin's device never shows it, so approving it can never split
/// the group (every other member would refuse the commit).
#[test]
fn a_request_reusing_a_members_device_id_is_never_shown() {
    use krypt_core::client::CIPHERSUITE;
    use krypt_core::identity::{ContactCard, Identity};
    use openmls::prelude::tls_codec::Serialize as _;
    use openmls::prelude::*;
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_traits::signatures::Signer as _;
    use openmls_traits::types::SignatureScheme;

    let mut mailbox = LocalMailbox::new();
    let mut now = 0;
    let mut alice = Device::new(1, &mut mailbox);
    let mut bob = Device::new(2, &mut mailbox);
    let (group, step) = alice
        .client
        .start_group(now, &[bob.client.contact_card()], "Climbing")
        .expect("starts");
    alice.apply(&mut mailbox, now, step);
    settle(&mut [&mut alice, &mut bob], &mut mailbox, &mut now);
    let seed = [42; 32];
    let rules = Policy {
        link: Some(seed),
        ..Policy::new(alice.client.identity())
    };
    let step = alice.client.set_policy(now, group, rules).expect("queues");
    alice.apply(&mut mailbox, now, step);
    settle(&mut [&mut alice, &mut bob], &mut mailbox, &mut now);

    let code = LinkKeys::from_seed(&seed, &group).code;
    let response = mailbox.handle(now, &code.header_frame()).expect("answers");
    let header = code
        .read_header(frame::decode(&response).expect("decodes").body)
        .expect("header");
    // A genuine identity of their own, certifying a device with Bob's id.
    let sam = Identity::from_seed([77; 32]);
    let mls = ed25519_dalek::SigningKey::from_bytes(&[78; 32]);
    let mls_public = mls.verifying_key().to_bytes();
    let signer = SignatureKeyPair::from_raw(
        SignatureScheme::ED25519,
        mls.to_bytes().to_vec(),
        mls_public.to_vec(),
    );
    let inbox = [9u8; 16];
    let cert = sam.certify(mls_public, bob.client.device(), inbox);
    let credential = CredentialWithKey {
        credential: BasicCredential::new(cert.encode()).into(),
        signature_key: mls_public.to_vec().into(),
    };
    let capabilities = Capabilities::builder()
        .ciphersuites(vec![CIPHERSUITE])
        .extensions(vec![
            ExtensionType::LastResort,
            ExtensionType::Unknown(0xF0D1),
            ExtensionType::Unknown(0xF0D2),
        ])
        .build();
    let provider = openmls_rust_crypto::OpenMlsRustCrypto::default();
    let bundle = KeyPackage::builder()
        .leaf_node_capabilities(capabilities)
        .build(CIPHERSUITE, &provider, &signer, credential)
        .expect("a key package");
    let key_package = bundle
        .key_package()
        .tls_serialize_detached()
        .expect("serializes");
    let card = ContactCard {
        identity: sam.public(),
        inbox,
    };
    let signed = code.signed_bytes(&card, "Sam", &key_package, now);
    let signature: [u8; 64] = signer
        .sign(&signed)
        .expect("signs")
        .try_into()
        .expect("64 bytes");
    let asked = code.request_frame(
        &header,
        &Request {
            card,
            name: "Sam".into(),
            key_package,
            at_ms: now,
            signature,
        },
    );
    mailbox.handle(now, &asked).expect("answers");
    settle(&mut [&mut alice, &mut bob], &mut mailbox, &mut now);
    assert_eq!(requests(&alice), 0);
    assert!(alice.client.is_active(&group) && bob.client.is_active(&group));
}

/// Members who come and go leave no duplicate windows behind: they used to
/// pile up until restoring the device failed.
#[test]
fn members_who_come_and_go_leave_no_windows_behind() {
    let mut mailbox = LocalMailbox::new();
    let mut now = 0;
    let mut alice = Device::new(1, &mut mailbox);
    let mut bob = Device::new(2, &mut mailbox);
    let (group, step) = alice
        .client
        .start_group(now, &[bob.client.contact_card()], "Trip")
        .expect("starts");
    alice.apply(&mut mailbox, now, step);
    settle(&mut [&mut alice, &mut bob], &mut mailbox, &mut now);
    for seed in 10..16 {
        let mut guest = Device::new(seed, &mut mailbox);
        let step = alice
            .client
            .invite(now, group, guest.client.contact_card())
            .expect("invites");
        alice.apply(&mut mailbox, now, step);
        settle(
            &mut [&mut alice, &mut bob, &mut guest],
            &mut mailbox,
            &mut now,
        );
        let (_, step) = guest.client.send(now, group, "hi").expect("sends");
        guest.apply(&mut mailbox, now, step);
        settle(
            &mut [&mut alice, &mut bob, &mut guest],
            &mut mailbox,
            &mut now,
        );
        let step = alice
            .client
            .remove(now, group, guest.client.identity())
            .expect("removes");
        alice.apply(&mut mailbox, now, step);
        settle(
            &mut [&mut alice, &mut bob, &mut guest],
            &mut mailbox,
            &mut now,
        );
    }
    // Only the members' devices: Bob's (and Alice's own, at most).
    assert!(alice.client.duplicate_windows(&group) <= 2);
    alice.restart(&mut mailbox, 20, now);
    assert!(alice.client.is_active(&group));
}

/// References name a device in the group: an edit of someone else's
/// message, or receipts for made-up devices, never reach the app (where they
/// used to wait, stored, for a message that never comes).
#[test]
fn references_to_other_peoples_or_made_up_devices_are_dropped() {
    let mut mailbox = LocalMailbox::new();
    let mut now = 0;
    let mut alice = Device::new(1, &mut mailbox);
    let mut bob = Device::new(2, &mut mailbox);
    let mut mallory = Device::new(3, &mut mailbox);
    let cards = [bob.client.contact_card(), mallory.client.contact_card()];
    let (group, step) = alice
        .client
        .start_group(now, &cards, "Trip")
        .expect("starts");
    alice.apply(&mut mailbox, now, step);
    settle(
        &mut [&mut alice, &mut bob, &mut mallory],
        &mut mailbox,
        &mut now,
    );
    let bobs = MessageRef {
        device: bob.client.device(),
        seq: 1,
    };
    let made_up = MessageRef {
        device: [0xEE; 32],
        seq: 1,
    };
    for content in [
        Content::Edit {
            to: bobs,
            text: "not mine to edit".into(),
        },
        Content::Delete { to: bobs },
        Content::React {
            to: made_up,
            emoji: "👍".into(),
        },
        Content::Receipt(vec![made_up]),
    ] {
        let (_, step) = mallory
            .client
            .send_content(now, group, content)
            .expect("sends");
        mallory.apply(&mut mailbox, now, step);
    }
    settle(
        &mut [&mut alice, &mut bob, &mut mallory],
        &mut mailbox,
        &mut now,
    );
    let from_mallory = alice
        .events
        .iter()
        .filter(|e| matches!(e, Event::Message { from, .. } if *from == mallory.client.identity()))
        .count();
    assert_eq!(from_mallory, 0);
}
