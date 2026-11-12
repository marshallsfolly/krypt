//! Invite links, with the mailbox in the loop: an admin turns the link on
//! and their device opens the group's requests log; someone with the link
//! (a stranger to everyone) reads the group's name and asks; the admin sees
//! the request, checked, and approves it; the requester joins with exactly
//! the key package they sent, and knows it is the group they asked for.
//! Requests in someone else's name are dropped; a group that adds the
//! requester another way is not taken for the one they asked; and nobody
//! else can take over the requests log.

mod common;

use common::{Device, settle};
use krypt_core::client::{Event, LinkChange, Policy};
use krypt_core::join::{JoinCode, LinkKeys, Request};
use krypt_core::mailbox::LocalMailbox;
use krypt_wire::frame::{self, Kind};
use krypt_wire::msg::{OpenRequests, Reject, Rejected};

fn header(mailbox: &mut LocalMailbox, code: &JoinCode) -> krypt_core::join::Header {
    let response = mailbox.handle(0, &code.header_frame()).expect("answers");
    let response = frame::decode(&response).expect("decodes");
    assert_eq!(response.kind, Kind::Header);
    code.read_header(response.body).expect("the link's header")
}

fn requests(device: &Device) -> Vec<(krypt_core::mailbox::Hash, String)> {
    device
        .events
        .iter()
        .filter_map(|e| match e {
            Event::JoinRequest { id, name, .. } => Some((*id, name.clone())),
            _ => None,
        })
        .collect()
}

#[test]
fn a_stranger_asks_with_the_link_and_an_admin_lets_them_in() {
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

    // Alice turns the link on.
    let seed = [42; 32];
    let link = Policy {
        link: Some(seed),
        ..Policy::new(alice.client.identity())
    };
    let step = alice.client.set_policy(now, group, link).expect("queues");
    alice.apply(&mut mailbox, now, step);
    settle(&mut [&mut alice, &mut bob], &mut mailbox, &mut now);
    let code = LinkKeys::from_seed(&seed, &group).code;
    assert!(
        bob.events.iter().any(|e| matches!(
            e,
            Event::Rules {
                link: Some(LinkChange::On),
                ..
            }
        )),
        "members are told the link is on"
    );

    // Nobody else can take the requests log over.
    let squatter = LinkKeys::from_seed(&[7; 32], &group);
    let body = squatter.open_body(&krypt_core::provider::Rand::seeded(9), "Mine");
    let squat = frame::encode_vec(Kind::OpenRequests, 1, code.route(), &body);
    let response = mailbox.handle(now, &squat).expect("answers");
    let response = frame::decode(&response).expect("decodes");
    assert_eq!(
        Rejected::decode(response.body).map(|r| r.reason),
        Ok(Reject::Forbidden)
    );
    let _ = OpenRequests::decode(&body).expect("well formed, just not theirs");

    // Dana has the link: she reads the group's name and asks.
    let header = header(&mut mailbox, &code);
    assert_eq!(header.name, "Climbing");
    let (request, step) = dana
        .client
        .join_request(now, &code, &header, "Dana")
        .expect("asks");
    dana.persist_only(step);
    let accepted = mailbox.handle(now, &request).expect("answers");
    assert_eq!(
        frame::decode(&accepted).expect("decodes").kind,
        Kind::Accepted
    );
    assert_eq!(dana.client.pending_joins(), vec!["Climbing".to_owned()]);

    // Mallory asks in Dana's name: Dana's card, without Dana's key.
    let impostor = Request {
        card: dana.client.contact_card(),
        name: "Dana".into(),
        key_package: vec![0; 64],
        at_ms: now,
        signature: [0; 64],
    };
    let fake = code.request_frame(&header, &impostor);
    mailbox
        .handle(now, &fake)
        .expect("stored: the mailbox cannot read it");

    settle(
        &mut [&mut alice, &mut bob, &mut dana],
        &mut mailbox,
        &mut now,
    );
    let seen = requests(&alice);
    assert_eq!(seen.len(), 1, "only Dana's genuine request: {seen:?}");
    assert_eq!(seen[0].1, "Dana");
    assert!(requests(&bob).is_empty(), "only admins read requests");

    // Alice approves: Dana joins, knowing it is the group she asked for.
    let step = alice
        .client
        .approve_join(now, group, seen[0].0)
        .expect("approves");
    alice.apply(&mut mailbox, now, step);
    settle(
        &mut [&mut alice, &mut bob, &mut dana],
        &mut mailbox,
        &mut now,
    );
    assert!(dana.events.iter().any(|e| matches!(
        e,
        Event::Joined { conversation, via_link: true, .. } if *conversation == group
    )));
    assert!(
        alice
            .client
            .members(&group)
            .contains(&dana.client.identity())
    );
    assert!(dana.client.pending_joins().is_empty());
}

#[test]
fn a_group_that_adds_the_requester_another_way_is_not_the_one_asked_for() {
    let mut mailbox = LocalMailbox::new();
    let mut now = 0;
    let mut alice = Device::new(1, &mut mailbox);
    let mut dana = Device::new(3, &mut mailbox);
    let mut eve = Device::new(5, &mut mailbox);
    let (group, step) = alice
        .client
        .start_group(now, &[eve.client.contact_card()], "Climbing")
        .expect("starts");
    alice.apply(&mut mailbox, now, step);
    let seed = [42; 32];
    let step = alice
        .client
        .set_policy(
            now,
            group,
            Policy {
                link: Some(seed),
                ..Policy::new(alice.client.identity())
            },
        )
        .expect("queues");
    alice.apply(&mut mailbox, now, step);
    settle(&mut [&mut alice, &mut eve], &mut mailbox, &mut now);
    let code = LinkKeys::from_seed(&seed, &group).code;
    let header = header(&mut mailbox, &code);
    let (request, step) = dana
        .client
        .join_request(now, &code, &header, "Dana")
        .expect("asks");
    dana.persist_only(step);
    mailbox.handle(now, &request).expect("answers");

    // Eve, who knows Dana's card, adds her to a group of her own.
    let (other, step) = eve
        .client
        .start_group(now, &[dana.client.contact_card()], "Climbing")
        .expect("starts");
    eve.apply(&mut mailbox, now, step);
    settle(&mut [&mut eve, &mut dana], &mut mailbox, &mut now);
    assert!(dana.events.iter().any(|e| matches!(
        e,
        Event::Joined { conversation, via_link: false, .. } if *conversation == other
    )));
    assert_eq!(
        dana.client.pending_joins(),
        vec!["Climbing".to_owned()],
        "still waiting"
    );
}
