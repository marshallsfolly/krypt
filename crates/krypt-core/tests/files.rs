//! Sharing a file end to end, with the mailbox in the loop: a member's parts
//! are authorized, sealed and stored (as R2 would), the message survives a
//! restart before it is sent, and the other member opens every part.

mod common;

use common::{Device, authorize, settle};
use krypt_core::client::{Content, Event, SharedFile};
use krypt_core::file;
use krypt_core::mailbox::LocalMailbox;
use krypt_wire::frame::Kind;
use krypt_wire::limits::FILE_PART_SIZE;
use krypt_wire::msg::Reject;

#[test]
fn a_member_shares_a_file_that_survives_a_restart() {
    let mut mailbox = LocalMailbox::new();
    let mut now = 0;
    let mut alice = Device::new(1, &mut mailbox);
    let mut bob = Device::new(2, &mut mailbox);

    let card = bob.client.contact_card();
    let (conversation, step) = alice.client.start_conversation(now, card).expect("starts");
    alice.apply(&mut mailbox, now, step);
    settle(&mut [&mut alice, &mut bob], &mut mailbox, &mut now);
    assert!(
        bob.events
            .iter()
            .any(|e| matches!(e, Event::Joined { conversation: c, .. } if *c == conversation)),
        "bob joined"
    );

    // Two full parts and a short one.
    let size = u64::from(FILE_PART_SIZE) * 2 + 1_000;
    #[allow(clippy::cast_possible_truncation)]
    let plaintext: Vec<u8> = (0..size).map(|i| (i % 253) as u8).collect();
    let (id, key) = alice.client.new_file();
    let mut stored = Vec::new();
    for part in 0..file::parts(size) {
        let start = part as usize * FILE_PART_SIZE as usize;
        let mut buffer = plaintext[start..start + file::plain_len(size, part) as usize].to_vec();
        file::seal(&key, size, part, &mut buffer);
        let len = u32::try_from(buffer.len()).expect("a part");
        let proof = alice
            .client
            .file_auth(conversation, id, part, len)
            .expect("a member");
        assert_eq!(
            authorize(
                &mut mailbox,
                Kind::AuthorizeFile,
                conversation,
                &proof.encode()
            ),
            Ok(())
        );
        stored.push(buffer);
    }

    // Someone who is not a member has no proof to offer, and a proof for one
    // conversation is worthless in another.
    let mut carol = Device::new(3, &mut mailbox);
    assert!(carol.client.file_auth(conversation, id, 0, 100).is_err());
    let proof = alice.client.file_auth(conversation, id, 0, 100).unwrap();
    assert_eq!(
        authorize(
            &mut mailbox,
            Kind::AuthorizeFile,
            [0xAA; 16],
            &proof.encode()
        ),
        Err(Reject::UnknownLog)
    );
    let card = carol.client.contact_card();
    let (other, step) = alice.client.start_conversation(now, card).unwrap();
    alice.apply(&mut mailbox, now, step);
    settle(&mut [&mut alice, &mut carol], &mut mailbox, &mut now);
    assert_eq!(
        authorize(&mut mailbox, Kind::AuthorizeFile, other, &proof.encode()),
        Err(Reject::Forbidden)
    );

    let shared = SharedFile {
        id,
        key,
        size,
        name: "holiday.mov".to_owned(),
        media_type: "video/quicktime".to_owned(),
        width: 1920,
        height: 1080,
        thumbnail: vec![0xFF, 0xD8, 0xFF, 0xD9],
    };
    // Alice crashes after queueing the message, before anything is sent.
    let (_, step) = alice
        .client
        .send_file(now, conversation, shared.clone())
        .expect("queues");
    alice.persist_only(step);
    alice.restart(&mut mailbox, 11, now);
    settle(&mut [&mut alice, &mut bob], &mut mailbox, &mut now);

    let received: Vec<&SharedFile> = bob
        .events
        .iter()
        .filter_map(|e| match e {
            Event::Message {
                content: Content::File(file),
                ..
            } => Some(&**file),
            _ => None,
        })
        .collect();
    assert_eq!(received, vec![&shared], "delivered exactly once, intact");

    let mut opened = Vec::new();
    for (part, bytes) in stored.into_iter().enumerate() {
        let mut buffer = bytes;
        let part = u32::try_from(part).unwrap();
        file::open(&received[0].key, received[0].size, part, &mut buffer).expect("opens");
        opened.extend_from_slice(&buffer);
    }
    assert_eq!(opened, plaintext);
}
