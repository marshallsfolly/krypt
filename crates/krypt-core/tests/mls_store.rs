//! Every kind of value OpenMLS stores survives the store's binary encoding.
//!
//! Each step runs on a group loaded from a fresh store that holds only what
//! the steps before it persisted, so every value OpenMLS writes is read back
//! before it is used again: trees, secrets and transcript hashes, key
//! packages with their private keys, signature keys, queued proposals and
//! own leaf nodes. krypt itself never queues proposals (the mailbox refuses
//! them), but OpenMLS's types must all work, not only the ones it uses
//! today.

use std::collections::BTreeMap;

use krypt_core::client::CIPHERSUITE;
use krypt_core::mls_store::MlsStore;
use krypt_core::provider::{Provider, Rand};
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::{
    BasicCredential, Capabilities, CredentialWithKey, GroupId, KeyPackage, LeafNodeParameters,
    MlsGroup, MlsGroupCreateConfig, MlsGroupJoinConfig, MlsMessageBodyIn, MlsMessageIn,
    MlsMessageOut, ProcessedMessageContent, ProtocolMessage, StagedWelcome,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider as _;

type Disk = BTreeMap<Vec<u8>, Vec<u8>>;

const GROUP: &[u8] = b"every value round-trips";

/// Leaves must list krypt's ciphersuite, which is not a default one.
fn capabilities() -> Capabilities {
    Capabilities::builder()
        .ciphersuites(vec![CIPHERSUITE])
        .build()
}

/// A member whose state lives only on its disk between steps.
struct Member {
    disk: Disk,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
}

impl Member {
    fn new(name: &str) -> Member {
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).expect("a key");
        let credential = CredentialWithKey {
            credential: BasicCredential::new(name.as_bytes().to_vec()).into(),
            signature_key: signer.public().into(),
        };
        let mut member = Member {
            disk: Disk::new(),
            signer,
            credential,
        };
        member.step(|provider, signer| signer.store(provider.storage()).expect("stores"));
        member.step(|provider, signer| {
            let read = SignatureKeyPair::read(
                provider.storage(),
                signer.public(),
                signer.signature_scheme(),
            );
            assert_eq!(
                read.map(|k| k.public().to_vec()),
                Some(signer.public().to_vec())
            );
        });
        member
    }

    /// Runs `f` on a store rebuilt from the disk, then persists its writes.
    fn step<T>(&mut self, f: impl FnOnce(&Provider, &SignatureKeyPair) -> T) -> T {
        let provider = Provider::new(Rand::os(), MlsStore::from_entries(self.disk.clone()));
        let out = f(&provider, &self.signer);
        for (key, value) in provider.storage().take_changes() {
            match value {
                Some(value) => self.disk.insert(key, value),
                None => self.disk.remove(&key),
            };
        }
        out
    }

    /// Runs `f` on the group, loaded from the disk.
    fn group<T>(&mut self, f: impl FnOnce(&mut MlsGroup, &Provider, &SignatureKeyPair) -> T) -> T {
        self.step(|provider, signer| {
            let mut group = MlsGroup::load(provider.storage(), &GroupId::from_slice(GROUP))
                .expect("loads")
                .expect("exists");
            f(&mut group, provider, signer)
        })
    }
}

fn bytes(message: &MlsMessageOut) -> Vec<u8> {
    message.tls_serialize_detached().expect("serializes")
}

fn protocol(bytes: &[u8]) -> ProtocolMessage {
    MlsMessageIn::tls_deserialize_exact(bytes)
        .expect("parses")
        .try_into_protocol_message()
        .expect("a protocol message")
}

/// Processes a proposal and queues it.
fn queue(group: &mut MlsGroup, provider: &Provider, proposal: &[u8]) {
    let processed = group
        .process_message(provider, protocol(proposal))
        .expect("processes");
    let ProcessedMessageContent::ProposalMessage(queued) = processed.into_content() else {
        panic!("not a proposal");
    };
    group
        .store_pending_proposal(provider.storage(), *queued)
        .expect("queues");
}

fn merge(group: &mut MlsGroup, provider: &Provider, commit: &[u8]) {
    let processed = group
        .process_message(provider, protocol(commit))
        .expect("processes");
    let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
        panic!("not a commit");
    };
    group
        .merge_staged_commit(provider, *staged)
        .expect("merges");
}

/// One message, sealed by one member and opened by the other.
fn send(from: &mut Member, to: &mut Member) {
    let message = from.group(|group, provider, signer| {
        bytes(
            &group
                .create_message(provider, signer, b"hello")
                .expect("seals"),
        )
    });
    let plaintext = to.group(|group, provider, _| {
        let processed = group
            .process_message(provider, protocol(&message))
            .expect("opens");
        let ProcessedMessageContent::ApplicationMessage(app) = processed.into_content() else {
            panic!("not a message");
        };
        app.into_bytes()
    });
    assert_eq!(plaintext, b"hello");
}

fn authenticator(member: &mut Member) -> Vec<u8> {
    member.group(|group, _, _| group.epoch_authenticator().as_slice().to_vec())
}

#[test]
fn every_openmls_value_round_trips() {
    let mut alice = Member::new("alice");
    let mut bob = Member::new("bob");

    let credential = bob.credential.clone();
    let key_package = bob.step(|provider, signer| {
        let bundle = KeyPackage::builder()
            .leaf_node_capabilities(capabilities())
            .build(CIPHERSUITE, provider, signer, credential)
            .expect("builds");
        bundle.key_package().clone()
    });
    let credential = alice.credential.clone();
    alice.step(|provider, signer| {
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .capabilities(capabilities())
            .use_ratchet_tree_extension(true)
            .build();
        MlsGroup::new_with_group_id(
            provider,
            signer,
            &config,
            GroupId::from_slice(GROUP),
            credential,
        )
        .expect("creates");
    });
    let welcome = alice.group(|group, provider, signer| {
        let (_, welcome, _) = group
            .add_members(provider, signer, &[key_package])
            .expect("adds");
        group.merge_pending_commit(provider).expect("merges");
        bytes(&welcome)
    });
    bob.step(|provider, _| {
        let MlsMessageBodyIn::Welcome(welcome) = MlsMessageIn::tls_deserialize_exact(&welcome)
            .expect("parses")
            .extract()
        else {
            panic!("not a welcome");
        };
        let config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();
        StagedWelcome::new_from_welcome(provider, &config, welcome, None)
            .and_then(|staged| staged.into_group(provider))
            .expect("joins");
    });
    assert_eq!(authenticator(&mut alice), authenticator(&mut bob));

    // Bob proposes an update (an own leaf node, queued), Alice queues it,
    // and both see it pending after a restart.
    let proposal = bob.group(|group, provider, signer| {
        let (proposal, _) = group
            .propose_self_update(provider, signer, LeafNodeParameters::default())
            .expect("proposes");
        bytes(&proposal)
    });
    alice.group(|group, provider, _| queue(group, provider, &proposal));
    assert_eq!(
        alice.group(|group, _, _| group.pending_proposals().count()),
        1
    );
    assert_eq!(
        bob.group(|group, _, _| group.pending_proposals().count()),
        1
    );

    // Alice commits to it; Bob applies his own update from the commit.
    let commit = alice.group(|group, provider, signer| {
        let (commit, _, _) = group
            .commit_to_pending_proposals(provider, signer)
            .expect("commits");
        group.merge_pending_commit(provider).expect("merges");
        bytes(&commit)
    });
    bob.group(|group, provider, _| merge(group, provider, &commit));
    assert_eq!(authenticator(&mut alice), authenticator(&mut bob));
    assert_eq!(
        alice.group(|group, _, _| group.pending_proposals().count()),
        0
    );

    // A proposal removed from the queue stays removed.
    let (proposal, reference) = bob.group(|group, provider, signer| {
        let (proposal, reference) = group
            .propose_self_update(provider, signer, LeafNodeParameters::default())
            .expect("proposes");
        (bytes(&proposal), reference)
    });
    alice.group(|group, provider, _| queue(group, provider, &proposal));
    alice.group(|group, provider, _| {
        group
            .remove_pending_proposal(provider.storage(), &reference)
            .expect("removes");
    });
    assert_eq!(
        alice.group(|group, _, _| group.pending_proposals().count()),
        0
    );
    bob.group(|group, provider, _| {
        group
            .clear_pending_proposals(provider.storage())
            .expect("clears");
    });
    assert_eq!(
        bob.group(|group, _, _| group.pending_proposals().count()),
        0
    );

    // Messages both ways, each side restarted in between.
    send(&mut alice, &mut bob);
    send(&mut bob, &mut alice);

    // Everything OpenMLS wrote is binary, except the join config.
    for disk in [&alice.disk, &bob.disk] {
        for (key, value) in disk {
            let config = key.starts_with(b"MlsGroupJoinConfig");
            assert_eq!(value.first() == Some(&0x01), !config, "{:?}", key);
        }
    }
}
