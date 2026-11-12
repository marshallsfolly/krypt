//! A device: the sans-IO client state machine.
//!
//! Every public method takes the current time and returns a [`Step`]: the
//! storage writes the call made, then the effects (frames to send and events
//! for the UI). The driver MUST persist `writes` atomically and durably before
//! performing any effect. A frame is therefore never sent that the device
//! could forget having sent, which for MLS would mean reusing a nonce after a
//! crash.
//!
//! Group state advances only in log order. Even this device's own commits are
//! merged when it reaches them in the conversation log, never when the
//! mailbox acknowledges them, so crash recovery and normal operation take the
//! same path.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};
use krypt_wire::codec::{DecodeError, Reader, Writer};
use krypt_wire::frame::{self, Kind, Route};
use krypt_wire::limits::{
    CALL_SDP_MAX, DISAPPEAR_MAX_S, FILE_NAME_MAX, FILE_TYPE_MAX, GROUP_NAME_MAX, RECEIPT_REFS_MAX,
    SIGNAL_SKEW_MS, THUMBNAIL_MAX,
};
use krypt_wire::limits::{
    CONVERSATIONS_MAX, DAY_MS, DEDUP_WINDOW, FETCH_ENTRIES_MAX, FRAME_BODY_MAX, GROUP_MEMBERS_MAX,
    INFLIGHT_MAX, KEY_PACKAGES_MAX, OUTBOX_MAX, PAST_EPOCHS_MAX, PUSH_ADDRESS_MAX, TEXT_MAX,
    WELCOMES_PER_SUBMIT_MAX,
};
use krypt_wire::msg::{
    Accepted, AppMessage, Body, CallEnd, CallKind, CallSignal, Entries, Fetch, FilePart, FileRef,
    InboxWelcome, KeyPackages, MLS_MESSAGE_MAX, MessageRef, Platform, PushTarget, ReadThrough,
    Reject, Rejected, Signal, SignalKind, Submit, TurnGrant, VoiceRef, Watch, WelcomeFor,
    reaction_valid,
};
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::{
    BasicCredential, Capabilities, Ciphersuite, ContentType, Credential, CredentialWithKey,
    Extension, ExtensionType, Extensions, GroupContext, GroupId, KeyPackage, KeyPackageIn,
    LeafNodeIndex, LeafNodeParameters, MlsGroup, MlsGroupCreateConfig, MlsGroupJoinConfig,
    MlsMessageBodyIn, MlsMessageIn, MlsMessageOut, PURE_CIPHERTEXT_WIRE_FORMAT_POLICY,
    ProcessedMessageContent, Proposal, ProtocolVersion, RequiredCapabilitiesExtension, Sender,
    SenderRatchetConfiguration, StagedCommit, StagedWelcome, UnknownExtension,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider as _;
use openmls_traits::signatures::Signer as _;
use openmls_traits::types::SignatureScheme;

use crate::hash16;
use crate::identity::{ContactCard, DeviceCert, DeviceId, Identity, IdentityKey};
use crate::join::{Header as JoinHeader, JoinCode, LinkKeys, Request as JoinBody};
use crate::link::{BACKUP_CONTACTS_MAX, Backup, DEVICES_MAX, LinkPayload};
use crate::mailbox::{
    WRITE_KEY_LABEL, creation_route, creation_signed_bytes, file_tag, signal_tag, turn_tag,
    watch_tag, write_tag,
};
use crate::mls_store::MlsStore;
use crate::provider::{Provider, Rand};

/// Hybrid post-quantum. HPKE uses X-Wing (X25519 + ML-KEM-768), so the keys
/// that carry group secrets (in welcomes and commit paths) hold up against a
/// quantum computer that records today's traffic and attacks it later; X25519
/// keeps today's guarantees if ML-KEM falls. Signatures stay Ed25519: forging
/// one takes a quantum computer at the time, not afterwards. Code point 0x004F
/// is provisional (draft-ietf-mls-pq-ciphersuites).
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519;

/// How far a sender's messages may arrive out of order (a retried submit
/// lands behind later ones) before older ones become undecryptable.
const OUT_OF_ORDER_TOLERANCE: u32 = 128;
const MAXIMUM_FORWARD_DISTANCE: u32 = 4096;
/// Most of one sender's messages sealed but not yet stored by the mailbox,
/// counted in sender_seq. A message can then be overtaken in the log by
/// fewer than this many of the same sender's later messages, which keeps every receiver within the ratchet's out-of-order
/// tolerance: without the window, one dropped submit followed by a burst of
/// queued messages makes the dropped one undecryptable for everyone.
const SUBMIT_WINDOW: u64 = 32;
const _: () = assert!(2 * SUBMIT_WINDOW <= OUT_OF_ORDER_TOLERANCE as u64);
/// Plaintexts are padded to a multiple of this, hiding exact lengths.
const PADDING: usize = 32;
/// Hashes of processed application messages remembered per conversation, so
/// the same ciphertext arriving again (by the other path) is skipped before
/// MLS, which would only refuse it.
const SEEN_MAX: usize = 4096;
#[allow(clippy::cast_possible_truncation)]
const MAX_PAST_EPOCHS: usize = PAST_EPOCHS_MAX as usize;

type Hash = [u8; 16];

#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub request_timeout_ms: u64,
    /// A safety net: the mailbox pushes new entries to connected devices, so
    /// polling only covers missed pushes.
    pub poll_interval_ms: u64,
    /// Key packages kept published at the mailbox.
    pub key_packages: usize,
    /// For tests only: build commits even when the group's rules forbid
    /// them, to play a member whose client misbehaves.
    pub break_rules: bool,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            request_timeout_ms: 2_000,
            poll_interval_ms: 15_000,
            key_packages: 8,
            break_rules: false,
        }
    }
}

/// The result of one call: persist `writes`, then perform `effects`.
#[derive(Debug, Default)]
pub struct Step {
    pub writes: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    pub effects: Vec<Effect>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    /// Send a request frame to the mailbox.
    Mailbox(Vec<u8>),
    Event(Event),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Started {
        conversation: Route,
    },
    Joined {
        conversation: Route,
        members: Vec<IdentityKey>,
        /// The MLS epoch this device's membership begins at.
        epoch: u64,
        /// It answers this device's request, sent with the group's link.
        via_link: bool,
        /// Who added this device (whose commit the welcome came from).
        added_by: IdentityKey,
    },
    /// Someone asks to join a group this device is an admin of, through
    /// its invite link. Checked: the request is signed by a device of the
    /// identity it names.
    JoinRequest {
        conversation: Route,
        id: Hash,
        identity: IdentityKey,
        name: String,
    },
    MembersAdded {
        conversation: Route,
        identities: Vec<IdentityKey>,
    },
    MembersRemoved {
        conversation: Route,
        identities: Vec<IdentityKey>,
        /// Who removed them; `None` when they left.
        by: Option<IdentityKey>,
    },
    /// This device was removed from the conversation.
    Removed {
        conversation: Route,
    },
    Message {
        conversation: Route,
        from: IdentityKey,
        device: DeviceId,
        sender_seq: u64,
        sent_at_ms: u64,
        /// Delete it this many seconds after showing it; zero keeps it.
        expires_after_s: u32,
        content: Content,
    },
    /// One of this device's messages was encrypted for these members.
    Sealed {
        conversation: Route,
        sender_seq: u64,
        recipients: Vec<IdentityKey>,
        /// The MLS epoch it was encrypted in.
        epoch: u64,
    },
    /// A member changed the conversation's disappearing-message timer.
    Timer {
        conversation: Route,
        by: IdentityKey,
        seconds: u32,
    },
    /// A member renamed the group (empty: it has no name now).
    Renamed {
        conversation: Route,
        by: IdentityKey,
        name: String,
    },
    /// One of this device's changes was not made: the group's rules do not
    /// allow it (only admins may), or a member's version cannot take it.
    Refused {
        conversation: Route,
        reason: String,
    },
    /// The group's admins or rules changed (by `by`'s commit): who became
    /// an admin and who stopped being one, and what changed of who may add
    /// people and rename the group.
    Rules {
        conversation: Route,
        by: IdentityKey,
        admins_added: Vec<IdentityKey>,
        admins_removed: Vec<IdentityKey>,
        add: Option<Who>,
        edit: Option<Who>,
        /// The invite link was turned on, reset or turned off.
        link: Option<LinkChange>,
    },
    /// This device's timer change could not be made: a member's version
    /// does not support it.
    TimerRefused {
        conversation: Route,
        reason: String,
    },
    /// The mailbox stored one of this device's messages.
    Sent {
        conversation: Route,
        sender_seq: u64,
    },
    /// An invitation could not be completed (the contact's key package was
    /// invalid or did not belong to them).
    InviteFailed {
        conversation: Route,
        identity: IdentityKey,
    },
    /// A message in the conversation could not be decrypted and was skipped.
    Undecryptable {
        conversation: Route,
        reason: String,
    },
    /// This device can no longer follow the conversation and must rejoin.
    Desync {
        conversation: Route,
        reason: String,
    },
    /// Another member's device, connected now, is typing, stopped, came
    /// online or went offline. Never stored; checked to come from that
    /// device.
    Signal {
        conversation: Route,
        from: IdentityKey,
        device: DeviceId,
        kind: SignalKind,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unknown conversation")]
    UnknownConversation,
    #[error("conversation is no longer active")]
    Inactive,
    #[error("text exceeds {TEXT_MAX} bytes")]
    TooLong,
    #[error("the file exceeds a limit (size, name, type or preview)")]
    FileTooLarge,
    #[error("the call signal or timer is out of bounds")]
    Invalid,
    #[error("too many unsent messages")]
    OutboxFull,
    #[error("too many conversations")]
    TooManyConversations,
    #[error("stored state is corrupt: {0}")]
    Corrupt(&'static str),
    #[error("mls: {0}")]
    Mls(String),
}

/// What an identity signs to claim a handle for a card.
pub fn handle_signed_bytes(handle: &str, card: &ContactCard, challenge: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.array(b"krypt handle v1")
        .bytes(handle.as_bytes())
        .bytes(&card.encode())
        .bytes(challenge);
    w.finish()
}

fn hex4(bytes: &[u8]) -> String {
    bytes.iter().take(4).map(|b| format!("{b:02x}")).collect()
}

fn mls_error(e: impl std::fmt::Debug) -> Error {
    Error::Mls(format!("{e:?}"))
}

/// A sliding window over one sender's sequence numbers: `max` is the
/// highest seen and bit `i` marks `max - i` as seen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Window {
    max: u64,
    bits: [u64; WINDOW_WORDS],
}

const WINDOW_WORDS: usize = (DEDUP_WINDOW / 64) as usize;

impl Window {
    fn new() -> Window {
        Window {
            max: 0,
            bits: [0; WINDOW_WORDS],
        }
    }

    /// Marks `seq` seen; returns false if it already was, or is too old to tell.
    fn insert(&mut self, seq: u64) -> bool {
        assert!(seq > 0);
        if seq > self.max {
            self.shift(seq - self.max);
            self.max = seq;
            self.bits[0] |= 1;
            return true;
        }
        let offset = self.max - seq;
        if offset >= DEDUP_WINDOW {
            return false;
        }
        let (word, bit) = ((offset / 64) as usize, offset % 64);
        let fresh = self.bits[word] & (1 << bit) == 0;
        self.bits[word] |= 1 << bit;
        fresh
    }

    fn shift(&mut self, by: u64) {
        if by >= DEXP {
            self.bits = [0; WINDOW_WORDS];
            return;
        }
        let (words, bits) = ((by / 64) as usize, by % 64);
        for i in (0..WINDOW_WORDS).rev() {
            let lo = i.checked_sub(words).map_or(0, |j| self.bits[j]);
            let lower = i.checked_sub(words + 1).map_or(0, |j| self.bits[j]);
            self.bits[i] = if bits == 0 {
                lo
            } else {
                (lo << bits) | (lower >> (64 - bits))
            };
        }
    }
}

const DEXP: u64 = DEDUP_WINDOW;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Intent {
    Add {
        contact: ContactCard,
        key_package: Option<Vec<u8>>,
    },
    Remove {
        identity: IdentityKey,
    },
    Update,
    /// Set the disappearing-message timer, in seconds.
    Timer(u32),
    /// Remove one device (by its inbox), not the whole identity.
    RemoveDevice {
        inbox: Route,
    },
    /// Name the group (empty: no name).
    Rename(String),
    /// Change the group's rules: its admins and who may do what.
    Policy(Policy),
    /// Stop being an admin, before leaving: worked out when the commit is
    /// made, from the rules as they are then (handing the role to the
    /// member at the lowest position, among those not leaving, if nobody
    /// else would have it).
    StepDown,
}

/// The group context extension holding a conversation's settings: the
/// disappearing-message timer (seconds, u32 little-endian) and, after it,
/// the group's name (a u8 length and UTF-8). Without a name it is the timer
/// alone, as before names existed. From the private-use range.
const TIMER_EXTENSION: u16 = 0xF0D1;

/// What every member of a group agrees on, beyond its membership.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Settings {
    timer: u32,
    name: String,
}

/// A group's settings. Malformed parts (only a misbehaving member could
/// commit them) read as off and unnamed.
fn group_settings(group: &MlsGroup) -> Settings {
    let Some(bytes) = group
        .extensions()
        .unknown(TIMER_EXTENSION)
        .map(|e| e.0.as_slice())
    else {
        return Settings::default();
    };
    let timer = bytes
        .get(..4)
        .map(|t| u32::from_le_bytes(t.try_into().expect("4 bytes")))
        .filter(|seconds| *seconds <= DISAPPEAR_MAX_S)
        .unwrap_or(0);
    let name = bytes
        .get(4)
        .and_then(|len| bytes.get(5..5 + usize::from(*len)))
        .filter(|name| name.len() <= GROUP_NAME_MAX && bytes.len() == 5 + name.len())
        .and_then(|name| std::str::from_utf8(name).ok())
        .unwrap_or_default()
        .to_owned();
    Settings { timer, name }
}

fn group_timer(group: &MlsGroup) -> u32 {
    group_settings(group).timer
}

/// The group context every conversation has: members must support the
/// settings extension (and the rules extension, once the group has rules),
/// the settings themselves, and the rules. Every change to any of them
/// builds the whole context here, so none drops another.
fn group_context(settings: &Settings, policy: Option<&Policy>) -> Extensions<GroupContext> {
    assert!(settings.name.len() <= GROUP_NAME_MAX);
    let mut required = vec![ExtensionType::Unknown(TIMER_EXTENSION)];
    if policy.is_some() {
        required.push(ExtensionType::Unknown(POLICY_EXTENSION));
    }
    let mut value = settings.timer.to_le_bytes().to_vec();
    if !settings.name.is_empty() {
        value.push(u8::try_from(settings.name.len()).expect("GROUP_NAME_MAX fits a byte"));
        value.extend_from_slice(settings.name.as_bytes());
    }
    let mut extensions = vec![
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(&required, &[], &[])),
        Extension::Unknown(TIMER_EXTENSION, UnknownExtension(value)),
    ];
    if let Some(policy) = policy {
        extensions.push(Extension::Unknown(
            POLICY_EXTENSION,
            UnknownExtension(policy.encode()),
        ));
    }
    Extensions::from_vec(extensions).expect("valid group context extensions")
}

/// The group context extension holding a group's rules (decision 51): who
/// its admins are, who may add people, and who may change its name and
/// timer. Groups from before admins have none: everyone may do everything.
const POLICY_EXTENSION: u16 = 0xF0D2;
const POLICY_VERSION: u8 = 1;
/// Largest encoded policy: every member an admin, and a link.
const POLICY_BYTES_MAX: usize = 3 + 4 + 32 * GROUP_MEMBERS_MAX + 1 + 32;
/// How a desync for a rule-breaking commit begins (the app shows it).
pub const RULES_BROKEN: &str = "rules: ";

/// What a commit may change that `after_commit` reports.
struct Before {
    members: Vec<IdentityKey>,
    settings: Settings,
    admins: Vec<IdentityKey>,
    policy: Option<Policy>,
}

/// How a group's invite link changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkChange {
    On,
    Reset,
    Off,
}

/// Who may do something in a group.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Who {
    Everyone,
    Admins,
}

/// A group's rules. Admins are identities, sorted; one who leaves the group
/// stops counting.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Policy {
    pub admins: Vec<IdentityKey>,
    pub add: Who,
    pub edit: Who,
    /// The invite link's secret, when the group has one (decision 52).
    pub link: Option<[u8; 32]>,
}

impl Policy {
    /// A new group's rules: its creator is the admin; everyone may add
    /// people and rename it, as before admins existed.
    pub fn new(creator: IdentityKey) -> Policy {
        Policy {
            admins: vec![creator],
            add: Who::Everyone,
            edit: Who::Everyone,
            link: None,
        }
    }

    fn encode(&self) -> Vec<u8> {
        let who = |w: Who| u8::from(w == Who::Admins);
        let mut admins = self.admins.clone();
        admins.sort_unstable();
        admins.dedup();
        let mut w = Writer::new();
        w.u8(POLICY_VERSION)
            .u8(who(self.add))
            .u8(who(self.edit))
            .count(admins.len());
        for admin in &admins {
            w.array(admin);
        }
        match &self.link {
            None => w.u8(0),
            Some(seed) => w.u8(1).array(seed),
        };
        w.finish()
    }

    /// Strict: one encoding per policy (admins sorted, no repeats).
    fn decode(bytes: &[u8]) -> Result<Policy, DecodeError> {
        let mut r = Reader::new(bytes);
        if r.u8()? != POLICY_VERSION {
            return Err(DecodeError::BadValue);
        }
        let who = |byte: u8| match byte {
            0 => Ok(Who::Everyone),
            1 => Ok(Who::Admins),
            _ => Err(DecodeError::BadValue),
        };
        let add = who(r.u8()?)?;
        let edit = who(r.u8()?)?;
        let n = r.count(GROUP_MEMBERS_MAX)?;
        let mut admins: Vec<IdentityKey> = Vec::with_capacity(n);
        for _ in 0..n {
            let admin: IdentityKey = r.array()?;
            if admins.last().is_some_and(|last| *last >= admin) {
                return Err(DecodeError::BadValue);
            }
            admins.push(admin);
        }
        let link = match r.u8()? {
            0 => None,
            1 => Some(r.array()?),
            _ => return Err(DecodeError::BadValue),
        };
        r.finish()?;
        Ok(Policy {
            admins,
            add,
            edit,
            link,
        })
    }
}

/// A group's rules: none for a group from before admins, an error for
/// damaged ones (which no honest member commits).
fn group_policy(group: &MlsGroup) -> Result<Option<Policy>, DecodeError> {
    policy_in(group.extensions())
}

fn policy_in(extensions: &Extensions<GroupContext>) -> Result<Option<Policy>, DecodeError> {
    extensions
        .unknown(POLICY_EXTENSION)
        .map(|e| Policy::decode(&e.0))
        .transpose()
}

/// The device ids of a group's members.
fn member_devices(group: &MlsGroup) -> BTreeSet<DeviceId> {
    group
        .members()
        .filter_map(|member| tree_cert(&member.credential))
        .map(|cert| cert.device)
        .collect()
}

/// The group's members' identities, each once, in leaf order.
fn member_identities(group: &MlsGroup) -> Vec<IdentityKey> {
    let mut seen = Vec::new();
    for member in group.members() {
        if let Some(cert) = tree_cert(&member.credential)
            && !seen.contains(&cert.identity)
        {
            seen.push(cert.identity);
        }
    }
    seen
}

/// Who the admins are now: the rules' admins who are members; if none is,
/// the member at the lowest leaf (so a group never lacks one, and every
/// member agrees who). Without rules, everyone.
fn effective_admins(group: &MlsGroup) -> Vec<IdentityKey> {
    let members = member_identities(group);
    match group_policy(group) {
        Ok(Some(policy)) => {
            let admins: Vec<_> = members
                .iter()
                .filter(|m| policy.admins.contains(m))
                .copied()
                .collect();
            if admins.is_empty() {
                members.first().copied().into_iter().collect()
            } else {
                admins
            }
        }
        Ok(None) => members,
        Err(_) => Vec::new(),
    }
}

/// Whether a commit by the member at `committer` keeps the group's rules
/// as they were before it (and krypt's own invariants), or why not. The
/// mailbox cannot see who committed, so every member checks for itself; a
/// commit that fails stops the group for every honest member.
fn check_commit(
    group: &MlsGroup,
    staged: &StagedCommit,
    committer: LeafNodeIndex,
) -> Result<(), &'static str> {
    let member = group
        .member_at(committer)
        .ok_or("a commit from someone not in the group")?;
    let identity = tree_cert(&member.credential)
        .ok_or("a commit from a member without a certificate")?
        .identity;
    let policy = group_policy(group).map_err(|_| "the group's rules are damaged")?;
    let admin = effective_admins(group).contains(&identity);
    for queued in staged.queued_proposals() {
        if !matches!(
            queued.proposal(),
            Proposal::Add(_) | Proposal::Remove(_) | Proposal::GroupContextExtensions(_)
        ) {
            return Err("a kind of change krypt never makes");
        }
    }
    // A member's leaf keeps its certificate and key: nobody becomes
    // someone else by updating.
    if let Some(leaf) = staged.update_path_leaf_node()
        && (leaf.credential() != &member.credential
            || leaf.signature_key().as_slice() != member.signature_key.as_slice())
    {
        return Err("a member's certificate changed");
    }
    // Device ids are unique in the group: messages and replies name a
    // message by its device.
    let mut devices: BTreeSet<DeviceId> = group
        .members()
        .filter_map(|m| tree_cert(&m.credential).map(|c| c.device))
        .collect();
    for add in staged.add_proposals() {
        let leaf = add.add_proposal().key_package().leaf_node();
        let cert = tree_cert(leaf.credential()).ok_or("an added member has no certificate")?;
        if !devices.insert(cert.device) {
            return Err("two devices in the group share an id");
        }
        let sibling = cert.identity == identity;
        if policy.as_ref().is_some_and(|p| p.add == Who::Admins) && !admin && !sibling {
            return Err("only admins may add people to this group");
        }
    }
    let old = group.extensions();
    let new = staged.group_context().extensions();
    for extension in new.iter() {
        if !matches!(
            extension.extension_type(),
            ExtensionType::RequiredCapabilities
                | ExtensionType::Unknown(TIMER_EXTENSION | POLICY_EXTENSION)
        ) {
            return Err("an extension krypt never sets");
        }
    }
    let required = |e: &Extensions<GroupContext>| {
        e.required_capabilities()
            .map(|r| r.extension_types().to_vec())
            .unwrap_or_default()
    };
    let old_policy = old.unknown(POLICY_EXTENSION).map(|e| e.0.clone());
    let new_policy = new.unknown(POLICY_EXTENSION).map(|e| e.0.clone());
    if required(old) != required(new) {
        // Only the commit that gives a group from before admins its first
        // rules may add the rules extension to what members must support.
        let first = old_policy.is_none()
            && new_policy.is_some()
            && required(old) == [ExtensionType::Unknown(TIMER_EXTENSION)]
            && required(new)
                == [
                    ExtensionType::Unknown(TIMER_EXTENSION),
                    ExtensionType::Unknown(POLICY_EXTENSION),
                ];
        if !first {
            return Err("what members must support changed");
        }
    }
    let settings = |e: &Extensions<GroupContext>| e.unknown(TIMER_EXTENSION).map(|e| e.0.clone());
    if settings(old) != settings(new)
        && policy.as_ref().is_some_and(|p| p.edit == Who::Admins)
        && !admin
    {
        return Err("only admins may change this group's name or timer");
    }
    if old_policy != new_policy {
        let next = new_policy
            .as_deref()
            .map(Policy::decode)
            .ok_or("the group's rules were removed")?
            .map_err(|_| "the group's rules were damaged")?;
        match policy {
            // A group's first rules make every member an admin, so nobody
            // takes over a group from before admins alone.
            None => {
                if !member_identities(group)
                    .iter()
                    .all(|m| next.admins.contains(m))
                {
                    return Err("a group's first rules must make every member an admin");
                }
            }
            Some(_) if !admin => return Err("only admins may change this group's rules"),
            Some(_) => {}
        }
    }
    // Nobody takes a group over by removing whoever runs it: only an admin
    // removes an admin (anyone may remove their own devices), and no commit
    // leaves a group that had an admin without one. (An admin who leaves
    // hands the role on first.)
    if let Some(rules) = &policy {
        let admins = effective_admins(group);
        let mut removed = BTreeSet::new();
        for remove in staged.remove_proposals() {
            let leaf = remove.remove_proposal().removed();
            let target = group
                .member_at(leaf)
                .and_then(|m| tree_cert(&m.credential))
                .ok_or("a removal of someone not in the group")?;
            if admins.contains(&target.identity) && target.identity != identity && !admin {
                return Err("only admins may remove an admin");
            }
            removed.insert(leaf);
        }
        let after = match &new_policy {
            Some(bytes) => Policy::decode(bytes).map_err(|_| "the group's rules were damaged")?,
            None => return Err("the group's rules were removed"),
        };
        let mut left: BTreeSet<IdentityKey> = group
            .members()
            .filter(|m| !removed.contains(&m.index))
            .filter_map(|m| tree_cert(&m.credential))
            .map(|cert| cert.identity)
            .collect();
        for add in staged.add_proposals() {
            if let Some(cert) = tree_cert(add.add_proposal().key_package().leaf_node().credential())
            {
                left.insert(cert.identity);
            }
        }
        let members = member_identities(group);
        let had_admin = rules.admins.iter().any(|a| members.contains(a));
        if had_admin && !left.is_empty() && !after.admins.iter().any(|a| left.contains(a)) {
            return Err("a group must keep an admin");
        }
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct Pending {
    message: Vec<u8>,
    welcomes: Vec<(Route, Vec<u8>)>,
    hash: Hash,
    /// Proof of membership for the mailbox, and the write key of the epoch
    /// this commit starts.
    auth: [u8; 16],
    next_key: [u8; 32],
    /// The creation key and its signature, for the commit that creates the log.
    creation: Option<([u8; 32], [u8; 64])>,
}

#[derive(Clone, Debug)]
struct Outgoing {
    sender_seq: u64,
    sent_at_ms: u64,
    expires_after_s: u32,
    content: Content,
    sealed: Option<Sealed>,
}

/// What a message carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Content {
    Text(String),
    File(Box<SharedFile>),
    Call(Box<Call>),
    /// The sender's identity left the group.
    Leave,
    /// A chat message answering another.
    Reply {
        to: MessageRef,
        text: String,
    },
    /// A reaction to a message, replacing the sender's earlier one; empty
    /// takes it back.
    React {
        to: MessageRef,
        emoji: String,
    },
    /// New text for one of the sender's own messages.
    Edit {
        to: MessageRef,
        text: String,
    },
    /// One of the sender's own messages, deleted for everyone.
    Delete {
        to: MessageRef,
    },
    /// Read watermarks: the newest message read from each sender device.
    Receipt(Vec<MessageRef>),
    Voice(Box<SharedVoice>),
}

/// A voice message: an audio file, its length and its waveform.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedVoice {
    pub file: SharedFile,
    pub duration_ms: u32,
    pub waveform: Vec<u8>,
}

impl SharedVoice {
    fn voice_ref(&self) -> VoiceRef<'_> {
        VoiceRef {
            file: self.file.file_ref(),
            duration_ms: self.duration_ms,
            waveform: &self.waveform,
        }
    }
}

impl From<VoiceRef<'_>> for SharedVoice {
    fn from(voice: VoiceRef<'_>) -> SharedVoice {
        SharedVoice {
            file: voice.file.into(),
            duration_ms: voice.duration_ms,
            waveform: voice.waveform.to_vec(),
        }
    }
}

impl Content {
    /// Runs `f` on the wire body for this content.
    fn with_body<T>(&self, f: impl FnOnce(Body<'_>) -> T) -> T {
        let receipts;
        let body = match self {
            Content::Text(text) => Body::Text(text),
            Content::File(file) => Body::File(file.file_ref()),
            Content::Call(call) => Body::Call(call.signal()),
            Content::Leave => Body::Leave,
            Content::Reply { to, text } => Body::Reply { to: *to, text },
            Content::React { to, emoji } => Body::React { to: *to, emoji },
            Content::Edit { to, text } => Body::Edit { to: *to, text },
            Content::Delete { to } => Body::Delete { to: *to },
            Content::Receipt(refs) => {
                receipts = ReadThrough::encode(refs);
                Body::Receipt(ReadThrough::parse(&receipts).expect("valid watermarks"))
            }
            Content::Voice(voice) => Body::Voice(voice.voice_ref()),
        };
        f(body)
    }

    fn from_body(body: Body<'_>) -> Content {
        match body {
            Body::Text(text) => Content::Text(text.to_owned()),
            Body::File(file) => Content::File(Box::new(file.into())),
            Body::Call(signal) => Content::Call(Box::new(signal.into())),
            Body::Leave => Content::Leave,
            Body::Reply { to, text } => Content::Reply {
                to,
                text: text.to_owned(),
            },
            Body::React { to, emoji } => Content::React {
                to,
                emoji: emoji.to_owned(),
            },
            Body::Edit { to, text } => Content::Edit {
                to,
                text: text.to_owned(),
            },
            Body::Delete { to } => Content::Delete { to },
            Body::Receipt(refs) => Content::Receipt(refs.iter().collect()),
            Body::Voice(voice) => Content::Voice(Box::new(voice.into())),
        }
    }

    /// Whether every field is within its limit (what encoding asserts).
    fn valid(&self) -> bool {
        match self {
            Content::Text(text) => text.len() <= TEXT_MAX,
            Content::File(file) => file.file_ref().valid(),
            Content::Call(call) => call.signal().valid(),
            Content::Leave | Content::Delete { .. } => true,
            Content::Reply { text, .. } | Content::Edit { text, .. } => {
                !text.is_empty() && text.len() <= TEXT_MAX
            }
            Content::React { emoji, .. } => reaction_valid(emoji),
            Content::Receipt(refs) => {
                (1..=RECEIPT_REFS_MAX).contains(&refs.len())
                    && refs.iter().all(|r| r.seq > 0)
                    && refs
                        .iter()
                        .enumerate()
                        .all(|(i, r)| refs[..i].iter().all(|o| o.device != r.device))
            }
            Content::Voice(voice) => voice.voice_ref().valid(),
        }
    }

    /// Whether it should wake devices that are asleep (see [`Body::wakes`]).
    fn wakes(&self) -> bool {
        self.with_body(|body| body.wakes())
    }

    /// Whether it takes the conversation's disappearing timer: what people
    /// say does; what only refers to it (a reaction, a receipt) does not.
    fn disappears(&self) -> bool {
        matches!(
            self,
            Content::Text(_) | Content::File(_) | Content::Reply { .. } | Content::Voice(_)
        )
    }
}

/// A call signal (see [`CallSignal`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Call {
    pub call: [u8; 16],
    /// The device it is for, or all zeros for every other member's devices.
    pub to: DeviceId,
    pub kind: CallKind,
    pub video: bool,
    pub sdp: String,
}

impl Call {
    fn signal(&self) -> CallSignal<'_> {
        CallSignal {
            call: self.call,
            to: self.to,
            kind: self.kind,
            video: self.video,
            sdp: &self.sdp,
        }
    }
}

impl From<CallSignal<'_>> for Call {
    fn from(signal: CallSignal<'_>) -> Call {
        Call {
            call: signal.call,
            to: signal.to,
            kind: signal.kind,
            video: signal.video,
            sdp: signal.sdp.to_owned(),
        }
    }
}

/// A file shared in a conversation: where its encrypted parts are stored
/// (under the conversation's route and `id`) and the key that opens them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedFile {
    pub id: [u8; 16],
    pub key: [u8; 32],
    pub size: u64,
    pub name: String,
    pub media_type: String,
    pub width: u32,
    pub height: u32,
    pub thumbnail: Vec<u8>,
}

impl SharedFile {
    fn file_ref(&self) -> FileRef<'_> {
        FileRef {
            id: self.id,
            key: self.key,
            size: self.size,
            name: &self.name,
            media_type: &self.media_type,
            width: self.width,
            height: self.height,
            thumbnail: &self.thumbnail,
        }
    }
}

impl From<FileRef<'_>> for SharedFile {
    fn from(file: FileRef<'_>) -> SharedFile {
        SharedFile {
            id: file.id,
            key: file.key,
            size: file.size,
            name: file.name.to_owned(),
            media_type: file.media_type.to_owned(),
            width: file.width,
            height: file.height,
            thumbnail: file.thumbnail.to_vec(),
        }
    }
}

#[derive(Clone, Debug)]
struct Sealed {
    message: Vec<u8>,
    hash: Hash,
    auth: [u8; 16],
}

#[derive(Debug)]
struct Conversation {
    group: MlsGroup,
    active: bool,
    /// Seq of the last log entry processed.
    cursor: u64,
    /// The last fetch reached the log's tip.
    caught_up: bool,
    next_sender_seq: u64,
    outbox: VecDeque<Outgoing>,
    pending: Option<Pending>,
    intents: VecDeque<Intent>,
    windows: BTreeMap<DeviceId, Window>,
    seen: VecDeque<Hash>,
    seen_set: BTreeSet<Hash>,
    /// For a conversation this device created, until its log exists: the
    /// seed of the key its route was derived from, which signs the first
    /// commit.
    creation_seed: Option<[u8; 32]>,
    /// The write key of the epoch it was exported for (not persisted).
    write_key: Option<(u64, [u8; 32])>,
    /// The signal key, likewise.
    signal_key: Option<(u64, [u8; 32])>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Request {
    FetchInbox,
    Fetch(Route),
    Submit {
        conversation: Route,
        hash: Hash,
    },
    Claim {
        conversation: Route,
        inbox: Route,
    },
    Publish {
        count: usize,
        last_resort: bool,
    },
    Watch {
        route: Route,
        target: (Platform, Vec<u8>),
        enable: bool,
    },
    /// Open (or keep open) a requests log, with the group's current name.
    OpenRequests(Route),
    FetchRequests(Route),
}

/// How often a device renews its push registration with each log, and how
/// often it replaces its published key packages (before they expire).
const WATCH_REFRESH_MS: u64 = 7 * DAY_MS;
const WATCH_RETRY_MS: u64 = 30_000;
const KEY_PACKAGE_REFRESH_MS: u64 = 14 * DAY_MS;

#[derive(Debug)]
struct Inflight {
    request: Request,
    frame: Vec<u8>,
    deadline_ms: u64,
    attempts: u32,
}

#[derive(Debug)]
pub struct Client {
    config: Config,
    provider: Provider,
    identity: Identity,
    mls_seed: [u8; 32],
    signer: SignatureKeyPair,
    cert: DeviceCert,
    inbox_cursor: u64,
    key_packages_owed: usize,
    last_resort_owed: bool,
    /// Where to wake this device when it is not connected.
    push_target: Option<(Platform, Vec<u8>)>,
    /// When each log's push registration is next due for renewal. Persisted
    /// (one record per log), so restarting the app re-registers nothing.
    watched: BTreeMap<Route, u64>,
    /// Registrations in flight, and when to retry them.
    watch_retry: BTreeMap<Route, u64>,
    dirty_watched: BTreeSet<Route>,
    /// Conversations that wake nobody until a time (ms; [`MUTED_FOREVER`]:
    /// until unmuted): their wakeups are withdrawn from the mailbox.
    muted: BTreeMap<Route, u64>,
    dirty_muted: BTreeSet<Route>,
    /// Requests logs this device reads, as an admin of a group with an
    /// invite link, by route (not persisted: rebuilt from the groups).
    requests: BTreeMap<Route, RequestsLog>,
    /// Requests read from them, until approved (not persisted: read again).
    join_requests: BTreeMap<(Route, Hash), JoinBody>,
    /// Requests this device sent with an invite link, waiting for an admin,
    /// by the link's `join`.
    pending_joins: BTreeMap<[u8; 16], PendingJoin>,
    dirty_joins: BTreeSet<[u8; 16]>,
    key_packages_refreshed_ms: u64,
    conversations: BTreeMap<Route, Conversation>,
    /// Identities whose invitations and messages this device drops.
    blocked: BTreeSet<IdentityKey>,
    /// Conversations this device forgot, with the next sender_seq it would
    /// have used: if it is invited back, its numbering carries on, so other
    /// members' duplicate windows accept its messages.
    tombstones: BTreeMap<Route, u64>,
    /// This identity's other devices, by inbox. Each device adds the others
    /// to every conversation it is in, so they all see the same chats.
    siblings: BTreeMap<Route, ContactCard>,
    /// Inboxes of this identity's devices that were unlinked: never added
    /// back, whichever device notices them missing.
    unlinked: BTreeSet<Route>,
    dirty_unlinked: BTreeSet<Route>,
    /// Members who said they are leaving, until their removal lands (to
    /// tell "left" from "removed"; not persisted).
    leavers: BTreeSet<(Route, IdentityKey)>,
    /// When to try adding a sibling to a conversation again (not persisted).
    sibling_retry: BTreeMap<(Route, Route), u64>,
    inflight: BTreeMap<u64, Inflight>,
    next_request: u64,
    last_poll_ms: Option<u64>,
    // Per-step scratch.
    effects: Vec<Effect>,
    /// The newest signal seen from each member's device (by leaf), so an old
    /// one replayed says nothing. Not persisted: after a restart the clock
    /// window does the same.
    last_signal: BTreeMap<(Route, u32), u64>,
    dirty_self: bool,
    dirty_conversations: BTreeSet<Route>,
    dirty_outbox: BTreeSet<(Route, u64)>,
    dirty_blocked: BTreeSet<IdentityKey>,
    dirty_tombstones: BTreeSet<Route>,
    dirty_siblings: BTreeSet<Route>,
}

// Storage keys. Application keys start with a zero byte so they can never
// collide with OpenMLS's labels, which are ASCII words.
const KEY_SELF: &[u8] = &[0, b'S'];
const PREFIX_CONVERSATION: &[u8] = &[0, b'C'];
const PREFIX_OUTBOX: &[u8] = &[0, b'O'];
const PREFIX_WATCH: &[u8] = &[0, b'W'];
const PREFIX_BLOCKED: &[u8] = &[0, b'B'];
const PREFIX_TOMBSTONE: &[u8] = &[0, b'T'];
const PREFIX_SIBLING: &[u8] = &[0, b'D'];
const PREFIX_MUTED: &[u8] = &[0, b'M'];
const PREFIX_JOIN: &[u8] = &[0, b'J'];
const PREFIX_UNLINKED: &[u8] = &[0, b'U'];
/// Per requests log: how far this device has read it (seq, little-endian).
const PREFIX_REQUESTS_READ: &[u8] = &[0, b'Q'];
/// Conversations nobody on this device ever answered (message requests,
/// mostly) past which invitations from strangers are dropped.
const UNANSWERED_MAX: usize = 1024;
/// Unlinked inboxes remembered (devices this identity has had, at most).
const UNLINKED_MAX: usize = 256;
/// How long a request sent with an invite link is waited for.
const PENDING_JOIN_MS: u64 = 30 * DAY_MS;

/// A requests log this device reads, as an admin of a group with a link.
#[derive(Debug)]
struct RequestsLog {
    conversation: Route,
    keys: LinkKeys,
    cursor: u64,
    /// The group name its header was last opened with.
    opened: Option<String>,
}

/// A request this device sent with an invite link: the one-time key
/// package's leaf key (to know the group when it comes) and the group's name.
#[derive(Clone, Debug, PartialEq, Eq)]
struct PendingJoin {
    encryption_key: Vec<u8>,
    name: String,
    at_ms: u64,
    /// The one-time key package's reference (TLS), deleted with the request
    /// when it lapses, so an old request can never add this device later.
    key_package_ref: Vec<u8>,
}

fn encode_pending_join(p: &PendingJoin) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(RECORD_VERSION)
        .u64(p.at_ms)
        .bytes(p.name.as_bytes())
        .bytes(&p.encryption_key)
        .bytes(&p.key_package_ref);
    w.finish()
}

fn decode_pending_join(bytes: &[u8]) -> Result<PendingJoin, DecodeError> {
    let mut r = Reader::new(bytes);
    record_version(&mut r)?;
    let pending = PendingJoin {
        at_ms: stored(&mut r)?,
        name: String::from_utf8(r.bytes(GROUP_NAME_MAX)?.to_vec())
            .map_err(|_| DecodeError::BadValue)?,
        encryption_key: r.bytes(KEY_PACKAGE_KEY_MAX)?.to_vec(),
        // Records written before it was kept have none.
        key_package_ref: if r.remaining() > 0 {
            r.bytes(KEY_PACKAGE_KEY_MAX)?.to_vec()
        } else {
            Vec::new()
        },
    };
    r.finish()?;
    Ok(pending)
}

/// Largest leaf encryption key (X-Wing's public key).
const KEY_PACKAGE_KEY_MAX: usize = 2048;

/// How long before adding a sibling device to a conversation is tried again
/// (its key packages may have run out, or the commit lost a race).
const SIBLING_RETRY_MS: u64 = 60_000;

/// Most identities one device blocks.
const BLOCKED_MAX: usize = 4096;

fn watch_key(route: &Route) -> Vec<u8> {
    [PREFIX_WATCH, route].concat()
}

fn conversation_key(id: &Route) -> Vec<u8> {
    [PREFIX_CONVERSATION, id].concat()
}

fn outbox_key(id: &Route, sender_seq: u64) -> Vec<u8> {
    [PREFIX_OUTBOX, id, &sender_seq.to_be_bytes()].concat()
}

/// What every leaf supports: krypt's one ciphersuite, and last-resort key
/// packages (a leaf must declare every extension its key package carries).
fn capabilities() -> Capabilities {
    Capabilities::builder()
        .ciphersuites(vec![CIPHERSUITE])
        .extensions(vec![
            ExtensionType::LastResort,
            ExtensionType::Unknown(TIMER_EXTENSION),
            ExtensionType::Unknown(POLICY_EXTENSION),
        ])
        .build()
}

/// Whether a leaf with these capabilities can join a conversation this
/// version makes (which requires extensions only). Key packages published
/// before an update that conversations now need cannot, so the mailbox stops
/// handing them out.
pub(crate) fn joins_new_conversations(capabilities: &Capabilities) -> bool {
    let context = group_context(&Settings::default(), Some(&Policy::new([0; 32])));
    context.required_capabilities().is_none_or(|required| {
        required
            .extension_types()
            .iter()
            .all(|t| capabilities.extensions().contains(t))
    })
}

fn create_config(name: &str, creator: IdentityKey) -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .capabilities(capabilities())
        .with_group_context_extensions(group_context(
            &Settings {
                timer: 0,
                name: name.to_owned(),
            },
            Some(&Policy::new(creator)),
        ))
        .use_ratchet_tree_extension(true)
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(MAX_PAST_EPOCHS)
        .padding_size(PADDING)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(
            OUT_OF_ORDER_TOLERANCE,
            MAXIMUM_FORWARD_DISTANCE,
        ))
        .build()
}

fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(MAX_PAST_EPOCHS)
        .padding_size(PADDING)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(
            OUT_OF_ORDER_TOLERANCE,
            MAXIMUM_FORWARD_DISTANCE,
        ))
        .build()
}

/// The current epoch's write key: what proves to the mailbox that this
/// device may write to the conversation.
/// Label for the per-epoch key that seals signals (typing, online). Unlike
/// the write key, the mailbox never has it.
const SIGNAL_KEY_LABEL: &str = "krypt signal v1";

/// What a device signs in a signal: everything that says who, where, when
/// and what.
fn signal_signed_bytes(
    route: &Route,
    epoch: u64,
    leaf: u32,
    kind: SignalKind,
    sent_at_ms: u64,
) -> Vec<u8> {
    let mut w = Writer::new();
    w.array(b"krypt signal v1")
        .array(route)
        .u64(epoch)
        .u32(leaf)
        .u8(kind as u8)
        .u64(sent_at_ms);
    w.finish()
}

/// Whether `signature` over `signed` is by the holder of `key` (a member's
/// Ed25519 MLS signature key).
fn signed_by(key: &[u8], signed: &[u8], signature: &[u8; 64]) -> bool {
    <[u8; 32]>::try_from(key)
        .ok()
        .and_then(|key| ed25519_dalek::VerifyingKey::from_bytes(&key).ok())
        .is_some_and(|key| {
            key.verify_strict(signed, &ed25519_dalek::Signature::from_bytes(signature))
                .is_ok()
        })
}

/// Binds a sealed signal to its conversation and epoch.
fn signal_aad(route: &Route, epoch: u64) -> Vec<u8> {
    let mut w = Writer::new();
    w.array(route).u64(epoch);
    w.finish()
}

fn write_key(group: &MlsGroup, provider: &Provider, route: &Route) -> [u8; 32] {
    group
        .export_secret(provider.crypto(), WRITE_KEY_LABEL, route, 32)
        .expect("exporting from an active group")
        .try_into()
        .expect("32 bytes")
}

fn serialize(message: &MlsMessageOut) -> Vec<u8> {
    message
        .tls_serialize_detached()
        .expect("serializing an MLS message cannot fail")
}

/// The certificate inside a credential already in a group's tree. Every such
/// credential was verified when it entered the tree, so it is only parsed.
/// Whether a commit and its welcomes can travel in one submit.
fn fits_in_frame(message: &[u8], welcomes: &[(Route, Vec<u8>)]) -> bool {
    message.len() <= MLS_MESSAGE_MAX
        && welcomes.iter().all(|(_, w)| w.len() <= MLS_MESSAGE_MAX)
        && Submit::size_max(message.len(), welcomes.iter().map(|(_, w)| w.len()))
            <= FRAME_BODY_MAX as usize
}

fn tree_cert(credential: &Credential) -> Option<DeviceCert> {
    let basic = BasicCredential::try_from(credential.clone()).ok()?;
    decode_cert_unverified(basic.identity())
}

fn decode_cert_unverified(bytes: &[u8]) -> Option<DeviceCert> {
    let mut r = Reader::new(bytes);
    if r.u8().ok()? != 1 {
        return None;
    }
    let cert = DeviceCert {
        identity: r.array().ok()?,
        mls_signature_key: r.array().ok()?,
        device: r.array().ok()?,
        inbox: r.array().ok()?,
        signature: r.array().ok()?,
    };
    r.finish().ok()?;
    Some(cert)
}

/// Verifies that a credential carries a valid certificate for the given
/// MLS signature key.
fn verify_credential(credential: &Credential, signature_key: &[u8]) -> Option<DeviceCert> {
    let basic = BasicCredential::try_from(credential.clone()).ok()?;
    let cert = DeviceCert::decode(basic.identity()).ok()?;
    (cert.mls_signature_key.as_slice() == signature_key).then_some(cert)
}

impl Client {
    /// Creates a brand-new device with a fresh identity.
    pub fn create(config: Config, rand: Rand, now_ms: u64) -> (Client, Step) {
        let identity = Identity::from_seed(rand.bytes());
        let mut client = Client::new_device(config, rand, identity, now_ms);
        client.pump(now_ms);
        let step = client.finish();
        (client, step)
    }

    /// A new device of an existing identity, from what one of its devices
    /// sealed for it ([`crate::link`]). The identity's other devices are its
    /// siblings: each device adds the others to every conversation it is in.
    pub fn create_linked(
        config: Config,
        rand: Rand,
        payload: &LinkPayload,
        now_ms: u64,
    ) -> (Client, Step) {
        let identity = Identity::from_seed(payload.identity_seed);
        let mut client = Client::new_device(config, rand, identity, now_ms);
        for card in &payload.devices {
            if card.identity == client.identity.public() && card.inbox != client.cert.inbox {
                client.siblings.insert(card.inbox, *card);
                client.dirty_siblings.insert(card.inbox);
            }
        }
        client.pump(now_ms);
        let step = client.finish();
        (client, step)
    }

    /// A device of `identity` with nothing done yet (its first pump publishes
    /// key packages).
    fn new_device(config: Config, rand: Rand, identity: Identity, now_ms: u64) -> Client {
        let device: DeviceId = rand.bytes();
        let mls_seed: [u8; 32] = rand.bytes();
        let mls_public = ed25519_dalek::SigningKey::from_bytes(&mls_seed)
            .verifying_key()
            .to_bytes();
        let signer = SignatureKeyPair::from_raw(
            SignatureScheme::ED25519,
            mls_seed.to_vec(),
            mls_public.to_vec(),
        );
        let inbox: Route = rand.bytes();
        let cert = identity.certify(mls_public, device, inbox);
        let next_request = u64::from_le_bytes(rand.bytes()) >> 1;

        Client {
            config,
            provider: Provider::new(rand, MlsStore::default()),
            identity,
            mls_seed,
            signer,
            cert,
            inbox_cursor: 0,
            key_packages_owed: config.key_packages,
            last_resort_owed: true,
            push_target: None,
            watched: BTreeMap::new(),
            watch_retry: BTreeMap::new(),
            dirty_watched: BTreeSet::new(),
            muted: BTreeMap::new(),
            dirty_muted: BTreeSet::new(),
            requests: BTreeMap::new(),
            join_requests: BTreeMap::new(),
            pending_joins: BTreeMap::new(),
            dirty_joins: BTreeSet::new(),
            key_packages_refreshed_ms: now_ms,
            conversations: BTreeMap::new(),
            blocked: BTreeSet::new(),
            tombstones: BTreeMap::new(),
            siblings: BTreeMap::new(),
            unlinked: BTreeSet::new(),
            dirty_unlinked: BTreeSet::new(),
            leavers: BTreeSet::new(),
            sibling_retry: BTreeMap::new(),
            inflight: BTreeMap::new(),
            next_request,
            last_poll_ms: None,
            effects: Vec::new(),
            last_signal: BTreeMap::new(),
            dirty_self: true,
            dirty_conversations: BTreeSet::new(),
            dirty_outbox: BTreeSet::new(),
            dirty_blocked: BTreeSet::new(),
            dirty_tombstones: BTreeSet::new(),
            dirty_siblings: BTreeSet::new(),
        }
    }

    /// Rebuilds a device from everything it ever persisted.
    pub fn restore(
        config: Config,
        rand: Rand,
        entries: impl IntoIterator<Item = (Vec<u8>, Vec<u8>)>,
        now_ms: u64,
    ) -> Result<(Client, Step), Error> {
        let store = MlsStore::from_entries(entries);
        let self_record = store
            .get_raw(KEY_SELF)
            .ok_or(Error::Corrupt("missing device record"))?;
        let record = decode_self(&self_record).map_err(|_| Error::Corrupt("device record"))?;
        let identity = Identity::from_seed(record.identity_seed);
        let mls_public = ed25519_dalek::SigningKey::from_bytes(&record.mls_seed)
            .verifying_key()
            .to_bytes();
        let signer = SignatureKeyPair::from_raw(
            SignatureScheme::ED25519,
            record.mls_seed.to_vec(),
            mls_public.to_vec(),
        );
        let cert =
            DeviceCert::decode(&record.cert).map_err(|_| Error::Corrupt("device certificate"))?;
        let next_request = u64::from_le_bytes(rand.bytes()) >> 1;
        let provider = Provider::new(rand, store);

        // One conversation this device cannot read stops only that
        // conversation (reported as out of sync), never the whole device.
        let mut conversations = BTreeMap::new();
        let mut unreadable = Vec::new();
        for (key, value) in provider.storage().scan_raw(PREFIX_CONVERSATION) {
            let id: Route = key[2..]
                .try_into()
                .map_err(|_| Error::Corrupt("conversation key"))?;
            let loaded = (|| -> std::result::Result<Conversation, &'static str> {
                let record = decode_conversation(&value).map_err(|_| "conversation record")?;
                let group = MlsGroup::load(provider.storage(), &GroupId::from_slice(&id))
                    .map_err(|_| "group state")?
                    .ok_or("missing group state")?;
                // OpenMLS trusts the state it stored: an own leaf that is not
                // this device's fails an assertion deep inside it later.
                let own = group
                    .own_leaf_node()
                    .is_some_and(|leaf| leaf.signature_key().as_slice() == signer.public());
                if record.active && !(group.is_active() && own) {
                    return Err("group state");
                }
                let mut outbox = VecDeque::new();
                for (_, value) in provider.storage().scan_raw(&[PREFIX_OUTBOX, &id].concat()) {
                    outbox.push_back(decode_outgoing(&value).map_err(|_| "outbox entry")?);
                }
                Ok(Conversation {
                    group,
                    active: record.active,
                    cursor: record.cursor,
                    caught_up: false,
                    next_sender_seq: record.next_sender_seq,
                    outbox,
                    pending: record.pending,
                    intents: record.intents,
                    windows: record.windows,
                    seen: VecDeque::new(),
                    seen_set: BTreeSet::new(),
                    creation_seed: record.creation_seed,
                    write_key: None,
                    signal_key: None,
                })
            })();
            match loaded {
                Ok(c) => {
                    conversations.insert(id, c);
                }
                Err(what) => unreadable.push((id, what)),
            }
        }
        let mut watched = BTreeMap::new();
        for (key, value) in provider.storage().scan_raw(PREFIX_WATCH) {
            let route: Route = key[2..]
                .try_into()
                .map_err(|_| Error::Corrupt("watch key"))?;
            let due = decode_watch(&value).map_err(|_| Error::Corrupt("watch record"))?;
            watched.insert(route, due);
        }
        let mut muted = BTreeMap::new();
        for (key, value) in provider.storage().scan_raw(PREFIX_MUTED) {
            let route: Route = key[2..]
                .try_into()
                .map_err(|_| Error::Corrupt("mute key"))?;
            let until = decode_watch(&value).map_err(|_| Error::Corrupt("mute record"))?;
            muted.insert(route, until);
        }
        let mut pending_joins = BTreeMap::new();
        for (key, value) in provider.storage().scan_raw(PREFIX_JOIN) {
            let join: [u8; 16] = key[2..]
                .try_into()
                .map_err(|_| Error::Corrupt("join key"))?;
            let pending = decode_pending_join(&value).map_err(|_| Error::Corrupt("join record"))?;
            pending_joins.insert(join, pending);
        }
        let mut blocked = BTreeSet::new();
        for (key, _) in provider.storage().scan_raw(PREFIX_BLOCKED) {
            let identity: IdentityKey = key[2..]
                .try_into()
                .map_err(|_| Error::Corrupt("blocked key"))?;
            blocked.insert(identity);
        }
        let mut unlinked = BTreeSet::new();
        for (key, _) in provider.storage().scan_raw(PREFIX_UNLINKED) {
            let inbox: Route = key[2..]
                .try_into()
                .map_err(|_| Error::Corrupt("unlinked key"))?;
            unlinked.insert(inbox);
        }
        let mut siblings = BTreeMap::new();
        for (key, value) in provider.storage().scan_raw(PREFIX_SIBLING) {
            let inbox: Route = key[2..]
                .try_into()
                .map_err(|_| Error::Corrupt("sibling key"))?;
            let card = ContactCard::decode(&value).map_err(|_| Error::Corrupt("sibling"))?;
            siblings.insert(inbox, card);
        }
        let mut tombstones = BTreeMap::new();
        for (key, value) in provider.storage().scan_raw(PREFIX_TOMBSTONE) {
            let route: Route = key[2..]
                .try_into()
                .map_err(|_| Error::Corrupt("tombstone key"))?;
            let seq = decode_watch(&value).map_err(|_| Error::Corrupt("tombstone"))?;
            tombstones.insert(route, seq);
        }
        // Whatever the store held must be exactly what was written.
        assert!(provider.storage().take_changes().is_empty());

        let mut client = Client {
            config,
            provider,
            identity,
            mls_seed: record.mls_seed,
            signer,
            cert,
            inbox_cursor: record.inbox_cursor,
            key_packages_owed: record.key_packages_owed,
            last_resort_owed: record.last_resort_owed,
            push_target: record.push_target,
            watched,
            watch_retry: BTreeMap::new(),
            dirty_watched: BTreeSet::new(),
            muted,
            dirty_muted: BTreeSet::new(),
            requests: BTreeMap::new(),
            join_requests: BTreeMap::new(),
            pending_joins,
            dirty_joins: BTreeSet::new(),
            key_packages_refreshed_ms: record.key_packages_refreshed_ms,
            conversations,
            blocked,
            tombstones,
            siblings,
            unlinked,
            dirty_unlinked: BTreeSet::new(),
            leavers: BTreeSet::new(),
            sibling_retry: BTreeMap::new(),
            inflight: BTreeMap::new(),
            next_request,
            last_poll_ms: None,
            effects: unreadable
                .into_iter()
                .map(|(conversation, what)| {
                    Effect::Event(Event::Desync {
                        conversation,
                        reason: format!("this device could not read its stored {what}"),
                    })
                })
                .collect(),
            last_signal: BTreeMap::new(),
            dirty_self: false,
            dirty_conversations: BTreeSet::new(),
            dirty_outbox: BTreeSet::new(),
            dirty_blocked: BTreeSet::new(),
            dirty_tombstones: BTreeSet::new(),
            dirty_siblings: BTreeSet::new(),
        };
        if record.classic || record.unruled {
            // Upgraded from before the post-quantum ciphersuite (nobody can
            // invite this device with what it published) or before timers
            // (groups now require them): replace it all.
            client.key_packages_refreshed_ms = now_ms;
            client.key_packages_owed = client.config.key_packages;
            client.last_resort_owed = true;
            client.dirty_self = true;
        }
        if record.unruled {
            // And tell each conversation this device supports what it did
            // not (timers, rules) now.
            let ids: Vec<Route> = client.conversations.keys().copied().collect();
            for id in ids {
                let c = client.conversations.get_mut(&id).expect("listed");
                if c.active && c.group.epoch().as_u64() > 0 {
                    c.intents.push_back(Intent::Update);
                    client.dirty_conversations.insert(id);
                }
            }
        }
        client.poll(now_ms);
        client.pump(now_ms);
        let step = client.finish();
        Ok((client, step))
    }

    pub fn identity(&self) -> IdentityKey {
        self.identity.public()
    }

    pub fn device(&self) -> DeviceId {
        self.cert.device
    }

    pub fn contact_card(&self) -> ContactCard {
        ContactCard {
            identity: self.identity.public(),
            inbox: self.cert.inbox,
        }
    }

    /// The logs this device follows: its inbox and its active conversations.
    /// A transport keeps a live subscription to each.
    pub fn routes(&self) -> Vec<Route> {
        let active = self
            .conversations
            .iter()
            .filter(|(_, c)| c.active)
            .map(|(id, _)| *id);
        std::iter::once(self.cert.inbox)
            .chain(active)
            .chain(self.requests.keys().copied())
            .collect()
    }

    /// Fetches every followed log now, e.g. after a subscription reconnects
    /// and pushes may have been missed.
    pub fn poll_now(&mut self, now_ms: u64) -> Step {
        self.poll(now_ms);
        self.pump(now_ms);
        self.finish()
    }

    /// Where the mailbox wakes this device when it is not connected.
    pub fn push_target(&self) -> Option<PushTarget<'_>> {
        self.push_target
            .as_ref()
            .map(|(platform, address)| PushTarget {
                platform: *platform,
                address,
            })
    }

    /// Sets (or clears) where the mailbox should wake this device when it is
    /// not connected. Every followed log is told.
    pub fn set_push_target(&mut self, now_ms: u64, target: Option<PushTarget<'_>>) -> Step {
        let target = target.map(|t| (t.platform, t.address.to_vec()));
        if target != self.push_target {
            if let Some(old) = self.push_target.take() {
                for route in self.routes() {
                    self.request(
                        now_ms,
                        Request::Watch {
                            route,
                            target: old.clone(),
                            enable: false,
                        },
                    );
                }
            }
            self.push_target = target;
            self.dirty_watched
                .extend(std::mem::take(&mut self.watched).into_keys());
            self.watch_retry.clear();
            self.dirty_self = true;
        }
        self.pump(now_ms);
        self.finish()
    }

    pub fn conversations(&self) -> impl Iterator<Item = Route> + '_ {
        self.conversations.keys().copied()
    }

    pub fn is_active(&self, conversation: &Route) -> bool {
        self.conversations
            .get(conversation)
            .is_some_and(|c| c.active)
    }

    /// The conversation's MLS epoch and epoch authenticator. Members that agree
    /// on both agree on the entire group state.
    pub fn epoch(&self, conversation: &Route) -> Option<(u64, Vec<u8>)> {
        let c = self.conversations.get(conversation)?;
        Some((
            c.group.epoch().as_u64(),
            c.group.epoch_authenticator().as_slice().to_vec(),
        ))
    }

    /// The identities in a conversation, each once however many of its
    /// devices are members.
    pub fn members(&self, conversation: &Route) -> Vec<IdentityKey> {
        let mut members: Vec<IdentityKey> = Vec::new();
        if let Some(c) = self.conversations.get(conversation) {
            for cert in c.group.members().filter_map(|m| tree_cert(&m.credential)) {
                if !members.contains(&cert.identity) {
                    members.push(cert.identity);
                }
            }
        }
        members
    }

    /// The inboxes of a conversation's member devices.
    fn member_inboxes(&self, conversation: &Route) -> Vec<Route> {
        self.conversations
            .get(conversation)
            .map_or_else(Vec::new, |c| {
                c.group
                    .members()
                    .filter_map(|m| tree_cert(&m.credential))
                    .map(|cert| cert.inbox)
                    .collect()
            })
    }

    /// Messages not yet stored by the mailbox.
    pub fn outbox_len(&self, conversation: &Route) -> usize {
        self.conversations
            .get(conversation)
            .map_or(0, |c| c.outbox.len())
    }

    /// A one-line summary of a conversation's protocol state, for diagnostics.
    pub fn describe(&self, conversation: &Route) -> String {
        let Some(c) = self.conversations.get(conversation) else {
            return "unknown".to_owned();
        };
        let inflight: Vec<String> = self
            .inflight
            .values()
            .filter(|i| match &i.request {
                Request::Fetch(id)
                | Request::Submit {
                    conversation: id, ..
                }
                | Request::Claim {
                    conversation: id, ..
                } => id == conversation,
                _ => false,
            })
            .map(|i| format!("{:?}x{}", i.request, i.attempts))
            .collect();
        format!(
            "epoch={} active={} cursor={} caught_up={} pending={} mls_pending={} intents={:?} outbox={:?} inflight={:?}",
            c.group.epoch().as_u64(),
            c.active,
            c.cursor,
            c.caught_up,
            c.pending
                .as_ref()
                .map(|p| hex4(&p.hash))
                .unwrap_or_default(),
            c.group.pending_commit().is_some(),
            c.intents
                .iter()
                .map(|i| match i {
                    Intent::Add { key_package, .. } => format!("add(kp={})", key_package.is_some()),
                    Intent::Remove { .. } => "remove".to_owned(),
                    Intent::Update => "update".to_owned(),
                    Intent::Timer(seconds) => format!("timer({seconds})"),
                    Intent::Rename(_) => "rename".to_owned(),
                    Intent::RemoveDevice { .. } => "remove device".to_owned(),
                    Intent::Policy(_) => "rules".to_owned(),
                    Intent::StepDown => "step down".to_owned(),
                })
                .collect::<Vec<_>>(),
            c.outbox
                .iter()
                .map(|o| (o.sender_seq, o.sealed.as_ref().map(|s| hex4(&s.hash))))
                .collect::<Vec<_>>(),
            inflight,
        )
    }

    /// Membership changes waiting to be committed.
    pub fn intents_len(&self, conversation: &Route) -> usize {
        self.conversations
            .get(conversation)
            .map_or(0, |c| c.intents.len() + usize::from(c.pending.is_some()))
    }

    pub fn start_conversation(
        &mut self,
        now_ms: u64,
        contact: ContactCard,
    ) -> Result<(Route, Step), Error> {
        self.start_group(now_ms, &[contact], "")
    }

    /// Starts a group with these people, named `name` (empty: unnamed, shown
    /// by its members). They are added one commit at a time.
    pub fn start_group(
        &mut self,
        now_ms: u64,
        contacts: &[ContactCard],
        name: &str,
    ) -> Result<(Route, Step), Error> {
        if self.conversations.len() >= CONVERSATIONS_MAX {
            return Err(Error::TooManyConversations);
        }
        if contacts.is_empty() || contacts.len() >= GROUP_MEMBERS_MAX || name.len() > GROUP_NAME_MAX
        {
            return Err(Error::Invalid);
        }
        // The route is the hash of a fresh key that signs the first commit,
        // so nobody else can create this log (or create it differently).
        let creation_seed: [u8; 32] = self.provider.rand().bytes();
        let creation_key = ed25519_dalek::SigningKey::from_bytes(&creation_seed);
        let id: Route = creation_route(&creation_key.verifying_key().to_bytes());
        let credential = self.credential();
        let group = MlsGroup::new_with_group_id(
            &self.provider,
            &self.signer,
            &create_config(name, self.identity.public()),
            GroupId::from_slice(&id),
            credential,
        )
        .map_err(mls_error)?;
        let intents = contacts
            .iter()
            .map(|contact| Intent::Add {
                contact: *contact,
                key_package: None,
            })
            .collect();
        let mut conversation = Conversation::new(group, 0, intents);
        conversation.creation_seed = Some(creation_seed);
        self.conversations.insert(id, conversation);
        self.dirty_conversations.insert(id);
        self.effects
            .push(Effect::Event(Event::Started { conversation: id }));
        self.pump(now_ms);
        Ok((id, self.finish()))
    }

    pub fn invite(
        &mut self,
        now_ms: u64,
        conversation: Route,
        contact: ContactCard,
    ) -> Result<Step, Error> {
        self.intend(
            conversation,
            Intent::Add {
                contact,
                key_package: None,
            },
        )?;
        self.pump(now_ms);
        Ok(self.finish())
    }

    pub fn remove(
        &mut self,
        now_ms: u64,
        conversation: Route,
        identity: IdentityKey,
    ) -> Result<Step, Error> {
        self.intend(conversation, Intent::Remove { identity })?;
        self.pump(now_ms);
        Ok(self.finish())
    }

    /// Rotates this device's leaf keys (post-compromise security).
    pub fn update_keys(&mut self, now_ms: u64, conversation: Route) -> Result<Step, Error> {
        self.intend(conversation, Intent::Update)?;
        self.pump(now_ms);
        Ok(self.finish())
    }

    fn intend(&mut self, conversation: Route, intent: Intent) -> Result<(), Error> {
        let c = self
            .conversations
            .get_mut(&conversation)
            .ok_or(Error::UnknownConversation)?;
        if !c.active {
            return Err(Error::Inactive);
        }
        if c.intents.len() >= INTENTS_MAX {
            return Err(Error::Invalid);
        }
        c.intents.push_back(intent);
        self.dirty_conversations.insert(conversation);
        Ok(())
    }

    /// Queues a message. It is encrypted and sent as soon as the group allows.
    pub fn send(
        &mut self,
        now_ms: u64,
        conversation: Route,
        text: &str,
    ) -> Result<(u64, Step), Error> {
        if text.len() > TEXT_MAX {
            return Err(Error::TooLong);
        }
        self.queue(now_ms, conversation, Content::Text(text.to_owned()))
    }

    /// A new file's id and key. Its parts are sealed with the key
    /// ([`crate::file::seal`]) and uploaded, each with [`Client::file_auth`],
    /// and only then shared with [`Client::send_file`].
    pub fn new_file(&self) -> ([u8; 16], [u8; 32]) {
        (self.provider.rand().bytes(), self.provider.rand().bytes())
    }

    /// Proof for the mailbox that this device, a member, may store part
    /// `part` (`len` stored bytes) of file `file` under the conversation:
    /// the epoch it holds for and its tag. A commit makes it stale; the
    /// mailbox then refuses it and the upload asks again.
    pub fn file_auth(
        &mut self,
        conversation: Route,
        file: [u8; 16],
        part: u32,
        len: u32,
    ) -> Result<FilePart, Error> {
        let c = self
            .conversations
            .get_mut(&conversation)
            .ok_or(Error::UnknownConversation)?;
        if !c.active || c.group.epoch().as_u64() == 0 {
            return Err(Error::Inactive);
        }
        let mut part = FilePart {
            file,
            part,
            len,
            epoch: c.group.epoch().as_u64(),
            auth: [0; 16],
        };
        part.auth = file_tag(
            &c.write_key(&self.provider, &conversation),
            &conversation,
            &part,
        );
        Ok(part)
    }

    /// Shares an uploaded file with the conversation, as a message.
    pub fn send_file(
        &mut self,
        now_ms: u64,
        conversation: Route,
        file: SharedFile,
    ) -> Result<(u64, Step), Error> {
        if !file.file_ref().valid() {
            return Err(Error::FileTooLarge);
        }
        self.queue(now_ms, conversation, Content::File(Box::new(file)))
    }

    /// Sends a call signal to the conversation.
    /// Sends a reply, reaction, edit, deletion, read receipt or voice
    /// message (text, files, calls and leaving have their own calls). A read
    /// receipt replaces one not yet sent.
    pub fn send_content(
        &mut self,
        now_ms: u64,
        conversation: Route,
        content: Content,
    ) -> Result<(u64, Step), Error> {
        let kind_allowed = matches!(
            content,
            Content::Reply { .. }
                | Content::React { .. }
                | Content::Edit { .. }
                | Content::Delete { .. }
                | Content::Receipt(_)
                | Content::Voice(_)
        );
        if !kind_allowed || !content.valid() {
            return Err(Error::Invalid);
        }
        self.queue(now_ms, conversation, content)
    }

    pub fn send_call(
        &mut self,
        now_ms: u64,
        conversation: Route,
        call: Call,
    ) -> Result<(u64, Step), Error> {
        if !call.signal().valid() {
            return Err(Error::Invalid);
        }
        self.queue(now_ms, conversation, Content::Call(Box::new(call)))
    }

    /// Sets the conversation's disappearing-message timer for everyone, in
    /// seconds (zero turns it off). Messages sent from now on carry it.
    ///
    /// The timer is part of the group's state (a group context extension),
    /// so a change is a commit: every member, and anyone who joins later,
    /// sees the same timer at the same point in the log.
    pub fn set_timer(
        &mut self,
        now_ms: u64,
        conversation: Route,
        seconds: u32,
    ) -> Result<Step, Error> {
        if seconds > DISAPPEAR_MAX_S {
            return Err(Error::Invalid);
        }
        self.intend(conversation, Intent::Timer(seconds))?;
        self.pump(now_ms);
        Ok(self.finish())
    }

    /// The conversation's disappearing-message timer, in seconds: this
    /// device's own change while it is being committed, else the group's.
    pub fn timer(&self, conversation: &Route) -> u32 {
        self.conversations
            .get(conversation)
            .map_or(0, Conversation::timer)
    }

    /// Forgets a conversation on this device: its keys, its unsent messages
    /// and its push registration. Nobody else is told; the device just stops
    /// reading the log (deleting a chat, or blocking someone, is silent).
    pub fn forget(&mut self, now_ms: u64, conversation: Route) -> Result<Step, Error> {
        let c = self
            .conversations
            .get(&conversation)
            .ok_or(Error::UnknownConversation)?;
        // Requests about it would find nothing when they are answered.
        self.inflight.retain(|_, inflight| match &inflight.request {
            Request::Fetch(route) | Request::Watch { route, .. } => *route != conversation,
            Request::Submit {
                conversation: c, ..
            }
            | Request::Claim {
                conversation: c, ..
            } => *c != conversation,
            Request::FetchInbox | Request::Publish { .. } => true,
            Request::OpenRequests(route) | Request::FetchRequests(route) => self
                .requests
                .get(route)
                .is_none_or(|log| log.conversation != conversation),
        });
        // Its requests log, if this device read one, is no longer read.
        self.requests
            .retain(|_, log| log.conversation != conversation);
        self.join_requests.retain(|(c, _), _| *c != conversation);
        // Stop the wakeups. The frame (and its proof of membership) is built
        // now, while the keys still exist.
        if let Some(target) = self.push_target.clone()
            && c.active
        {
            self.request(
                now_ms,
                Request::Watch {
                    route: conversation,
                    target,
                    enable: false,
                },
            );
        }
        let mut c = self.conversations.remove(&conversation).expect("checked");
        c.group
            .delete(self.provider.storage())
            .expect("storage is in memory");
        if self.tombstones.len() >= CONVERSATIONS_MAX
            && let Some((&oldest, _)) = self.tombstones.iter().min_by_key(|(_, seq)| **seq)
        {
            self.tombstones.remove(&oldest);
            self.dirty_tombstones.insert(oldest);
        }
        self.tombstones.insert(conversation, c.next_sender_seq);
        self.dirty_tombstones.insert(conversation);
        for outgoing in &c.outbox {
            self.dirty_outbox
                .insert((conversation, outgoing.sender_seq));
        }
        self.dirty_conversations.insert(conversation);
        self.watch_retry.remove(&conversation);
        if self.watched.remove(&conversation).is_some() {
            self.dirty_watched.insert(conversation);
        }
        if self.muted.remove(&conversation).is_some() {
            self.dirty_muted.insert(conversation);
        }
        Ok(self.finish())
    }

    /// Mutes a conversation until `until_ms` ([`MUTED_FOREVER`]: until
    /// unmuted), or unmutes it (`None`). A muted conversation still updates
    /// whenever the app is open; it only stops waking this device.
    pub fn set_muted(
        &mut self,
        now_ms: u64,
        conversation: Route,
        until_ms: Option<u64>,
    ) -> Result<Step, Error> {
        if !self.conversations.contains_key(&conversation) {
            return Err(Error::UnknownConversation);
        }
        match until_ms {
            Some(until) if until > now_ms => {
                self.muted.insert(conversation, until.min(MUTED_FOREVER));
            }
            _ => {
                self.muted.remove(&conversation);
            }
        }
        self.dirty_muted.insert(conversation);
        self.pump(now_ms);
        Ok(self.finish())
    }

    /// Until when a conversation is muted ([`MUTED_FOREVER`]: until unmuted).
    pub fn muted_until(&self, conversation: &Route) -> Option<u64> {
        self.muted.get(conversation).copied()
    }

    /// The group's rules (`None` for a group from before admins, where
    /// everyone may do everything).
    pub fn policy(&self, conversation: &Route) -> Option<Policy> {
        self.conversations
            .get(conversation)
            .and_then(|c| group_policy(&c.group).ok().flatten())
    }

    /// Who the group's admins are now (everyone, in a group from before
    /// admins).
    pub fn admins(&self, conversation: &Route) -> Vec<IdentityKey> {
        self.conversations
            .get(conversation)
            .map(|c| effective_admins(&c.group))
            .unwrap_or_default()
    }

    /// Changes the group's rules (a commit). Only an admin may; in a group
    /// from before admins, the first rules must make every member an admin.
    pub fn set_policy(
        &mut self,
        now_ms: u64,
        conversation: Route,
        mut policy: Policy,
    ) -> Result<Step, Error> {
        policy.admins.sort_unstable();
        policy.admins.dedup();
        if policy.admins.len() > GROUP_MEMBERS_MAX {
            return Err(Error::Invalid);
        }
        self.intend(conversation, Intent::Policy(policy))?;
        self.pump(now_ms);
        Ok(self.finish())
    }

    /// Asks to join a group with its invite link: a one-time key package of
    /// this device (never published), signed, sealed to the group's admins.
    /// Returns the frame to leave at the requests log (sent once; a lost
    /// one is sent again by asking again).
    pub fn join_request(
        &mut self,
        now_ms: u64,
        code: &JoinCode,
        header: &JoinHeader,
        name: &str,
    ) -> Result<(Vec<u8>, Step), Error> {
        if name.len() > crate::join::JOIN_NAME_MAX || header.name.len() > GROUP_NAME_MAX {
            return Err(Error::Invalid);
        }
        let key_package = self.new_key_package(false)?;
        let validated = KeyPackageIn::tls_deserialize_exact(&key_package)
            .map_err(mls_error)?
            .validate(self.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(mls_error)?;
        let encryption_key = validated
            .leaf_node()
            .encryption_key()
            .tls_serialize_detached()
            .map_err(mls_error)?;
        let key_package_ref = validated
            .hash_ref(self.provider.crypto())
            .map_err(mls_error)?
            .tls_serialize_detached()
            .map_err(mls_error)?;
        let card = self.contact_card();
        let signed = code.signed_bytes(&card, name, &key_package, now_ms);
        let signature: [u8; 64] = self
            .signer
            .sign(&signed)
            .map_err(mls_error)?
            .try_into()
            .map_err(|_| Error::Mls("signature size".into()))?;
        let frame = code.request_frame(
            header,
            &JoinBody {
                card,
                name: name.to_owned(),
                key_package,
                at_ms: now_ms,
                signature,
            },
        );
        self.pending_joins.insert(
            code.join,
            PendingJoin {
                encryption_key,
                name: header.name.clone(),
                at_ms: now_ms,
                key_package_ref,
            },
        );
        self.dirty_joins.insert(code.join);
        Ok((frame, self.finish()))
    }

    /// How many senders' duplicate windows a conversation keeps (tests).
    #[doc(hidden)]
    pub fn duplicate_windows(&self, conversation: &Route) -> usize {
        self.conversations
            .get(conversation)
            .map_or(0, |c| c.windows.len())
    }

    /// Groups this device asked to join with a link, by name, still waiting.
    pub fn pending_joins(&self) -> Vec<String> {
        self.pending_joins
            .values()
            .map(|p| p.name.clone())
            .collect()
    }

    /// Approves a request to join (as an admin): adds exactly the key
    /// package it carried.
    pub fn approve_join(
        &mut self,
        now_ms: u64,
        conversation: Route,
        id: Hash,
    ) -> Result<Step, Error> {
        let request = self
            .join_requests
            .remove(&(conversation, id))
            .ok_or(Error::Invalid)?;
        self.intend(
            conversation,
            Intent::Add {
                contact: request.card,
                key_package: Some(request.key_package),
            },
        )?;
        self.pump(now_ms);
        Ok(self.finish())
    }

    /// Follows the requests log of every group this device is an admin of
    /// that has a link; opens each (and opens it again when the group's
    /// name changes, for its header).
    fn follow_requests(&mut self, now_ms: u64) {
        let me = self.identity.public();
        let mut wanted = BTreeMap::new();
        for (id, c) in &self.conversations {
            if !c.active || c.group.epoch().as_u64() == 0 {
                continue;
            }
            if let Ok(Some(Policy {
                link: Some(seed), ..
            })) = group_policy(&c.group)
                && effective_admins(&c.group).contains(&me)
            {
                wanted.insert(*id, seed);
            }
        }
        let dropped: Vec<Route> = self
            .requests
            .iter()
            .filter(|(_, log)| {
                !wanted.get(&log.conversation).is_some_and(|seed| {
                    crate::join::join_of(seed, &log.conversation) == log.keys.code.join
                })
            })
            .map(|(route, _)| *route)
            .collect();
        for route in dropped {
            self.requests.remove(&route);
            self.provider
                .storage()
                .delete_raw(&[PREFIX_REQUESTS_READ, &route].concat());
        }
        self.join_requests
            .retain(|(conversation, _), _| wanted.contains_key(conversation));
        for (conversation, seed) in wanted {
            if self
                .requests
                .values()
                .any(|log| log.conversation == conversation)
            {
                continue;
            }
            let keys = LinkKeys::from_seed(&seed, &conversation);
            let route = keys.code.route();
            // Where this device stopped reading, so requests already shown
            // (and approved or declined) are not shown again.
            let cursor = self
                .provider
                .storage()
                .get_raw(&[PREFIX_REQUESTS_READ, &route].concat())
                .and_then(|v| v.try_into().ok())
                .map(u64::from_le_bytes)
                .unwrap_or(0);
            self.requests.insert(
                route,
                RequestsLog {
                    conversation,
                    keys,
                    cursor,
                    opened: None,
                },
            );
            self.request(now_ms, Request::FetchRequests(route));
        }
        let stale: Vec<Route> = self
            .requests
            .iter()
            .filter(|(_, log)| {
                log.opened.as_deref()
                    != Some(
                        group_settings(&self.conversations[&log.conversation].group)
                            .name
                            .as_str(),
                    )
            })
            .map(|(route, _)| *route)
            .collect();
        for route in stale {
            self.request(now_ms, Request::OpenRequests(route));
        }
    }

    /// New requests in a requests log: opened, checked (signed by a device
    /// of the identity they name, whose certificate that identity signed),
    /// and reported. Requests from people blocked, or already members, are
    /// dropped.
    fn apply_requests(&mut self, now_ms: u64, route: Route, entries: &Entries<'_>) {
        let Some(log) = self.requests.get(&route) else {
            return;
        };
        let conversation = log.conversation;
        let members = self.members(&conversation);
        let devices = member_devices(&self.conversations[&conversation].group);
        let mut cursor = log.cursor;
        let mut found = Vec::new();
        for entry in &entries.entries {
            if entry.seq <= cursor {
                continue;
            }
            cursor = entry.seq;
            let Ok(request) = log.keys.open(entry.data) else {
                continue;
            };
            let Some(leaf) = KeyPackageIn::tls_deserialize_exact(&request.key_package)
                .ok()
                .and_then(|kp| {
                    kp.validate(self.provider.crypto(), ProtocolVersion::Mls10)
                        .ok()
                })
                .filter(|kp| kp.ciphersuite() == CIPHERSUITE)
                .map(|kp| kp.leaf_node().clone())
            else {
                continue;
            };
            // Fresh: made within the time a request waits, and not from the
            // future (a day's grace for clocks).
            if request.at_ms + PENDING_JOIN_MS < now_ms || request.at_ms > now_ms + DAY_MS {
                continue;
            }
            let signed = log.keys.code.signed_bytes(
                &request.card,
                &request.name,
                &request.key_package,
                request.at_ms,
            );
            // The device must be new to the group: one reusing a member's
            // device id would make the group refuse the commit adding it.
            let genuine = verify_credential(leaf.credential(), leaf.signature_key().as_slice())
                .is_some_and(|cert| {
                    cert.identity == request.card.identity
                        && cert.inbox == request.card.inbox
                        && !devices.contains(&cert.device)
                })
                && signed_by(leaf.signature_key().as_slice(), &signed, &request.signature);
            if !genuine
                || self.blocked.contains(&request.card.identity)
                || members.contains(&request.card.identity)
            {
                continue;
            }
            found.push((hash16(entry.data), request));
        }
        // Moved only past what was read; if the log holds more than one
        // fetch returned, fetch again. A batch of junk hides nothing.
        let more = match entries.entries.last() {
            Some(last) => entries.next > last.seq + 1,
            None => {
                cursor = cursor.max(entries.next.saturating_sub(1));
                false
            }
        };
        if let Some(log) = self.requests.get_mut(&route)
            && cursor != log.cursor
        {
            log.cursor = cursor;
            self.provider.storage().put_raw(
                [PREFIX_REQUESTS_READ, &route].concat(),
                cursor.to_le_bytes().to_vec(),
            );
        }
        if more {
            self.request(now_ms, Request::FetchRequests(route));
        }
        for (id, request) in found {
            self.effects.push(Effect::Event(Event::JoinRequest {
                conversation,
                id,
                identity: request.card.identity,
                name: request.name.clone(),
            }));
            self.join_requests.insert((conversation, id), request);
        }
    }

    /// The rules once this device's identity stops being an admin, or
    /// `None` when there is nothing to step down from (not an admin, no
    /// rules, or nobody else in the group).
    fn step_down_rules(&self, id: &Route) -> Option<Policy> {
        let group = &self.conversations[id].group;
        let me = self.identity.public();
        let mut rules = group_policy(group).ok().flatten()?;
        if !effective_admins(group).contains(&me) {
            return None;
        }
        let others: Vec<IdentityKey> = member_identities(group)
            .into_iter()
            .filter(|m| *m != me)
            .collect();
        if others.is_empty() {
            return None;
        }
        rules.admins.retain(|a| *a != me);
        if !rules.admins.iter().any(|a| others.contains(a)) {
            // Prefer someone who is not on their way out too.
            let staying = others
                .iter()
                .find(|m| !self.leavers.contains(&(*id, **m)))
                .unwrap_or(&others[0]);
            rules.admins.push(*staying);
            rules.admins.sort_unstable();
        }
        Some(rules)
    }

    /// Whether this device has sent anything in a conversation `identity`
    /// is in (or it is this identity).
    fn talks_with(&self, identity: &IdentityKey) -> bool {
        *identity == self.identity.public()
            || self
                .conversations
                .values()
                .any(|c| c.next_sender_seq > 1 && member_identities(&c.group).contains(identity))
    }

    /// Conversations this device has never sent anything in.
    fn unanswered(&self) -> usize {
        self.conversations
            .values()
            .filter(|c| c.next_sender_seq <= 1)
            .count()
    }

    /// Forgets one of this identity's devices for good: not a sibling any
    /// more, and never added back to a conversation.
    fn unlink(&mut self, inbox: Route) {
        if self.siblings.remove(&inbox).is_some() {
            self.dirty_siblings.insert(inbox);
        }
        if self.unlinked.len() < UNLINKED_MAX && self.unlinked.insert(inbox) {
            self.dirty_unlinked.insert(inbox);
        }
    }

    /// Whether this device's change keeps the group's rules, or why not.
    fn permitted(&self, id: &Route, intent: &Intent) -> Result<(), &'static str> {
        let group = &self.conversations[id].group;
        let me = self.identity.public();
        let policy = group_policy(group).map_err(|_| "the group's rules are damaged")?;
        let admin = effective_admins(group).contains(&me);
        let only_admins = |who: fn(&Policy) -> Who| {
            policy.as_ref().is_some_and(|p| who(p) == Who::Admins) && !admin
        };
        match intent {
            Intent::Add { contact, .. } if contact.identity != me && only_admins(|p| p.add) => {
                Err("only admins may add people to this group")
            }
            Intent::Timer(_) | Intent::Rename(_) if only_admins(|p| p.edit) => {
                Err("only admins may change this group's name or timer")
            }
            Intent::Policy(next) => match policy {
                None if !member_identities(group)
                    .iter()
                    .all(|m| next.admins.contains(m)) =>
                {
                    Err("a group's first rules must make every member an admin")
                }
                Some(_) if !admin => Err("only admins may change this group's rules"),
                _ => Ok(()),
            },
            _ => Ok(()),
        }
    }

    /// Names the group for everyone (a commit, like the timer).
    pub fn rename(&mut self, now_ms: u64, conversation: Route, name: &str) -> Result<Step, Error> {
        if name.len() > GROUP_NAME_MAX {
            return Err(Error::Invalid);
        }
        self.intend(conversation, Intent::Rename(name.to_owned()))?;
        self.pump(now_ms);
        Ok(self.finish())
    }

    /// The group's name (empty: none): this device's own change while it
    /// is being committed, else the group's.
    pub fn group_name(&self, conversation: &Route) -> String {
        let Some(c) = self.conversations.get(conversation) else {
            return String::new();
        };
        c.intents
            .iter()
            .rev()
            .find_map(|intent| match intent {
                Intent::Rename(name) => Some(name.clone()),
                _ => None,
            })
            .unwrap_or_else(|| group_settings(&c.group).name)
    }

    /// Leaves the group: tells the members, who remove all of this
    /// identity's devices. Once it is sent, forget the conversation.
    /// An admin first steps down (handing the role to the member at the
    /// lowest position if nobody else has it), so the members who then
    /// remove this identity may: the commit goes before the message, which
    /// waits for it.
    pub fn leave(&mut self, now_ms: u64, conversation: Route) -> Result<(u64, Step), Error> {
        let me = self.identity.public();
        if let Some(c) = self.conversations.get(&conversation)
            && c.active
            && group_policy(&c.group).is_ok_and(|p| p.is_some())
            && effective_admins(&c.group).contains(&me)
        {
            self.intend(conversation, Intent::StepDown)?;
        }
        self.queue(now_ms, conversation, Content::Leave)
    }

    /// Everyone this device shares a conversation with, one card each (a
    /// device of theirs to invite: their other devices follow).
    pub fn known_contacts(&self) -> Vec<ContactCard> {
        let me = self.identity.public();
        let mut cards: BTreeMap<IdentityKey, ContactCard> = BTreeMap::new();
        for c in self.conversations.values().filter(|c| c.active) {
            for cert in c.group.members().filter_map(|m| tree_cert(&m.credential)) {
                if cert.identity != me {
                    cards.entry(cert.identity).or_insert(ContactCard {
                        identity: cert.identity,
                        inbox: cert.inbox,
                    });
                }
            }
        }
        cards.into_values().collect()
    }

    /// The identity's root key, for linking a new device or sealing a backup.
    /// Whoever holds it can act as this identity: it only ever leaves the
    /// device sealed ([`crate::link`]).
    pub fn identity_seed(&self) -> [u8; 32] {
        self.identity.seed()
    }

    /// This identity's other devices.
    pub fn devices(&self) -> Vec<ContactCard> {
        self.siblings.values().copied().collect()
    }

    /// What a new device of this identity needs: the root key and every
    /// device it should add to its conversations (this one included).
    pub fn link_payload(&self, app: Vec<u8>) -> LinkPayload {
        let mut devices = vec![self.contact_card()];
        devices.extend(self.siblings.values().copied());
        devices.truncate(DEVICES_MAX);
        LinkPayload {
            identity_seed: self.identity.seed(),
            devices,
            app,
        }
    }

    /// Adds a newly linked device of this identity: it joins every
    /// conversation this device is in.
    pub fn add_device(&mut self, now_ms: u64, card: ContactCard) -> Result<Step, Error> {
        if card.identity != self.identity.public()
            || card.inbox == self.cert.inbox
            || self.unlinked.contains(&card.inbox)
        {
            return Err(Error::Invalid);
        }
        if !self.siblings.contains_key(&card.inbox) && self.siblings.len() + 1 >= DEVICES_MAX {
            return Err(Error::Invalid);
        }
        self.siblings.insert(card.inbox, card);
        self.dirty_siblings.insert(card.inbox);
        self.pump(now_ms);
        Ok(self.finish())
    }

    /// Unlinks a device of this identity (lost, or no longer used): it is
    /// removed from every conversation this device is in. It keeps the
    /// identity's root key, so a stolen device can still act as the identity;
    /// only burning the identity stops that.
    pub fn remove_device(&mut self, now_ms: u64, inbox: Route) -> Step {
        self.unlink(inbox);
        let ids: Vec<Route> = self.conversations.keys().copied().collect();
        for id in ids {
            if self.conversations[&id].active && self.member_inboxes(&id).contains(&inbox) {
                let c = self.conversations.get_mut(&id).expect("listed");
                c.intents.push_back(Intent::RemoveDevice { inbox });
                self.dirty_conversations.insert(id);
            }
        }
        self.pump(now_ms);
        self.finish()
    }

    /// A backup of this identity: its root key and the devices of everyone it
    /// talks to, so a restored device can reach them again.
    pub fn backup(&self, app: Vec<u8>) -> Backup {
        let me = self.identity.public();
        let mut contacts: Vec<ContactCard> = Vec::new();
        for c in self.conversations.values() {
            for cert in c.group.members().filter_map(|m| tree_cert(&m.credential)) {
                let card = ContactCard {
                    identity: cert.identity,
                    inbox: cert.inbox,
                };
                if cert.identity != me
                    && !contacts.contains(&card)
                    && contacts.len() < BACKUP_CONTACTS_MAX
                {
                    contacts.push(card);
                }
            }
        }
        Backup {
            identity_seed: self.identity.seed(),
            contacts,
            app,
        }
    }

    /// This identity's signature claiming `handle` for `card` (with the
    /// directory's `challenge`), so nobody can point a handle at someone
    /// else's identity.
    pub fn sign_handle(&self, handle: &str, challenge: &[u8]) -> [u8; 64] {
        self.identity.sign(&handle_signed_bytes(
            handle,
            &self.contact_card(),
            challenge,
        ))
    }

    /// Blocks an identity: this device no longer joins conversations it is
    /// in, and drops its messages (and calls) in the ones it shares. The
    /// identity is not told.
    pub fn block(&mut self, identity: IdentityKey) -> Result<Step, Error> {
        if self.blocked.len() >= BLOCKED_MAX && !self.blocked.contains(&identity) {
            return Err(Error::Invalid);
        }
        if self.blocked.insert(identity) {
            self.dirty_blocked.insert(identity);
        }
        Ok(self.finish())
    }

    pub fn unblock(&mut self, identity: IdentityKey) -> Step {
        if self.blocked.remove(&identity) {
            self.dirty_blocked.insert(identity);
        }
        self.finish()
    }

    pub fn blocked(&self) -> impl Iterator<Item = IdentityKey> + '_ {
        self.blocked.iter().copied()
    }

    /// Tells the members of a conversation connected right now that this
    /// device is typing, stopped, online or offline. Sealed with a key from
    /// the epoch that the mailbox never has, and signed with this device's
    /// MLS key, so no member can speak for another. Nothing is stored or
    /// retried: a lost signal is not worth sending again.
    pub fn signal(
        &mut self,
        now_ms: u64,
        conversation: Route,
        kind: SignalKind,
    ) -> Result<Step, Error> {
        let c = self
            .conversations
            .get_mut(&conversation)
            .ok_or(Error::UnknownConversation)?;
        if !c.active || c.group.epoch().as_u64() == 0 {
            return Err(Error::Inactive);
        }
        let epoch = c.group.epoch().as_u64();
        let leaf = c.group.own_leaf_index().u32();
        let signed = signal_signed_bytes(&conversation, epoch, leaf, kind, now_ms);
        let signature: [u8; 64] = self
            .signer
            .sign(&signed)
            .map_err(mls_error)?
            .try_into()
            .map_err(|_| Error::Mls("signature size".into()))?;
        let mut plain = Writer::with_capacity(4 + 1 + 8 + 64);
        plain.u32(leaf).u8(kind as u8).u64(now_ms).array(&signature);
        let key = c.signal_key(&self.provider, &conversation);
        let nonce: [u8; 12] = self.provider.rand().bytes();
        let sealed = ChaCha20Poly1305::new(&key.into())
            .encrypt(
                &nonce.into(),
                Payload {
                    msg: &plain.finish(),
                    aad: &signal_aad(&conversation, epoch),
                },
            )
            .map_err(|_| Error::Invalid)?;
        let sealed = [nonce.as_slice(), &sealed].concat();
        let auth = signal_tag(
            &c.write_key(&self.provider, &conversation),
            &conversation,
            &sealed,
        );
        let body = Signal {
            epoch,
            auth,
            sealed: &sealed,
        }
        .encode();
        self.effects.push(Effect::Mailbox(frame::encode_vec(
            Kind::Signal,
            0,
            conversation,
            &body,
        )));
        Ok(self.finish())
    }

    /// A member's signal, relayed by the mailbox: shown only if it opens with
    /// this epoch's key, is signed by the member at the leaf it names, is not
    /// this device's own, and is recent and newer than the last one from
    /// that device.
    fn on_signal(&mut self, now_ms: u64, route: Route, body: &[u8]) {
        let Ok(signal) = Signal::decode(body) else {
            return;
        };
        let Some(c) = self.conversations.get_mut(&route).filter(|c| c.active) else {
            return;
        };
        let epoch = c.group.epoch().as_u64();
        if signal.epoch != epoch || signal.sealed.len() < 12 {
            return;
        }
        let key = c.signal_key(&self.provider, &route);
        let (nonce, ciphertext) = signal.sealed.split_at(12);
        let Ok(plain) = ChaCha20Poly1305::new(&key.into()).decrypt(
            nonce.into(),
            Payload {
                msg: ciphertext,
                aad: &signal_aad(&route, epoch),
            },
        ) else {
            return;
        };
        let mut r = Reader::new(&plain);
        let (Ok(leaf), Ok(kind), Ok(sent_at_ms), Ok(signature)) =
            (r.u32(), r.u8(), r.u64(), r.array::<64>())
        else {
            return;
        };
        let (Ok(()), Some(kind)) = (r.finish(), SignalKind::from_u8(kind)) else {
            return;
        };
        if leaf == c.group.own_leaf_index().u32() || sent_at_ms.abs_diff(now_ms) > SIGNAL_SKEW_MS {
            return;
        }
        let Some(member) = c.group.member_at(LeafNodeIndex::new(leaf)) else {
            return;
        };
        let signed = signal_signed_bytes(&route, epoch, leaf, kind, sent_at_ms);
        let verified = signed_by(&member.signature_key, &signed, &signature);
        let Some(cert) = tree_cert(&member.credential).filter(|_| verified) else {
            return;
        };
        if self.blocked.contains(&cert.identity) {
            return;
        }
        let last = self.last_signal.entry((route, leaf)).or_insert(0);
        if sent_at_ms <= *last {
            return;
        }
        *last = sent_at_ms;
        self.effects.push(Effect::Event(Event::Signal {
            conversation: route,
            from: cert.identity,
            device: cert.device,
            kind,
        }));
    }

    /// Proof for the mailbox that this device, a member, may obtain call
    /// relay credentials for the conversation. Stale after a commit, like
    /// [`Client::file_auth`].
    pub fn turn_auth(&mut self, conversation: Route) -> Result<TurnGrant, Error> {
        let c = self
            .conversations
            .get_mut(&conversation)
            .ok_or(Error::UnknownConversation)?;
        if !c.active || c.group.epoch().as_u64() == 0 {
            return Err(Error::Inactive);
        }
        let key = c.write_key(&self.provider, &conversation);
        Ok(TurnGrant {
            epoch: c.group.epoch().as_u64(),
            auth: turn_tag(&key, &conversation),
        })
    }

    fn queue(
        &mut self,
        now_ms: u64,
        conversation: Route,
        content: Content,
    ) -> Result<(u64, Step), Error> {
        let c = self
            .conversations
            .get_mut(&conversation)
            .ok_or(Error::UnknownConversation)?;
        if !c.active {
            return Err(Error::Inactive);
        }
        // One read receipt waits at a time: a newer one replaces it.
        if matches!(content, Content::Receipt(_))
            && let Some(o) = c
                .outbox
                .iter_mut()
                .find(|o| o.sealed.is_none() && matches!(o.content, Content::Receipt(_)))
        {
            o.content = content;
            o.sent_at_ms = now_ms;
            let sender_seq = o.sender_seq;
            self.dirty_outbox.insert((conversation, sender_seq));
            self.pump(now_ms);
            return Ok((sender_seq, self.finish()));
        }
        if c.outbox.len() >= OUTBOX_MAX {
            return Err(Error::OutboxFull);
        }
        let sender_seq = c.next_sender_seq;
        c.next_sender_seq += 1;
        let expires_after_s = if content.disappears() { c.timer() } else { 0 };
        c.outbox.push_back(Outgoing {
            sender_seq,
            sent_at_ms: now_ms,
            expires_after_s,
            content,
            sealed: None,
        });
        self.dirty_conversations.insert(conversation);
        self.dirty_outbox.insert((conversation, sender_seq));
        self.pump(now_ms);
        Ok((sender_seq, self.finish()))
    }

    /// Handles a frame from the mailbox: a response, or a pushed `Notify`.
    pub fn receive(&mut self, now_ms: u64, bytes: &[u8]) -> Step {
        if let Ok(frame) = frame::decode(bytes) {
            match frame.kind {
                Kind::Accepted | Kind::Rejected | Kind::Entries | Kind::KeyPackage => {
                    if let Some(inflight) = self.inflight.remove(&frame.seq) {
                        self.on_response(now_ms, inflight.request, frame.kind, frame.body);
                    }
                }
                Kind::Notify => self.on_notify(now_ms, frame.route, frame.body),
                Kind::Signaled => self.on_signal(now_ms, frame.route, frame.body),
                _ => {}
            }
        }
        self.pump(now_ms);
        self.finish()
    }

    /// Retries timed-out requests and polls for new log entries.
    pub fn tick(&mut self, now_ms: u64) -> Step {
        for inflight in self.inflight.values_mut() {
            if inflight.deadline_ms <= now_ms {
                inflight.attempts += 1;
                let backoff = self.config.request_timeout_ms << inflight.attempts.min(4);
                inflight.deadline_ms = now_ms + backoff;
                self.effects.push(Effect::Mailbox(inflight.frame.clone()));
            }
        }
        if self
            .last_poll_ms
            .is_none_or(|last| now_ms >= last + self.config.poll_interval_ms)
        {
            self.poll(now_ms);
        }
        self.pump(now_ms);
        self.finish()
    }

    fn poll(&mut self, now_ms: u64) {
        self.last_poll_ms = Some(now_ms);
        self.request(now_ms, Request::FetchInbox);
        let active: Vec<Route> = self
            .conversations
            .iter()
            .filter(|(_, c)| c.active)
            .map(|(id, _)| *id)
            .collect();
        for id in active {
            self.request(now_ms, Request::Fetch(id));
        }
        let requests: Vec<Route> = self.requests.keys().copied().collect();
        for route in requests {
            self.request(now_ms, Request::FetchRequests(route));
        }
    }

    fn credential(&self) -> CredentialWithKey {
        CredentialWithKey {
            credential: BasicCredential::new(self.cert.encode()).into(),
            signature_key: self.signer.public().into(),
        }
    }

    /// Sends a request unless an identical one is already in flight or the
    /// in-flight table is full (the pump will try again later).
    fn request(&mut self, now_ms: u64, request: Request) -> bool {
        if self.inflight.values().any(|i| i.request == request)
            || self.inflight.len() >= INFLIGHT_MAX
        {
            return false;
        }
        let (kind, route, body) = match &request {
            Request::FetchInbox => (
                Kind::Fetch,
                self.cert.inbox,
                Fetch {
                    after: self.inbox_cursor,
                    max: FETCH_ENTRIES_MAX,
                }
                .encode(),
            ),
            Request::OpenRequests(route) => {
                let log = &self.requests[route];
                let name = group_settings(&self.conversations[&log.conversation].group).name;
                (
                    Kind::OpenRequests,
                    *route,
                    log.keys.open_body(self.provider.rand(), &name),
                )
            }
            Request::FetchRequests(route) => (
                Kind::Fetch,
                *route,
                Fetch {
                    after: self.requests[route].cursor,
                    max: FETCH_ENTRIES_MAX,
                }
                .encode(),
            ),
            Request::Fetch(id) => {
                let cursor = self.conversations[id].cursor;
                (
                    Kind::Fetch,
                    *id,
                    Fetch {
                        after: cursor,
                        max: FETCH_ENTRIES_MAX,
                    }
                    .encode(),
                )
            }
            Request::Submit { conversation, hash } => {
                let c = &self.conversations[conversation];
                let body = if let Some(p) = c.pending.as_ref().filter(|p| p.hash == *hash) {
                    let welcomes = p
                        .welcomes
                        .iter()
                        .map(|(inbox, welcome)| WelcomeFor {
                            inbox: *inbox,
                            welcome,
                        })
                        .collect();
                    Submit {
                        message: &p.message,
                        welcomes,
                        auth: p.auth,
                        next_key: Some(p.next_key),
                        creation: p.creation,
                        quiet: false,
                    }
                    .encode()
                } else {
                    let outgoing = c
                        .outbox
                        .iter()
                        .find(|o| o.sealed.as_ref().is_some_and(|s| s.hash == *hash))
                        .expect("submitting a message that is not in the outbox");
                    let sealed = outgoing.sealed.as_ref().expect("found sealed");
                    Submit {
                        message: &sealed.message,
                        welcomes: Vec::new(),
                        auth: sealed.auth,
                        next_key: None,
                        creation: None,
                        quiet: !outgoing.content.wakes(),
                    }
                    .encode()
                };
                (Kind::Submit, *conversation, body)
            }
            Request::Claim { inbox, .. } => (Kind::ClaimKeyPackage, *inbox, Vec::new()),
            Request::Watch {
                route,
                target,
                enable,
            } => {
                let target = PushTarget {
                    platform: target.0,
                    address: &target.1,
                };
                let signed = Watch::signed_bytes(route, *enable, &target);
                // An inbox proves ownership; a conversation proves membership.
                let proof: Vec<u8> = match self.conversations.get(route) {
                    Some(c) => {
                        watch_tag(&write_key(&c.group, &self.provider, route), &signed).to_vec()
                    }
                    None => self.identity.sign(&signed).to_vec(),
                };
                (
                    Kind::Watch,
                    *route,
                    Watch {
                        enable: *enable,
                        target,
                        proof: &proof,
                    }
                    .encode(),
                )
            }
            Request::Publish { count, last_resort } => {
                let mut packages = Vec::with_capacity(*count + 1);
                for i in 0..*count + usize::from(*last_resort) {
                    match self.new_key_package(i == *count) {
                        Ok(kp) => packages.push(kp),
                        Err(_) => return false,
                    }
                }
                let list = packages.iter().map(Vec::as_slice).collect();
                (
                    Kind::PublishKeyPackages,
                    self.cert.inbox,
                    KeyPackages { list }.encode(),
                )
            }
        };
        let id = self.next_request;
        self.next_request = self.next_request.wrapping_add(1);
        let frame = frame::encode_vec(kind, id, route, &body);
        self.effects.push(Effect::Mailbox(frame.clone()));
        let deadline_ms = now_ms + self.config.request_timeout_ms;
        self.inflight.insert(
            id,
            Inflight {
                request,
                frame,
                deadline_ms,
                attempts: 0,
            },
        );
        true
    }

    fn new_key_package(&self, last_resort: bool) -> Result<Vec<u8>, Error> {
        let builder = KeyPackage::builder().leaf_node_capabilities(capabilities());
        let builder = if last_resort {
            builder.mark_as_last_resort()
        } else {
            builder
        };
        let bundle = builder
            .build(CIPHERSUITE, &self.provider, &self.signer, self.credential())
            .map_err(mls_error)?;
        let bytes = bundle
            .key_package()
            .tls_serialize_detached()
            .map_err(mls_error)?;
        assert!(bytes.len() <= MLS_MESSAGE_MAX);
        Ok(bytes)
    }

    /// Moves every conversation forward as far as it can go right now.
    fn pump(&mut self, now_ms: u64) {
        if now_ms >= self.key_packages_refreshed_ms + KEY_PACKAGE_REFRESH_MS {
            // Replace the published set before the mailbox's copies expire.
            self.key_packages_refreshed_ms = now_ms;
            self.key_packages_owed = self.config.key_packages;
            self.last_resort_owed = true;
            self.dirty_self = true;
        }
        if let Some(target) = self.push_target.clone() {
            let routes = self.routes();
            // Logs this device no longer follows need no renewal.
            let stale: Vec<Route> = self
                .watched
                .keys()
                .filter(|r| !routes.contains(r))
                .copied()
                .collect();
            for route in stale {
                self.watched.remove(&route);
                self.dirty_watched.insert(route);
            }
            let publishing = self.key_packages_owed > 0 || self.last_resort_owed;
            let lapsed: Vec<Route> = self
                .muted
                .iter()
                .filter(|(_, until)| **until <= now_ms)
                .map(|(route, _)| *route)
                .collect();
            for route in lapsed {
                self.muted.remove(&route);
                self.dirty_muted.insert(route);
            }
            for route in routes {
                // The mailbox learns who owns an inbox from its key packages
                // and refuses to register anyone else for it, so a new
                // device's registration must wait for its first publish.
                if (route == self.cert.inbox && publishing) || self.requests.contains_key(&route) {
                    continue;
                }
                // Muted: withdraw the registration (until the mailbox says it
                // is gone), and make none.
                if self.muted.contains_key(&route) {
                    if self.watched.contains_key(&route) {
                        self.request(
                            now_ms,
                            Request::Watch {
                                route,
                                target: target.clone(),
                                enable: false,
                            },
                        );
                    }
                    continue;
                }
                let due = self.watch_retry.get(&route).or(self.watched.get(&route));
                if due.is_none_or(|due| now_ms >= *due) {
                    let request = Request::Watch {
                        route,
                        target: target.clone(),
                        enable: true,
                    };
                    if self.request(now_ms, request) {
                        self.watch_retry.insert(route, now_ms + WATCH_RETRY_MS);
                    }
                }
            }
        }
        self.follow_requests(now_ms);
        let lapsed: Vec<[u8; 16]> = self
            .pending_joins
            .iter()
            .filter(|(_, p)| now_ms >= p.at_ms + PENDING_JOIN_MS)
            .map(|(join, _)| *join)
            .collect();
        for join in lapsed {
            if let Some(pending) = self.pending_joins.remove(&join)
                && let Ok(key_package_ref) =
                    openmls::prelude::KeyPackageRef::tls_deserialize_exact(&pending.key_package_ref)
            {
                // Its one-time key package goes too: an old request can
                // never add this device later.
                let _ = openmls_traits::storage::StorageProvider::delete_key_package(
                    self.provider.storage(),
                    &key_package_ref,
                );
            }
            self.dirty_joins.insert(join);
        }
        if self.key_packages_owed > 0 || self.last_resort_owed {
            let count = self.key_packages_owed.min(KEY_PACKAGES_MAX - 1);
            let last_resort = self.last_resort_owed;
            if !self
                .inflight
                .values()
                .any(|i| matches!(i.request, Request::Publish { .. }))
            {
                self.request(now_ms, Request::Publish { count, last_resort });
            }
        }

        let ids: Vec<Route> = self.conversations.keys().copied().collect();
        for id in ids {
            if !self.conversations[&id].active {
                continue;
            }
            self.add_siblings(now_ms, id);
            self.pump_commit(now_ms, id);
            self.pump_outbox(now_ms, id);
        }
    }

    /// Adds this identity's other devices to a conversation that lacks them.
    fn add_siblings(&mut self, now_ms: u64, id: Route) {
        if self.siblings.is_empty() {
            return;
        }
        let c = &self.conversations[&id];
        if c.group.epoch().as_u64() == 0 || !c.caught_up {
            return;
        }
        let present = self.member_inboxes(&id);
        let c = &self.conversations[&id];
        let missing: Vec<ContactCard> = self
            .siblings
            .values()
            .filter(|card| !present.contains(&card.inbox))
            .filter(|card| !self.unlinked.contains(&card.inbox))
            .filter(|card| {
                !c.intents.iter().any(
                    |i| matches!(i, Intent::Add { contact, .. } if contact.inbox == card.inbox),
                )
            })
            .filter(|card| {
                self.sibling_retry
                    .get(&(id, card.inbox))
                    .is_none_or(|due| now_ms >= *due)
            })
            .copied()
            .collect();
        for card in missing {
            self.sibling_retry
                .insert((id, card.inbox), now_ms + SIBLING_RETRY_MS);
            let c = self.conversations.get_mut(&id).expect("exists");
            c.intents.push_back(Intent::Add {
                contact: card,
                key_package: None,
            });
            self.dirty_conversations.insert(id);
        }
    }

    fn pump_commit(&mut self, now_ms: u64, id: Route) {
        let c = &self.conversations[&id];
        if let Some(pending) = &c.pending {
            let hash = pending.hash;
            self.request(
                now_ms,
                Request::Submit {
                    conversation: id,
                    hash,
                },
            );
            return;
        }
        if !c.caught_up || c.group.pending_commit().is_some() {
            return;
        }
        let Some(mut intent) = c.intents.front().cloned() else {
            return;
        };
        // Stepping down becomes the rules it leaves, worked out anew each
        // time the commit is built (a commit that lost its epoch is built
        // again from the group as it is then, never from an old snapshot).
        if matches!(intent, Intent::StepDown) {
            match self.step_down_rules(&id) {
                Some(rules) => intent = Intent::Policy(rules),
                None => {
                    let c = self.conversations.get_mut(&id).expect("exists");
                    c.intents.pop_front();
                    self.dirty_conversations.insert(id);
                    return;
                }
            }
        }

        // Membership intents are idempotent: someone else may already have
        // made the change (two members inviting the same person at once).
        let already = match &intent {
            Intent::Add { contact, .. } => self.member_inboxes(&id).contains(&contact.inbox),
            Intent::Remove { identity } => !self.members(&id).contains(identity),
            Intent::RemoveDevice { inbox } => !self.member_inboxes(&id).contains(inbox),
            Intent::Update => false,
            Intent::Timer(seconds) => group_timer(&self.conversations[&id].group) == *seconds,
            Intent::Rename(name) => group_settings(&self.conversations[&id].group).name == *name,
            Intent::Policy(policy) => group_policy(&self.conversations[&id].group)
                .is_ok_and(|p| p.as_ref() == Some(policy)),
            Intent::StepDown => unreachable!("turned into rules above"),
        };
        if already {
            let c = self.conversations.get_mut(&id).expect("exists");
            c.intents.pop_front();
            self.dirty_conversations.insert(id);
            return;
        }
        // Only an admin removes an admin (one who leaves steps down first,
        // so this is only an old client leaving): anyone else leaves it to
        // them, quietly.
        if let Intent::Remove { identity } = &intent
            && !self.config.break_rules
        {
            let group = &self.conversations[&id].group;
            let admins = effective_admins(group);
            let me = self.identity.public();
            if group_policy(group).is_ok_and(|p| p.is_some())
                && admins.contains(identity)
                && *identity != me
                && !admins.contains(&me)
            {
                let c = self.conversations.get_mut(&id).expect("exists");
                c.intents.pop_front();
                self.dirty_conversations.insert(id);
                return;
            }
        }
        // This device never breaks the group's rules (a demotion may have
        // landed since the intent was queued).
        if let Err(reason) = self.permitted(&id, &intent)
            && !self.config.break_rules
        {
            let c = self.conversations.get_mut(&id).expect("exists");
            c.intents.pop_front();
            self.dirty_conversations.insert(id);
            self.effects.push(Effect::Event(Event::Refused {
                conversation: id,
                reason: reason.to_owned(),
            }));
            return;
        }
        // Messages about a fuller group might not fit in a frame.
        if let Intent::Add { contact, .. } = &intent
            && self.conversations[&id].group.members().count() >= GROUP_MEMBERS_MAX
        {
            self.fail_invite(id, contact.identity);
            return;
        }

        let built = match intent {
            Intent::Add {
                contact,
                key_package: None,
            } => {
                self.request(
                    now_ms,
                    Request::Claim {
                        conversation: id,
                        inbox: contact.inbox,
                    },
                );
                return;
            }
            Intent::Add {
                contact,
                key_package: Some(bytes),
            } => {
                let key_package = KeyPackageIn::tls_deserialize_exact(&bytes)
                    .map_err(mls_error)
                    .and_then(|kp| {
                        kp.validate(self.provider.crypto(), ProtocolVersion::Mls10)
                            .map_err(mls_error)
                    });
                let Ok(key_package) = key_package else {
                    self.fail_invite(id, contact.identity);
                    return;
                };
                let c = self.conversations.get_mut(&id).expect("exists");
                // A key package this group cannot take (say, from a device
                // too old to support every required extension) fails the
                // invitation, not the conversation.
                let Ok((commit, welcome, _)) =
                    c.group
                        .add_members(&self.provider, &self.signer, &[key_package])
                else {
                    self.fail_invite(id, contact.identity);
                    return;
                };
                Ok((
                    serialize(&commit),
                    vec![(contact.inbox, serialize(&welcome))],
                ))
            }
            Intent::Remove { identity } => {
                let c = &self.conversations[&id];
                let leaves: Vec<LeafNodeIndex> = c
                    .group
                    .members()
                    .filter(|m| {
                        tree_cert(&m.credential).is_some_and(|cert| cert.identity == identity)
                    })
                    .map(|m| m.index)
                    .collect();
                let c = self.conversations.get_mut(&id).expect("exists");
                c.group
                    .remove_members(&self.provider, &self.signer, &leaves)
                    .map_err(mls_error)
                    .map(|(commit, _, _)| (serialize(&commit), Vec::new()))
            }
            Intent::RemoveDevice { inbox } => {
                let c = &self.conversations[&id];
                let leaves: Vec<LeafNodeIndex> = c
                    .group
                    .members()
                    .filter(|m| tree_cert(&m.credential).is_some_and(|cert| cert.inbox == inbox))
                    .map(|m| m.index)
                    .collect();
                let c = self.conversations.get_mut(&id).expect("exists");
                c.group
                    .remove_members(&self.provider, &self.signer, &leaves)
                    .map_err(mls_error)
                    .map(|(commit, _, _)| (serialize(&commit), Vec::new()))
            }
            Intent::Update => {
                // Each update also advertises what this version supports.
                let leaf = LeafNodeParameters::builder()
                    .with_capabilities(capabilities())
                    .build();
                let c = self.conversations.get_mut(&id).expect("exists");
                c.group
                    .self_update(&self.provider, &self.signer, leaf)
                    .map_err(mls_error)
                    .map(|bundle| (serialize(&bundle.into_messages().0), Vec::new()))
            }
            Intent::StepDown => unreachable!("turned into rules above"),
            Intent::Timer(_) | Intent::Rename(_) | Intent::Policy(_) => {
                let c = self.conversations.get_mut(&id).expect("exists");
                let mut settings = group_settings(&c.group);
                let mut policy = group_policy(&c.group).ok().flatten();
                match intent {
                    Intent::Timer(seconds) => settings.timer = seconds,
                    Intent::Rename(name) => settings.name = name,
                    Intent::Policy(next) => policy = Some(next),
                    _ => unreachable!("matched above"),
                }
                match c.group.update_group_context_extensions(
                    &self.provider,
                    group_context(&settings, policy.as_ref()),
                    &self.signer,
                ) {
                    Ok((commit, _, _)) => Ok((serialize(&commit), Vec::new())),
                    // A member whose version does not support the settings:
                    // nothing is committed, and they stay as they were.
                    Err(e) => {
                        c.intents.pop_front();
                        self.dirty_conversations.insert(id);
                        self.effects.push(Effect::Event(Event::TimerRefused {
                            conversation: id,
                            reason: format!("{e:?}"),
                        }));
                        return;
                    }
                }
            }
        };
        // The checks every member runs on it: a commit they would refuse
        // (say, adding a device whose id a member's device has) is never
        // sent, or this device would carry on alone in an epoch nobody else
        // could join.
        let refusal = match &built {
            Ok(_) if !self.config.break_rules => {
                let c = &self.conversations[&id];
                c.group.pending_commit().and_then(|staged| {
                    check_commit(&c.group, staged, c.group.own_leaf_index()).err()
                })
            }
            _ => None,
        };
        match built {
            Ok(_) if refusal.is_some() => {
                let c = self.conversations.get_mut(&id).expect("exists");
                c.group
                    .clear_pending_commit(self.provider.storage())
                    .expect("storage is in memory");
                match c.intents.front() {
                    Some(Intent::Add { contact, .. }) => {
                        let identity = contact.identity;
                        self.fail_invite(id, identity);
                    }
                    _ => {
                        c.intents.pop_front();
                        self.dirty_conversations.insert(id);
                    }
                }
                self.effects.push(Effect::Event(Event::Refused {
                    conversation: id,
                    reason: format!("{RULES_BROKEN}{}", refusal.unwrap_or_default()),
                }));
            }
            Ok((message, welcomes)) if !fits_in_frame(&message, &welcomes) => {
                // Only a pathological tree makes a commit and its welcome
                // outgrow a frame. Drop the change rather than keep a
                // submission that can never be sent.
                let c = self.conversations.get_mut(&id).expect("exists");
                c.group
                    .clear_pending_commit(self.provider.storage())
                    .expect("storage is in memory");
                match c.intents.front() {
                    Some(Intent::Add { contact, .. }) => {
                        let identity = contact.identity;
                        self.fail_invite(id, identity);
                    }
                    _ => {
                        c.intents.pop_front();
                        self.dirty_conversations.insert(id);
                    }
                }
            }
            Ok((message, welcomes)) => {
                assert!(welcomes.len() <= WELCOMES_PER_SUBMIT_MAX);
                let hash = hash16(&message);
                let c = self.conversations.get_mut(&id).expect("exists");
                let auth = write_tag(&write_key(&c.group, &self.provider, &id), &id, &message);
                let next_key = c
                    .group
                    .pending_commit()
                    .expect("a commit was just built")
                    .export_secret(self.provider.crypto(), WRITE_KEY_LABEL, &id, 32)
                    .expect("exporting from the next epoch")
                    .try_into()
                    .expect("32 bytes");
                let creation = c
                    .creation_seed
                    .filter(|_| c.group.epoch().as_u64() == 0)
                    .map(|seed| {
                        let key = ed25519_dalek::SigningKey::from_bytes(&seed);
                        let signed = creation_signed_bytes(&id, &message);
                        let signature = ed25519_dalek::Signer::sign(&key, &signed).to_bytes();
                        (key.verifying_key().to_bytes(), signature)
                    });
                c.pending = Some(Pending {
                    message,
                    welcomes,
                    hash,
                    auth,
                    next_key,
                    creation,
                });
                self.dirty_conversations.insert(id);
                self.request(
                    now_ms,
                    Request::Submit {
                        conversation: id,
                        hash,
                    },
                );
            }
            Err(e) => self.desync(id, format!("building commit: {e}")),
        }
    }

    fn fail_invite(&mut self, id: Route, identity: IdentityKey) {
        let c = self.conversations.get_mut(&id).expect("exists");
        c.intents.pop_front();
        self.dirty_conversations.insert(id);
        // Adding one of this identity's own devices is retried quietly.
        if identity == self.identity.public() {
            return;
        }
        self.effects.push(Effect::Event(Event::InviteFailed {
            conversation: id,
            identity,
        }));
    }

    fn pump_outbox(&mut self, now_ms: u64, id: Route) {
        let c = self.conversations.get_mut(&id).expect("exists");
        // A group at epoch 0 has nobody to talk to and no log yet; a group
        // with a pending commit cannot encrypt until the commit resolves; and
        // encrypting before catching up with the log risks a stale epoch the
        // mailbox will refuse, wasting ratchet generations.
        let can_seal = c.group.epoch().as_u64() > 0
            && c.group.pending_commit().is_none()
            && c.pending.is_none()
            && c.caught_up;
        let window_end = c.outbox.front().map_or(0, |o| o.sender_seq + SUBMIT_WINDOW);
        let mut to_submit = Vec::new();
        let mut recipients = None;
        for i in 0..c.outbox.len() {
            if c.outbox[i].sender_seq >= window_end {
                break;
            }
            if c.outbox[i].sealed.is_none() {
                if !can_seal {
                    break;
                }
                let outgoing = &c.outbox[i];
                let plaintext = outgoing.content.with_body(|body| {
                    AppMessage {
                        sender_seq: outgoing.sender_seq,
                        sent_at_ms: outgoing.sent_at_ms,
                        expires_after_s: outgoing.expires_after_s,
                        body,
                    }
                    .encode()
                });
                let message = match c
                    .group
                    .create_message(&self.provider, &self.signer, &plaintext)
                {
                    Ok(message) => serialize(&message),
                    Err(e) => {
                        self.desync(id, format!("encrypting: {e:?}"));
                        return;
                    }
                };
                let hash = hash16(&message);
                let recipients: &Vec<IdentityKey> = recipients.get_or_insert_with(|| {
                    c.group
                        .members()
                        .filter_map(|m| tree_cert(&m.credential))
                        .filter(|cert| cert.device != self.cert.device)
                        .map(|cert| cert.identity)
                        .collect()
                });
                self.effects.push(Effect::Event(Event::Sealed {
                    conversation: id,
                    sender_seq: c.outbox[i].sender_seq,
                    recipients: recipients.clone(),
                    epoch: c.group.epoch().as_u64(),
                }));
                let auth = write_tag(&c.write_key(&self.provider, &id), &id, &message);
                c.outbox[i].sealed = Some(Sealed {
                    message,
                    hash,
                    auth,
                });
                self.dirty_outbox.insert((id, c.outbox[i].sender_seq));
            }
            to_submit.push(c.outbox[i].sealed.as_ref().expect("sealed above").hash);
        }
        for hash in to_submit {
            self.request(
                now_ms,
                Request::Submit {
                    conversation: id,
                    hash,
                },
            );
        }
    }

    fn on_response(&mut self, now_ms: u64, request: Request, kind: Kind, body: &[u8]) {
        match (request, kind) {
            (Request::OpenRequests(route), Kind::Accepted) => {
                if let Some(log) = self.requests.get_mut(&route) {
                    log.opened =
                        Some(group_settings(&self.conversations[&log.conversation].group).name);
                }
            }
            (Request::OpenRequests(route), Kind::Rejected) => {
                // Someone else opened this route first: the link cannot work.
                if let Some(log) = self.requests.get_mut(&route) {
                    log.opened =
                        Some(group_settings(&self.conversations[&log.conversation].group).name);
                    let conversation = log.conversation;
                    self.effects.push(Effect::Event(Event::Refused {
                        conversation,
                        reason: "the invite link could not be set up; reset it".to_owned(),
                    }));
                }
            }
            (Request::FetchRequests(route), Kind::Entries) => {
                if let Ok(entries) = Entries::decode(body) {
                    self.apply_requests(now_ms, route, &entries);
                }
            }
            (Request::FetchInbox, Kind::Entries) => {
                if let Ok(entries) = Entries::decode(body) {
                    self.apply_inbox_entries(now_ms, &entries);
                }
            }
            (Request::Fetch(id), Kind::Entries) => {
                let Ok(entries) = Entries::decode(body) else {
                    return;
                };
                if let Some(gap) = self.apply_log_entries(now_ms, id, &entries) {
                    self.desync(id, format!("log gap: expected {} got {}", gap.0, gap.1));
                }
            }
            (
                Request::Watch {
                    route,
                    enable: true,
                    ..
                },
                Kind::Accepted,
            ) => {
                self.watch_retry.remove(&route);
                self.watched.insert(route, now_ms + WATCH_REFRESH_MS);
                self.dirty_watched.insert(route);
            }
            // A muted conversation's registration is gone.
            (
                Request::Watch {
                    route,
                    target,
                    enable: false,
                },
                Kind::Accepted,
            ) if self.muted.contains_key(&route) && self.push_target.as_ref() == Some(&target) => {
                if self.watched.remove(&route).is_some() {
                    self.dirty_watched.insert(route);
                }
            }
            (Request::Fetch(id), Kind::Rejected) => {
                if let Ok(Rejected {
                    reason: Reject::Evicted,
                    ..
                }) = Rejected::decode(body)
                {
                    self.desync(id, "fell behind the mailbox's retention".to_owned());
                }
            }
            (Request::Submit { conversation, hash }, Kind::Accepted) => {
                if Accepted::decode(body).is_err() {
                    return;
                }
                let Some(c) = self.conversations.get_mut(&conversation) else {
                    return;
                };
                if let Some(pos) = c
                    .outbox
                    .iter()
                    .position(|o| o.sealed.as_ref().is_some_and(|s| s.hash == hash))
                {
                    let done = c.outbox.remove(pos).expect("position is valid");
                    self.dirty_outbox.insert((conversation, done.sender_seq));
                    self.effects.push(Effect::Event(Event::Sent {
                        conversation,
                        sender_seq: done.sender_seq,
                    }));
                }
                // Our commit is in the log: read up to it and merge it there.
                self.request(now_ms, Request::Fetch(conversation));
            }
            (Request::Submit { conversation, hash }, Kind::Rejected) => {
                let Ok(rejected) = Rejected::decode(body) else {
                    return;
                };
                self.on_rejected(now_ms, conversation, hash, rejected.reason);
            }
            (
                Request::Claim {
                    conversation,
                    inbox,
                },
                Kind::KeyPackage,
            ) => {
                self.on_key_package(conversation, inbox, body);
            }
            (Request::Claim { .. }, Kind::Rejected) => {
                // No key packages right now; the next poll's pump retries.
            }
            (Request::Publish { count, last_resort }, Kind::Accepted) => {
                self.key_packages_owed = self.key_packages_owed.saturating_sub(count);
                self.last_resort_owed &= !last_resort;
                self.dirty_self = true;
            }
            _ => {}
        }
    }

    fn apply_inbox_entries(&mut self, now_ms: u64, entries: &Entries<'_>) {
        for entry in &entries.entries {
            if entry.seq <= self.inbox_cursor {
                continue;
            }
            self.on_inbox_entry(now_ms, entry.data);
            self.inbox_cursor = entry.seq;
            self.dirty_self = true;
        }
        if entries.next > self.inbox_cursor + 1 {
            self.request(now_ms, Request::FetchInbox);
        }
    }

    /// Processes a run of log entries in order. Returns `(expected, got)` if
    /// the run skips over entries this device has not seen.
    fn apply_log_entries(
        &mut self,
        now_ms: u64,
        id: Route,
        entries: &Entries<'_>,
    ) -> Option<(u64, u64)> {
        if !self.conversations.get(&id).is_some_and(|c| c.active) {
            return None;
        }
        for entry in &entries.entries {
            let c = self.conversations.get_mut(&id).expect("checked above");
            if entry.seq <= c.cursor {
                continue;
            }
            let expected = c.cursor + 1;
            if entry.seq != expected {
                return Some((expected, entry.seq));
            }
            self.on_log_entry(id, entry.data);
            let c = self
                .conversations
                .get_mut(&id)
                .expect("conversations are never deleted");
            c.cursor = entry.seq;
            self.dirty_conversations.insert(id);
            if !c.active {
                return None;
            }
        }
        let c = self.conversations.get_mut(&id).expect("exists");
        c.caught_up = entries.next == c.cursor + 1;
        if !c.caught_up {
            self.request(now_ms, Request::Fetch(id));
        }
        None
    }

    /// A push from the mailbox: new entries in a followed log, usually with
    /// the entries themselves. Applied at once when they continue where this
    /// device is; otherwise it fetches.
    fn on_notify(&mut self, now_ms: u64, route: Route, body: &[u8]) {
        let Ok(entries) = Entries::decode(body) else {
            return;
        };
        if let Some(log) = self.requests.get(&route) {
            let contiguous = entries
                .entries
                .first()
                .is_some_and(|e| e.seq <= log.cursor + 1);
            if contiguous {
                self.apply_requests(now_ms, route, &entries);
            } else {
                self.request(now_ms, Request::FetchRequests(route));
            }
            return;
        }
        if route == self.cert.inbox {
            let contiguous = entries
                .entries
                .first()
                .is_some_and(|e| e.seq <= self.inbox_cursor + 1);
            if contiguous {
                self.apply_inbox_entries(now_ms, &entries);
            } else if entries.next > self.inbox_cursor + 1 {
                self.request(now_ms, Request::FetchInbox);
            }
            return;
        }
        let Some(c) = self.conversations.get(&route).filter(|c| c.active) else {
            return;
        };
        let contiguous = entries
            .entries
            .first()
            .is_some_and(|e| e.seq <= c.cursor + 1);
        if contiguous {
            // A gap inside a pushed run cannot happen; if it somehow did,
            // fetching recovers instead of giving up on the conversation.
            if self.apply_log_entries(now_ms, route, &entries).is_some() {
                self.request(now_ms, Request::Fetch(route));
            }
        } else if entries.next > c.cursor + 1 {
            self.request(now_ms, Request::Fetch(route));
        }
    }

    fn on_rejected(&mut self, now_ms: u64, id: Route, hash: Hash, reason: Reject) {
        let Some(c) = self.conversations.get_mut(&id) else {
            return;
        };
        if c.pending.as_ref().is_some_and(|p| p.hash == hash) {
            match reason {
                Reject::StaleEpoch | Reject::FutureEpoch => {
                    // Another member's commit won this epoch. Ours never
                    // happened: drop it, catch up, and the pump retries the
                    // intent on top of the new epoch.
                    if let Err(e) = c.group.clear_pending_commit(self.provider.storage()) {
                        self.desync(id, format!("clearing pending commit: {e:?}"));
                        return;
                    }
                    c.pending = None;
                    c.caught_up = false;
                    self.dirty_conversations.insert(id);
                    self.request(now_ms, Request::Fetch(id));
                }
                other => self.desync(id, format!("commit rejected: {other:?}")),
            }
            return;
        }
        let Some(pos) = c
            .outbox
            .iter()
            .position(|o| o.sealed.as_ref().is_some_and(|s| s.hash == hash))
        else {
            return;
        };
        match reason {
            Reject::TooOld | Reject::FutureEpoch => {
                // A commit landed first. Re-encrypt in the new epoch once
                // caught up; the same sender_seq means it can never be
                // delivered twice.
                c.outbox[pos].sealed = None;
                c.caught_up = false;
                let seq = c.outbox[pos].sender_seq;
                self.dirty_outbox.insert((id, seq));
                self.request(now_ms, Request::Fetch(id));
            }
            other => self.desync(id, format!("message rejected: {other:?}")),
        }
    }

    fn on_key_package(&mut self, id: Route, inbox: Route, body: &[u8]) {
        let Some(c) = self.conversations.get_mut(&id) else {
            return;
        };
        let Some(Intent::Add {
            contact,
            key_package,
        }) = c.intents.front_mut()
        else {
            return;
        };
        // A late answer to a claim for an invite that has since resolved.
        if key_package.is_some() || contact.inbox != inbox {
            return;
        }
        let contact = *contact;
        let valid = KeyPackageIn::tls_deserialize_exact(body)
            .ok()
            .and_then(|kp| {
                kp.validate(self.provider.crypto(), ProtocolVersion::Mls10)
                    .ok()
            })
            .filter(|kp| kp.ciphersuite() == CIPHERSUITE)
            .and_then(|kp| {
                let leaf = kp.leaf_node();
                verify_credential(leaf.credential(), leaf.signature_key().as_slice())
            })
            .is_some_and(|cert| cert.identity == contact.identity && cert.inbox == contact.inbox);
        if !valid {
            // The mailbox handed out a key package that is not the contact's.
            self.fail_invite(id, contact.identity);
            return;
        }
        *key_package = Some(body.to_vec());
        self.dirty_conversations.insert(id);
    }

    fn on_inbox_entry(&mut self, now_ms: u64, data: &[u8]) {
        let Ok(entry) = InboxWelcome::decode(data) else {
            return;
        };
        // A device removed from a conversation, or one that forgot it, may be
        // invited back. It rejoins as a new member, and its numbering carries
        // on from where it was.
        let rejoining = match self.conversations.get(&entry.conversation) {
            Some(c) if c.active => return,
            Some(c) => Some(c.next_sender_seq),
            None => self.tombstones.get(&entry.conversation).copied(),
        };
        if !self.conversations.contains_key(&entry.conversation)
            && self.conversations.len() >= CONVERSATIONS_MAX
        {
            return;
        }
        let Ok(message) = MlsMessageIn::tls_deserialize_exact(entry.welcome) else {
            return;
        };
        let MlsMessageBodyIn::Welcome(welcome) = message.extract() else {
            return;
        };
        // OpenMLS keeps one state per group: the old one (this device was
        // removed, and only its history remains) makes way first, leaving a
        // tombstone in case this welcome fails and another comes.
        if let Some(mut old) = self.conversations.remove(&entry.conversation) {
            old.group
                .delete(self.provider.storage())
                .expect("storage is in memory");
            for outgoing in &old.outbox {
                self.dirty_outbox
                    .insert((entry.conversation, outgoing.sender_seq));
            }
            self.dirty_conversations.insert(entry.conversation);
            self.tombstones
                .insert(entry.conversation, old.next_sender_seq);
            self.dirty_tombstones.insert(entry.conversation);
        }
        // Every conversation this device joins is post-quantum.
        if welcome.ciphersuite() != CIPHERSUITE {
            self.effects.push(Effect::Event(Event::Undecryptable {
                conversation: entry.conversation,
                reason: format!("welcome: ciphersuite {:?}", welcome.ciphersuite()),
            }));
            return;
        }
        let staged =
            match StagedWelcome::new_from_welcome(&self.provider, &join_config(), welcome, None) {
                Ok(staged) => staged,
                Err(e) => {
                    // The inviter now believes we are a member, but we cannot
                    // join; they need to know so they can invite us again.
                    self.effects.push(Effect::Event(Event::Undecryptable {
                        conversation: entry.conversation,
                        reason: format!("welcome: {e:?}"),
                    }));
                    return;
                }
            };
        // One of our key packages was consumed; publish a replacement.
        self.key_packages_owed += 1;
        self.dirty_self = true;

        let mut members = Vec::new();
        let mut devices = BTreeSet::new();
        for member in staged.members() {
            match verify_credential(&member.credential, &member.signature_key) {
                // Device ids are unique in a group (messages are named by them).
                Some(cert) if devices.insert(cert.device) => members.push(cert.identity),
                _ => return,
            }
        }
        if members.iter().any(|m| self.blocked.contains(m)) {
            return;
        }
        // Every check comes before the group is stored, so a welcome that
        // fails one leaves nothing behind.
        if staged.group_context().group_id().as_slice() != entry.conversation {
            return;
        }
        let Ok(policy) = policy_in(staged.group_context().extensions()) else {
            return;
        };
        let Some(added_by) = staged
            .welcome_sender()
            .ok()
            .and_then(|leaf| tree_cert(leaf.credential()))
            .map(|cert| cert.identity)
        else {
            return;
        };
        // Invitations from people this device talks with always get in;
        // past a limit of conversations nobody here ever answered, others
        // are dropped, so a flood of them cannot crowd the real ones out.
        if !self.talks_with(&added_by) && self.unanswered() >= UNANSWERED_MAX {
            return;
        }
        // The answer to a request this device sent with the group's link:
        // the group's link is the one asked through, and this device joined
        // with the very key package the request carried.
        let via_link = policy
            .and_then(|p| p.link)
            .map(|seed| crate::join::join_of(&seed, &entry.conversation))
            .filter(|join| {
                self.pending_joins.get(join).is_some_and(|p| {
                    staged.own_leaf_node().is_some_and(|leaf| {
                        leaf.encryption_key()
                            .tls_serialize_detached()
                            .is_ok_and(|key| key == p.encryption_key)
                    })
                })
            });
        let Ok(group) = staged.into_group(&self.provider) else {
            return;
        };
        let epoch = group.epoch().as_u64();
        if let Some(join) = via_link {
            self.pending_joins.remove(&join);
            self.dirty_joins.insert(join);
        }
        let via_link = via_link.is_some();
        let mut c = Conversation::new(group, entry.join_after, VecDeque::new());
        // The log has likely moved past the commit that added us.
        c.caught_up = false;
        c.next_sender_seq = rejoining.unwrap_or(1);
        if self.tombstones.remove(&entry.conversation).is_some() {
            self.dirty_tombstones.insert(entry.conversation);
        }
        self.conversations.insert(entry.conversation, c);
        self.dirty_conversations.insert(entry.conversation);
        self.effects.push(Effect::Event(Event::Joined {
            conversation: entry.conversation,
            members,
            epoch,
            via_link,
            added_by,
        }));
        self.request(now_ms, Request::Fetch(entry.conversation));
    }

    fn on_log_entry(&mut self, id: Route, data: &[u8]) {
        let hash = hash16(data);
        let c = self.conversations.get_mut(&id).expect("exists");
        if c.seen_set.contains(&hash) {
            return;
        }
        let Some(protocol) = MlsMessageIn::tls_deserialize_exact(data)
            .ok()
            .and_then(|m| m.try_into_protocol_message().ok())
        else {
            return;
        };
        let is_commit = protocol.content_type() == ContentType::Commit;
        let processed = match c.group.process_message(&self.provider, protocol) {
            Ok(processed) => processed,
            Err(e) if is_commit => {
                self.desync(id, format!("processing commit: {e:?}"));
                return;
            }
            // An application message we cannot read (too old, or garbage from
            // a misbehaving member) is skipped, but never silently.
            Err(e) => {
                self.effects.push(Effect::Event(Event::Undecryptable {
                    conversation: id,
                    reason: format!("{e:?}"),
                }));
                return;
            }
        };
        let credential = processed.credential().clone();
        let committer = match processed.sender() {
            Sender::Member(leaf) => Some(*leaf),
            _ => None,
        };
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app) => {
                // It may come again (pushed and fetched); skip it cheaply.
                self.conversations
                    .get_mut(&id)
                    .expect("exists")
                    .remember(hash);
                self.deliver(id, &credential, &app.into_bytes())
            }
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                for add in staged.add_proposals() {
                    let leaf = add.add_proposal().key_package().leaf_node();
                    if verify_credential(leaf.credential(), leaf.signature_key().as_slice())
                        .is_none()
                    {
                        self.desync(
                            id,
                            "commit adds a member with an invalid certificate".to_owned(),
                        );
                        return;
                    }
                }
                let removed_self = staged.self_removed();
                let Some(by) = tree_cert(&credential).map(|cert| cert.identity) else {
                    self.desync(id, "commit from a member without a certificate".to_owned());
                    return;
                };
                // One of this identity's devices removing another of them is
                // an unlink: every device of the identity forgets it, so none
                // adds it back.
                let me = self.identity.public();
                let unlinked: Vec<Route> = if by == me {
                    let group = &self.conversations[&id].group;
                    staged
                        .remove_proposals()
                        .filter_map(|remove| group.member_at(remove.remove_proposal().removed()))
                        .filter_map(|member| tree_cert(&member.credential))
                        .filter(|cert| cert.identity == me && cert.inbox != self.cert.inbox)
                        .map(|cert| cert.inbox)
                        .collect()
                } else {
                    Vec::new()
                };
                for inbox in unlinked {
                    self.unlink(inbox);
                }
                let group = &self.conversations[&id].group;
                if let Err(reason) = committer
                    .ok_or("a commit from outside the group")
                    .and_then(|leaf| check_commit(group, &staged, leaf))
                {
                    self.desync(id, format!("{RULES_BROKEN}{reason}"));
                    return;
                }
                let before = self.state(&id);
                let c = self.conversations.get_mut(&id).expect("exists");
                if let Err(e) = c.group.merge_staged_commit(&self.provider, *staged) {
                    self.desync(id, format!("merging commit: {e:?}"));
                    return;
                }
                // A commit from someone else won the epoch, so ours (if any)
                // can never be accepted; its rejection is on its way.
                c.pending = None;
                self.after_commit(id, by, before, removed_self);
            }
            ProcessedMessageContent::OwnPrivateMessage => {
                let c = self.conversations.get_mut(&id).expect("exists");
                if c.pending.as_ref().is_some_and(|p| p.hash == hash) {
                    let before = self.state(&id);
                    let c = self.conversations.get_mut(&id).expect("exists");
                    if let Err(e) = c.group.merge_pending_commit(&self.provider) {
                        self.desync(id, format!("merging own commit: {e:?}"));
                        return;
                    }
                    c.pending = None;
                    c.intents.pop_front();
                    c.creation_seed = None;
                    self.after_commit(id, self.identity.public(), before, false);
                } else if let Some(pos) = c
                    .outbox
                    .iter()
                    .position(|o| o.sealed.as_ref().is_some_and(|s| s.hash == hash))
                {
                    // Our message reached the log but the acknowledgement was
                    // lost; the log is just as good.
                    let done = c.outbox.remove(pos).expect("position is valid");
                    self.dirty_outbox.insert((id, done.sender_seq));
                    self.effects.push(Effect::Event(Event::Sent {
                        conversation: id,
                        sender_seq: done.sender_seq,
                    }));
                }
            }
            _ => {}
        }
    }

    /// What a commit may change that `after_commit` reports.
    fn state(&self, id: &Route) -> Before {
        let group = &self.conversations[id].group;
        Before {
            members: self.members(id),
            settings: group_settings(group),
            admins: effective_admins(group),
            policy: group_policy(group).ok().flatten(),
        }
    }

    /// After merging a commit by `by`: reports who joined and left, and a
    /// new timer.
    fn after_commit(&mut self, id: Route, by: IdentityKey, before: Before, removed_self: bool) {
        // Duplicate windows only for devices still in the group: no past
        // epochs are kept, so nothing a removed device sent can arrive any
        // more, and devices that come and go cannot pile windows up.
        let devices = member_devices(&self.conversations[&id].group);
        let c = self.conversations.get_mut(&id).expect("exists");
        let before_windows = c.windows.len();
        c.windows.retain(|device, _| devices.contains(device));
        if c.windows.len() != before_windows {
            self.dirty_conversations.insert(id);
        }
        let Before {
            members: before,
            settings: settings_before,
            admins: admins_before,
            policy: policy_before,
        } = before;
        let group = &self.conversations[&id].group;
        let settings = group_settings(group);
        let (admins, policy) = (effective_admins(group), group_policy(group).ok().flatten());
        let who = |p: &Option<Policy>| {
            p.as_ref()
                .map_or((Who::Everyone, Who::Everyone), |p| (p.add, p.edit))
        };
        let (add_before, edit_before) = who(&policy_before);
        let (add, edit) = who(&policy);
        let seed = |p: &Option<Policy>| p.as_ref().and_then(|p| p.link);
        let link = match (seed(&policy_before), seed(&policy)) {
            (None, Some(_)) => Some(LinkChange::On),
            (Some(before), Some(after)) if before != after => Some(LinkChange::Reset),
            (Some(_), None) => Some(LinkChange::Off),
            _ => None,
        };
        let admins_added: Vec<_> = admins
            .iter()
            .filter(|a| !admins_before.contains(a))
            .copied()
            .collect();
        let admins_removed: Vec<_> = admins_before
            .iter()
            .filter(|a| !admins.contains(a) && self.members(&id).contains(a))
            .copied()
            .collect();
        // A group from before admins getting its first rules changes nothing
        // anyone sees but what the rules say.
        let first = policy_before.is_none();
        if !removed_self
            && (add != add_before
                || edit != edit_before
                || link.is_some()
                || (!first && (!admins_added.is_empty() || !admins_removed.is_empty())))
        {
            self.effects.push(Effect::Event(Event::Rules {
                conversation: id,
                by,
                admins_added: if first { Vec::new() } else { admins_added },
                admins_removed: if first { Vec::new() } else { admins_removed },
                add: (add != add_before).then_some(add),
                edit: (edit != edit_before).then_some(edit),
                link,
            }));
        }
        if settings.timer != settings_before.timer && !removed_self {
            self.effects.push(Effect::Event(Event::Timer {
                conversation: id,
                by,
                seconds: settings.timer,
            }));
        }
        if settings.name != settings_before.name && !removed_self {
            self.effects.push(Effect::Event(Event::Renamed {
                conversation: id,
                by,
                name: settings.name,
            }));
        }
        self.dirty_conversations.insert(id);
        if removed_self {
            let c = self.conversations.get_mut(&id).expect("exists");
            c.active = false;
            for outgoing in c.outbox.drain(..) {
                self.dirty_outbox.insert((id, outgoing.sender_seq));
            }
            self.effects
                .push(Effect::Event(Event::Removed { conversation: id }));
            return;
        }
        let after = self.members(&id);
        let added: Vec<_> = after
            .iter()
            .filter(|m| !before.contains(m))
            .copied()
            .collect();
        let removed: Vec<_> = before
            .iter()
            .filter(|m| !after.contains(m))
            .copied()
            .collect();
        if !added.is_empty() {
            self.effects.push(Effect::Event(Event::MembersAdded {
                conversation: id,
                identities: added,
            }));
        }
        // Those who said they were leaving left; anyone else was removed,
        // by whoever committed it.
        let (left, removed): (Vec<_>, Vec<_>) = removed
            .into_iter()
            .partition(|m| self.leavers.remove(&(id, *m)));
        if !left.is_empty() {
            self.effects.push(Effect::Event(Event::MembersRemoved {
                conversation: id,
                identities: left,
                by: None,
            }));
        }
        if !removed.is_empty() {
            self.effects.push(Effect::Event(Event::MembersRemoved {
                conversation: id,
                identities: removed,
                by: Some(by),
            }));
        }
    }

    fn deliver(&mut self, id: Route, credential: &Credential, plaintext: &[u8]) {
        let Some(cert) = tree_cert(credential) else {
            return;
        };
        let Ok(message) = AppMessage::decode(plaintext) else {
            return;
        };
        if self.blocked.contains(&cert.identity) {
            return;
        }
        let c = self.conversations.get_mut(&id).expect("exists");
        if !c
            .windows
            .entry(cert.device)
            .or_insert_with(Window::new)
            .insert(message.sender_seq)
        {
            return;
        }
        self.dirty_conversations.insert(id);
        let content = match message.body {
            Body::Leave => {
                // Someone left: any member removes all of their devices (the
                // first commit wins; the others find them gone).
                let leaving = cert.identity;
                let queued = c
                    .intents
                    .iter()
                    .any(|i| matches!(i, Intent::Remove { identity } if *identity == leaving));
                self.leavers.insert((id, leaving));
                let c = self.conversations.get_mut(&id).expect("exists");
                if c.active
                    && leaving != self.identity.public()
                    && !queued
                    && c.intents.len() < INTENTS_MAX
                {
                    c.intents.push_back(Intent::Remove { identity: leaving });
                }
                Content::Leave
            }
            body => Content::from_body(body),
        };
        // References name a device in the group (edits and deletions, one of
        // the sender's own): any other would only pile up on the receiving
        // device, waiting for a message that never comes.
        let devices: BTreeMap<DeviceId, IdentityKey> = self.conversations[&id]
            .group
            .members()
            .filter_map(|m| tree_cert(&m.credential))
            .map(|c| (c.device, c.identity))
            .collect();
        let content = match content {
            Content::React { to, .. } if !devices.contains_key(&to.device) => return,
            Content::Edit { to, .. } | Content::Delete { to }
                if devices.get(&to.device) != Some(&cert.identity) =>
            {
                return;
            }
            Content::Receipt(refs) => {
                let refs: Vec<MessageRef> = refs
                    .into_iter()
                    .filter(|r| devices.contains_key(&r.device))
                    .collect();
                if refs.is_empty() {
                    return;
                }
                Content::Receipt(refs)
            }
            content => content,
        };
        self.effects.push(Effect::Event(Event::Message {
            conversation: id,
            from: cert.identity,
            device: cert.device,
            sender_seq: message.sender_seq,
            sent_at_ms: message.sent_at_ms,
            expires_after_s: message.expires_after_s,
            content,
        }));
    }

    fn desync(&mut self, id: Route, reason: String) {
        if let Some(c) = self.conversations.get_mut(&id)
            && c.active
        {
            c.active = false;
            self.dirty_conversations.insert(id);
            self.effects.push(Effect::Event(Event::Desync {
                conversation: id,
                reason,
            }));
        }
    }

    /// Serializes everything this step changed and hands back writes + effects.
    fn finish(&mut self) -> Step {
        if self.dirty_self {
            self.dirty_self = false;
            let record = SelfRecord {
                identity_seed: self.identity.seed(),
                mls_seed: self.mls_seed,
                cert: self.cert.encode(),
                inbox_cursor: self.inbox_cursor,
                key_packages_owed: self.key_packages_owed,
                last_resort_owed: self.last_resort_owed,
                push_target: self.push_target.clone(),
                key_packages_refreshed_ms: self.key_packages_refreshed_ms,
                classic: false,
                unruled: false,
            };
            self.provider
                .storage()
                .put_raw(KEY_SELF.to_vec(), encode_self(&record));
        }
        for id in std::mem::take(&mut self.dirty_conversations) {
            match self.conversations.get(&id) {
                Some(c) => self
                    .provider
                    .storage()
                    .put_raw(conversation_key(&id), encode_conversation(c)),
                None => self.provider.storage().delete_raw(&conversation_key(&id)),
            }
        }
        for inbox in std::mem::take(&mut self.dirty_unlinked) {
            let key = [PREFIX_UNLINKED, &inbox].concat();
            if self.unlinked.contains(&inbox) {
                self.provider.storage().put_raw(key, Vec::new());
            } else {
                self.provider.storage().delete_raw(&key);
            }
        }
        for inbox in std::mem::take(&mut self.dirty_siblings) {
            let key = [PREFIX_SIBLING, &inbox].concat();
            match self.siblings.get(&inbox) {
                Some(card) => self.provider.storage().put_raw(key, card.encode()),
                None => self.provider.storage().delete_raw(&key),
            }
        }
        for route in std::mem::take(&mut self.dirty_tombstones) {
            let key = [PREFIX_TOMBSTONE, &route].concat();
            match self.tombstones.get(&route) {
                // Same layout as a watch record: a version and a u64.
                Some(seq) => self.provider.storage().put_raw(key, encode_watch(*seq)),
                None => self.provider.storage().delete_raw(&key),
            }
        }
        for identity in std::mem::take(&mut self.dirty_blocked) {
            let key = [PREFIX_BLOCKED, &identity].concat();
            if self.blocked.contains(&identity) {
                self.provider.storage().put_raw(key, vec![RECORD_VERSION]);
            } else {
                self.provider.storage().delete_raw(&key);
            }
        }
        for join in std::mem::take(&mut self.dirty_joins) {
            let key = [PREFIX_JOIN, &join].concat();
            match self.pending_joins.get(&join) {
                Some(pending) => self
                    .provider
                    .storage()
                    .put_raw(key, encode_pending_join(pending)),
                None => self.provider.storage().delete_raw(&key),
            }
        }
        for route in std::mem::take(&mut self.dirty_muted) {
            let key = [PREFIX_MUTED, &route].concat();
            match self.muted.get(&route) {
                // Same layout as a watch record: a version and a u64.
                Some(until) => self.provider.storage().put_raw(key, encode_watch(*until)),
                None => self.provider.storage().delete_raw(&key),
            }
        }
        for route in std::mem::take(&mut self.dirty_watched) {
            match self.watched.get(&route) {
                Some(due) => self
                    .provider
                    .storage()
                    .put_raw(watch_key(&route), encode_watch(*due)),
                None => self.provider.storage().delete_raw(&watch_key(&route)),
            }
        }
        for (id, seq) in std::mem::take(&mut self.dirty_outbox) {
            let key = outbox_key(&id, seq);
            match self
                .conversations
                .get(&id)
                .and_then(|c| c.outbox.iter().find(|o| o.sender_seq == seq))
            {
                Some(outgoing) => self
                    .provider
                    .storage()
                    .put_raw(key, encode_outgoing(outgoing)),
                None => self.provider.storage().delete_raw(&key),
            }
        }
        Step {
            writes: self.provider.storage().take_changes(),
            effects: std::mem::take(&mut self.effects),
        }
    }
}

impl Conversation {
    /// Remembers an application message as processed, by content hash.
    fn remember(&mut self, hash: Hash) {
        if !self.seen_set.insert(hash) {
            return;
        }
        if self.seen.len() == SEEN_MAX {
            let oldest = self.seen.pop_front().expect("full");
            self.seen_set.remove(&oldest);
        }
        self.seen.push_back(hash);
    }

    fn new(group: MlsGroup, cursor: u64, intents: VecDeque<Intent>) -> Conversation {
        Conversation {
            group,
            active: true,
            cursor,
            caught_up: true,
            next_sender_seq: 1,
            outbox: VecDeque::new(),
            pending: None,
            intents,
            windows: BTreeMap::new(),
            seen: VecDeque::new(),
            seen_set: BTreeSet::new(),
            creation_seed: None,
            write_key: None,
            signal_key: None,
        }
    }

    /// The timer messages sent from now on carry: this device's own change
    /// while it is being committed, else the group's.
    fn timer(&self) -> u32 {
        self.intents
            .iter()
            .rev()
            .find_map(|intent| match intent {
                Intent::Timer(seconds) => Some(*seconds),
                _ => None,
            })
            .unwrap_or_else(|| group_timer(&self.group))
    }

    /// The current epoch's signal key, exported once per epoch.
    fn signal_key(&mut self, provider: &Provider, route: &Route) -> [u8; 32] {
        let epoch = self.group.epoch().as_u64();
        match self.signal_key {
            Some((at, key)) if at == epoch => key,
            _ => {
                let key: [u8; 32] = self
                    .group
                    .export_secret(provider.crypto(), SIGNAL_KEY_LABEL, route, 32)
                    .expect("an active group exports secrets")
                    .try_into()
                    .expect("32 bytes");
                self.signal_key = Some((epoch, key));
                key
            }
        }
    }

    /// The current epoch's write key, exported once per epoch.
    fn write_key(&mut self, provider: &Provider, route: &Route) -> [u8; 32] {
        let epoch = self.group.epoch().as_u64();
        match self.write_key {
            Some((at, key)) if at == epoch => key,
            _ => {
                let key = write_key(&self.group, provider, route);
                self.write_key = Some((epoch, key));
                key
            }
        }
    }
}

// ---- Records -------------------------------------------------------------

/// Version 3 records are laid out like version 2's; the version says the
/// device's published key packages are post-quantum. Version 5 is laid out
/// like 4; it says the device's leaves support group rules.
const RECORD_VERSION: u8 = 5;
/// Still read: before group rules (admins).
const RECORD_VERSION_UNRULED: u8 = 4;
/// Still read: before disappearing messages (no timers).
const RECORD_VERSION_UNTIMED: u8 = 3;
/// Still read: a device upgraded from before the post-quantum ciphersuite,
/// whose published key packages must be replaced at once.
const RECORD_VERSION_CLASSIC: u8 = 2;

/// Log positions, sequence numbers and times a device stores grow by one per
/// entry or message, or by one per millisecond: honestly kept, none comes
/// near this in millions of years. A record holding more is damaged, and
/// arithmetic on what was read can never overflow.
const STORED_MAX: u64 = 1 << 62;
/// A mute that lasts until the conversation is unmuted.
pub const MUTED_FOREVER: u64 = STORED_MAX;
/// Counts a device stores (key packages owed) are small; incrementing what
/// was read never overflows, even where `usize` has 32 bits.
const STORED_COUNT_MAX: usize = 1 << 30;

fn stored(r: &mut Reader) -> Result<u64, DecodeError> {
    match r.u64()? {
        v if v <= STORED_MAX => Ok(v),
        _ => Err(DecodeError::BadValue),
    }
}

fn record_version(r: &mut Reader) -> Result<u8, DecodeError> {
    match r.u8()? {
        v @ (RECORD_VERSION
        | RECORD_VERSION_UNRULED
        | RECORD_VERSION_UNTIMED
        | RECORD_VERSION_CLASSIC) => Ok(v),
        _ => Err(DecodeError::BadValue),
    }
}

struct SelfRecord {
    identity_seed: [u8; 32],
    mls_seed: [u8; 32],
    cert: Vec<u8>,
    inbox_cursor: u64,
    key_packages_owed: usize,
    last_resort_owed: bool,
    push_target: Option<(Platform, Vec<u8>)>,
    key_packages_refreshed_ms: u64,
    /// Read from a version 2 record: the published key packages are classic.
    classic: bool,
    /// Read from a record before group rules (or timers): the key packages
    /// and leaves published do not support every extension groups need.
    unruled: bool,
}

fn encode_self(r: &SelfRecord) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(RECORD_VERSION)
        .array(&r.identity_seed)
        .array(&r.mls_seed)
        .bytes(&r.cert)
        .u64(r.inbox_cursor)
        .count(r.key_packages_owed)
        .u8(u8::from(r.last_resort_owed));
    match &r.push_target {
        None => w.u8(0),
        Some((platform, address)) => w.u8(*platform as u8).bytes(address),
    };
    w.u64(r.key_packages_refreshed_ms);
    w.finish()
}

fn decode_self(bytes: &[u8]) -> Result<SelfRecord, DecodeError> {
    let mut r = Reader::new(bytes);
    let version = record_version(&mut r)?;
    let record = SelfRecord {
        identity_seed: r.array()?,
        mls_seed: r.array()?,
        cert: r.bytes(crate::identity::CERT_SIZE)?.to_vec(),
        inbox_cursor: stored(&mut r)?,
        key_packages_owed: r.count(STORED_COUNT_MAX)?,
        last_resort_owed: r.u8()? != 0,
        push_target: match r.u8()? {
            0 => None,
            platform => Some((
                Platform::from_u8(platform).ok_or(DecodeError::BadValue)?,
                r.bytes(PUSH_ADDRESS_MAX)?.to_vec(),
            )),
        },
        key_packages_refreshed_ms: stored(&mut r)?,
        classic: version == RECORD_VERSION_CLASSIC,
        unruled: version < RECORD_VERSION,
    };
    r.finish()?;
    Ok(record)
}

struct ConversationRecord {
    active: bool,
    cursor: u64,
    next_sender_seq: u64,
    pending: Option<Pending>,
    intents: VecDeque<Intent>,
    windows: BTreeMap<DeviceId, Window>,
    creation_seed: Option<[u8; 32]>,
}

fn encode_conversation(c: &Conversation) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(RECORD_VERSION)
        .u8(u8::from(c.active))
        .u64(c.cursor)
        .u64(c.next_sender_seq);
    match &c.pending {
        None => {
            w.u8(0);
        }
        Some(p) => {
            w.u8(1)
                .bytes(&p.message)
                .array(&p.hash)
                .array(&p.auth)
                .array(&p.next_key);
            match &p.creation {
                None => w.u8(0),
                Some((key, signature)) => w.u8(1).array(key).array(signature),
            };
            w.count(p.welcomes.len());
            for (inbox, welcome) in &p.welcomes {
                w.array(inbox).bytes(welcome);
            }
        }
    }
    // Never more than a restore reads back.
    w.count(c.intents.len().min(INTENTS_MAX));
    for intent in c.intents.iter().take(INTENTS_MAX) {
        match intent {
            Intent::Add {
                contact,
                key_package,
            } => {
                w.u8(1).array(&contact.identity).array(&contact.inbox);
                match key_package {
                    None => w.u8(0),
                    Some(kp) => w.u8(1).bytes(kp),
                };
            }
            Intent::Remove { identity } => {
                w.u8(2).array(identity);
            }
            Intent::Update => {
                w.u8(3);
            }
            Intent::Timer(seconds) => {
                w.u8(4).u32(*seconds);
            }
            Intent::RemoveDevice { inbox } => {
                w.u8(5).array(inbox);
            }
            Intent::Rename(name) => {
                w.u8(6).bytes(name.as_bytes());
            }
            Intent::Policy(policy) => {
                w.u8(7).bytes(&policy.encode());
            }
            Intent::StepDown => {
                w.u8(8);
            }
        }
    }
    // Never more than a restore reads back.
    w.count(c.windows.len().min(WINDOWS_MAX));
    for (device, window) in c.windows.iter().take(WINDOWS_MAX) {
        w.array(device).u64(window.max);
        for word in window.bits {
            w.u64(word);
        }
    }
    match &c.creation_seed {
        None => w.u8(0),
        Some(seed) => w.u8(1).array(seed),
    };
    w.finish()
}

/// Intents queued per conversation are bounded by what a record can hold.
const INTENTS_MAX: usize = 1024;
/// Duplicate windows kept per conversation: one per member device.
const WINDOWS_MAX: usize = GROUP_MEMBERS_MAX * 4;
const WINDOWS_READ_MAX: usize = 1 << 16;

fn decode_conversation(bytes: &[u8]) -> Result<ConversationRecord, DecodeError> {
    let mut r = Reader::new(bytes);
    record_version(&mut r)?;
    let active = r.u8()? != 0;
    let cursor = stored(&mut r)?;
    let next_sender_seq = stored(&mut r)?;
    let pending = match r.u8()? {
        0 => None,
        1 => {
            let message = r.bytes(MLS_MESSAGE_MAX)?.to_vec();
            let hash = r.array()?;
            let auth = r.array()?;
            let next_key = r.array()?;
            let creation = match r.u8()? {
                0 => None,
                1 => Some((r.array()?, r.array()?)),
                _ => return Err(DecodeError::BadValue),
            };
            let n = r.count(WELCOMES_PER_SUBMIT_MAX)?;
            let mut welcomes = Vec::with_capacity(n);
            for _ in 0..n {
                welcomes.push((r.array()?, r.bytes(MLS_MESSAGE_MAX)?.to_vec()));
            }
            Some(Pending {
                message,
                welcomes,
                hash,
                auth,
                next_key,
                creation,
            })
        }
        _ => return Err(DecodeError::BadValue),
    };
    let n = r.count(INTENTS_MAX)?;
    let mut intents = VecDeque::with_capacity(n);
    for _ in 0..n {
        intents.push_back(match r.u8()? {
            1 => {
                let contact = ContactCard {
                    identity: r.array()?,
                    inbox: r.array()?,
                };
                let key_package = match r.u8()? {
                    0 => None,
                    1 => Some(r.bytes(MLS_MESSAGE_MAX)?.to_vec()),
                    _ => return Err(DecodeError::BadValue),
                };
                Intent::Add {
                    contact,
                    key_package,
                }
            }
            2 => Intent::Remove {
                identity: r.array()?,
            },
            3 => Intent::Update,
            4 => Intent::Timer(r.u32()?.min(DISAPPEAR_MAX_S)),
            5 => Intent::RemoveDevice { inbox: r.array()? },
            6 => Intent::Rename(
                String::from_utf8(r.bytes(GROUP_NAME_MAX)?.to_vec())
                    .map_err(|_| DecodeError::BadValue)?,
            ),
            7 => Intent::Policy(Policy::decode(r.bytes(POLICY_BYTES_MAX)?)?),
            8 => Intent::StepDown,
            _ => return Err(DecodeError::BadValue),
        });
    }
    // Read leniently: records from before windows were pruned may hold more
    // (the next commit prunes them); written ones never exceed WINDOWS_MAX.
    let n = r.count(WINDOWS_READ_MAX)?;
    let mut windows = BTreeMap::new();
    for _ in 0..n {
        let device = r.array()?;
        let mut window = Window {
            max: r.u64()?,
            bits: [0; WINDOW_WORDS],
        };
        for word in &mut window.bits {
            *word = r.u64()?;
        }
        windows.insert(device, window);
    }
    let creation_seed = match r.u8()? {
        0 => None,
        1 => Some(r.array()?),
        _ => return Err(DecodeError::BadValue),
    };
    r.finish()?;
    Ok(ConversationRecord {
        active,
        cursor,
        next_sender_seq,
        pending,
        intents,
        windows,
        creation_seed,
    })
}

fn encode_watch(due: u64) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(RECORD_VERSION).u64(due);
    w.finish()
}

fn decode_watch(bytes: &[u8]) -> Result<u64, DecodeError> {
    let mut r = Reader::new(bytes);
    record_version(&mut r)?;
    let due = stored(&mut r)?;
    r.finish()?;
    Ok(due)
}

/// An outgoing record's content, stored as the application message it is.
const OUTGOING_AS_MESSAGE: u8 = 6;

fn encode_outgoing(o: &Outgoing) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(RECORD_VERSION)
        .u64(o.sender_seq)
        .u64(o.sent_at_ms)
        .u32(o.expires_after_s);
    // The content as the message itself encodes it, so every kind of
    // message is stored by the one codec (tags 1 to 5 are older records).
    let message = o.content.with_body(|body| {
        AppMessage {
            sender_seq: o.sender_seq,
            sent_at_ms: o.sent_at_ms,
            expires_after_s: o.expires_after_s,
            body,
        }
        .encode()
    });
    w.u8(OUTGOING_AS_MESSAGE).bytes(&message);
    match &o.sealed {
        None => w.u8(0),
        Some(s) => w.u8(1).bytes(&s.message).array(&s.hash).array(&s.auth),
    };
    w.finish()
}

fn decode_outgoing(bytes: &[u8]) -> Result<Outgoing, DecodeError> {
    let mut r = Reader::new(bytes);
    let version = record_version(&mut r)?;
    let sender_seq = stored(&mut r)?;
    let sent_at_ms = stored(&mut r)?;
    let expires_after_s = if version >= RECORD_VERSION_UNRULED {
        r.u32()?
    } else {
        0
    };
    if expires_after_s > DISAPPEAR_MAX_S {
        return Err(DecodeError::BadValue);
    }
    let text = |bytes: &[u8]| String::from_utf8(bytes.to_vec()).map_err(|_| DecodeError::BadValue);
    let content = match r.u8()? {
        1 => Content::Text(text(r.bytes(TEXT_MAX)?)?),
        2 => {
            let file = SharedFile {
                id: r.array()?,
                key: r.array()?,
                size: r.u64()?,
                name: text(r.bytes(FILE_NAME_MAX)?)?,
                media_type: text(r.bytes(FILE_TYPE_MAX)?)?,
                width: r.u32()?,
                height: r.u32()?,
                thumbnail: r.bytes(THUMBNAIL_MAX)?.to_vec(),
            };
            if !file.file_ref().valid() {
                return Err(DecodeError::BadValue);
            }
            Content::File(Box::new(file))
        }
        3 => {
            let call = r.array()?;
            let to = r.array()?;
            let kind = match (r.u8()?, r.u8()?) {
                (1, 0) => CallKind::Offer,
                (2, 0) => CallKind::Answer,
                (3, 0) => CallKind::Candidates,
                (5, 0) => CallKind::Join,
                (4, reason) => CallKind::End(match reason {
                    1 => CallEnd::Hangup,
                    2 => CallEnd::Declined,
                    3 => CallEnd::Busy,
                    4 => CallEnd::Unanswered,
                    5 => CallEnd::Failed,
                    _ => return Err(DecodeError::BadValue),
                }),
                _ => return Err(DecodeError::BadValue),
            };
            let call = Call {
                call,
                to,
                kind,
                video: r.u8()? != 0,
                sdp: text(r.bytes(CALL_SDP_MAX)?)?,
            };
            if !call.signal().valid() {
                return Err(DecodeError::BadValue);
            }
            Content::Call(Box::new(call))
        }
        5 => Content::Leave,
        OUTGOING_AS_MESSAGE => {
            let message = AppMessage::decode(r.bytes(MLS_MESSAGE_MAX)?)?;
            if message.sender_seq != sender_seq {
                return Err(DecodeError::BadValue);
            }
            Content::from_body(message.body)
        }
        _ => return Err(DecodeError::BadValue),
    };
    let sealed = match r.u8()? {
        0 => None,
        1 => Some(Sealed {
            message: r.bytes(MLS_MESSAGE_MAX)?.to_vec(),
            hash: r.array()?,
            auth: r.array()?,
        }),
        _ => return Err(DecodeError::BadValue),
    };
    r.finish()?;
    Ok(Outgoing {
        sender_seq,
        sent_at_ms,
        expires_after_s,
        content,
        sealed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_member_cannot_signal_as_another() {
        use ed25519_dalek::Signer as _;
        let alice = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        let mallory = ed25519_dalek::SigningKey::from_bytes(&[2; 32]);
        // Mallory claims Alice's leaf (0) and signs it herself.
        let claim = signal_signed_bytes(&[5; 16], 3, 0, SignalKind::Typing, 1_000);
        let forged = mallory.sign(&claim).to_bytes();
        assert!(!signed_by(
            alice.verifying_key().as_bytes(),
            &claim,
            &forged
        ));
        let real = alice.sign(&claim).to_bytes();
        assert!(signed_by(alice.verifying_key().as_bytes(), &claim, &real));
        // Nor can a real signature be moved to another conversation, epoch,
        // leaf, kind or time.
        for other in [
            signal_signed_bytes(&[6; 16], 3, 0, SignalKind::Typing, 1_000),
            signal_signed_bytes(&[5; 16], 4, 0, SignalKind::Typing, 1_000),
            signal_signed_bytes(&[5; 16], 3, 1, SignalKind::Typing, 1_000),
            signal_signed_bytes(&[5; 16], 3, 0, SignalKind::Online, 1_000),
            signal_signed_bytes(&[5; 16], 3, 0, SignalKind::Typing, 1_001),
        ] {
            assert!(!signed_by(alice.verifying_key().as_bytes(), &other, &real));
        }
    }

    #[test]
    fn outgoing_records_from_before_timers_still_load() {
        let outgoing = Outgoing {
            sender_seq: 4,
            sent_at_ms: 9,
            expires_after_s: 0,
            content: Content::Text("old".to_owned()),
            sealed: None,
        };
        let mut old = encode_outgoing(&outgoing);
        // Version 3 had no timer between the send time and the content.
        old[0] = RECORD_VERSION_UNTIMED;
        old.drain(17..21);
        let decoded = decode_outgoing(&old).expect("decodes");
        assert_eq!(decoded.content, outgoing.content);
        assert_eq!(decoded.expires_after_s, 0);

        let call = Outgoing {
            content: Content::Call(Box::new(Call {
                call: [1; 16],
                to: [2; 32],
                kind: CallKind::End(CallEnd::Busy),
                video: false,
                sdp: String::new(),
            })),
            expires_after_s: 60,
            ..outgoing
        };
        let decoded = decode_outgoing(&encode_outgoing(&call)).expect("decodes");
        assert_eq!(decoded.content, call.content);
        assert_eq!(decoded.expires_after_s, 60);
    }

    /// A member of a test group, driven directly through OpenMLS with the
    /// client's own configuration, credential and key packages.
    struct Member {
        client: Client,
        group: Option<MlsGroup>,
    }

    impl Member {
        fn new(seed: u64) -> Member {
            let (client, _) = Client::create(Config::default(), Rand::seeded(seed), 0);
            Member {
                client,
                group: None,
            }
        }

        fn key_package(&self) -> KeyPackage {
            let bytes = self.client.new_key_package(false).expect("key package");
            KeyPackageIn::tls_deserialize_exact(&bytes)
                .expect("decodes")
                .validate(self.client.provider.crypto(), ProtocolVersion::Mls10)
                .expect("valid")
        }

        fn group(&mut self) -> (&mut MlsGroup, &Provider, &SignatureKeyPair) {
            let c = &mut self.client;
            (self.group.as_mut().expect("joined"), &c.provider, &c.signer)
        }
    }

    /// Everyone but `from` processes a commit.
    fn deliver(members: &mut [Member], from: usize, commit: &[u8]) {
        for (i, m) in members.iter_mut().enumerate() {
            if i == from {
                continue;
            }
            let message = MlsMessageIn::tls_deserialize_exact(commit)
                .expect("decodes")
                .try_into_protocol_message()
                .expect("a commit");
            let (group, provider, _) = m.group();
            let processed = group.process_message(provider, message).expect("valid");
            let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content()
            else {
                panic!("not a commit");
            };
            group
                .merge_staged_commit(provider, *staged)
                .expect("merges");
        }
    }

    /// Adds a member; returns the size of the submit carrying the commit
    /// and its welcome.
    fn add(members: &mut Vec<Member>, seed: u64) -> usize {
        let mut joiner = Member::new(seed);
        let key_package = joiner.key_package();
        let (group, provider, signer) = members[0].group();
        let (commit, welcome, _) = group
            .add_members(provider, signer, &[key_package])
            .expect("adds");
        group.merge_pending_commit(provider).expect("merges");
        let (commit, welcome) = (serialize(&commit), serialize(&welcome));
        deliver(members, 0, &commit);
        let MlsMessageBodyIn::Welcome(w) = MlsMessageIn::tls_deserialize_exact(&welcome)
            .expect("decodes")
            .extract()
        else {
            panic!("not a welcome");
        };
        let c = &joiner.client;
        joiner.group = Some(
            StagedWelcome::new_from_welcome(&c.provider, &join_config(), w, None)
                .and_then(|staged| staged.into_group(&c.provider))
                .expect("joins"),
        );
        members.push(joiner);
        assert!(commit.len() <= MLS_MESSAGE_MAX && welcome.len() <= MLS_MESSAGE_MAX);
        Submit::size_max(commit.len(), [welcome.len()])
    }

    /// The largest submits a group of `GROUP_MEMBERS_MAX` makes fit in a
    /// frame. Building that group takes minutes, so this builds a smaller
    /// one and scales up: every size here grows linearly with the members,
    /// and scaling the whole size (fixed part included) overestimates.
    #[test]
    fn largest_submits_fit_in_a_frame() {
        const MEMBERS: usize = 32;
        let scale = |size: usize| size * GROUP_MEMBERS_MAX / MEMBERS;

        let mut members = vec![Member::new(0)];
        let c = &members[0].client;
        members[0].group = Some(
            MlsGroup::new(
                &c.provider,
                &c.signer,
                &create_config("", [0; 32]),
                c.credential(),
            )
            .expect("creates"),
        );
        // Adding to a tree whose parents are blank: the commit encrypts to
        // every member separately.
        let mut blank = 0;
        for seed in 1..MEMBERS as u64 {
            blank = blank.max(add(&mut members, seed));
        }
        // Once everyone has updated, every parent is filled and the welcome
        // carries the largest possible tree.
        for i in 1..members.len() {
            let (group, provider, signer) = members[i].group();
            let bundle = group
                .self_update(provider, signer, LeafNodeParameters::default())
                .expect("updates");
            group.merge_pending_commit(provider).expect("merges");
            deliver(&mut members, i, &serialize(&bundle.into_messages().0));
        }
        let full = add(&mut members, MEMBERS as u64);

        let frame = FRAME_BODY_MAX as usize;
        assert!(
            scale(blank) <= frame,
            "blank tree: {blank} -> {}",
            scale(blank)
        );
        assert!(scale(full) <= frame, "full tree: {full} -> {}", scale(full));
    }

    /// Builds a commit in `member`'s group, checks it as if the member at
    /// `as_leaf` had made it, and throws it away.
    fn checked(
        member: &mut Member,
        as_leaf: LeafNodeIndex,
        build: impl FnOnce(&mut MlsGroup, &Provider, &SignatureKeyPair),
    ) -> Result<(), &'static str> {
        let (group, provider, signer) = member.group();
        build(group, provider, signer);
        let result = check_commit(group, group.pending_commit().expect("a commit"), as_leaf);
        group
            .clear_pending_commit(provider.storage())
            .expect("clears");
        result
    }

    fn rules(
        group: &mut MlsGroup,
        provider: &Provider,
        signer: &SignatureKeyPair,
        policy: Option<&Policy>,
    ) {
        let settings = group_settings(group);
        group
            .update_group_context_extensions(provider, group_context(&settings, policy), signer)
            .expect("commits");
    }

    fn rename(group: &mut MlsGroup, provider: &Provider, signer: &SignatureKeyPair) {
        let settings = Settings {
            name: "renamed".into(),
            ..group_settings(group)
        };
        let policy = group_policy(group).expect("readable");
        group
            .update_group_context_extensions(
                provider,
                group_context(&settings, policy.as_ref()),
                signer,
            )
            .expect("commits");
    }

    #[test]
    fn every_commit_is_checked_against_the_group_rules() {
        let mut members = vec![Member::new(0)];
        let alice = members[0].client.identity.public();
        let c = &members[0].client;
        members[0].group = Some(
            MlsGroup::new(
                &c.provider,
                &c.signer,
                &create_config("", alice),
                c.credential(),
            )
            .expect("creates"),
        );
        add(&mut members, 1);
        let bob = members[1].client.identity.public();
        let a = members[0].group.as_ref().expect("in").own_leaf_index();
        let b = members[1].group.as_ref().expect("in").own_leaf_index();
        let restricted = Policy {
            add: Who::Admins,
            edit: Who::Admins,
            ..Policy::new(alice)
        };

        // Only an admin changes the rules; anyone renames while that is
        // open to everyone.
        assert_eq!(
            checked(&mut members[0], a, |g, p, s| rules(
                g,
                p,
                s,
                Some(&restricted)
            )),
            Ok(())
        );
        assert_eq!(
            checked(&mut members[1], b, |g, p, s| rules(
                g,
                p,
                s,
                Some(&restricted)
            )),
            Err("only admins may change this group's rules")
        );
        assert_eq!(checked(&mut members[1], b, rename), Ok(()));
        // Nobody removes the rules. (An extension krypt never sets cannot
        // even be committed: OpenMLS requires members to support it, and
        // checks that too on receipt; `check_commit` refuses it as well.)
        assert!(checked(&mut members[0], a, |g, p, s| rules(g, p, s, None)).is_err());
        // A member's update keeps its certificate and key (Alice's update,
        // passed off as Bob's, is caught).
        let update = |g: &mut MlsGroup, p: &Provider, s: &SignatureKeyPair| {
            g.self_update(p, s, LeafNodeParameters::default())
                .expect("updates");
        };
        assert_eq!(checked(&mut members[0], a, update), Ok(()));
        assert_eq!(
            checked(&mut members[0], b, update),
            Err("a member's certificate changed")
        );
        // No two devices in a group share an id.
        let mut twin = Member::new(5);
        twin.client.cert.device = members[0].client.cert.device;
        let twin = twin.key_package();
        assert_eq!(
            checked(&mut members[0], a, |g, p, s| {
                g.add_members(p, s, &[twin]).expect("adds");
            }),
            Err("two devices in the group share an id")
        );

        // With adding and renaming for admins only: Bob may still add his
        // own devices, nobody else, and may not rename.
        let (group, provider, signer) = members[0].group();
        let settings = group_settings(group);
        let (commit, _, _) = group
            .update_group_context_extensions(
                provider,
                group_context(&settings, Some(&restricted)),
                signer,
            )
            .expect("commits");
        group.merge_pending_commit(provider).expect("merges");
        deliver(&mut members, 0, &serialize(&commit));
        let stranger = Member::new(6).key_package();
        assert_eq!(
            checked(&mut members[1], b, |g, p, s| {
                g.add_members(p, s, &[stranger]).expect("adds");
            }),
            Err("only admins may add people to this group")
        );
        let mut sibling = Member::new(7);
        sibling.client.cert.identity = bob;
        let sibling = sibling.key_package();
        assert_eq!(
            checked(&mut members[1], b, |g, p, s| {
                g.add_members(p, s, &[sibling]).expect("adds");
            }),
            Ok(())
        );
        assert_eq!(
            checked(&mut members[1], b, rename),
            Err("only admins may change this group's name or timer")
        );
    }

    #[test]
    fn a_group_from_before_admins_gets_rules_naming_everyone() {
        let mut members = vec![Member::new(10)];
        let alice = members[0].client.identity.public();
        let c = &members[0].client;
        let legacy = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .capabilities(capabilities())
            .with_group_context_extensions(group_context(&Settings::default(), None))
            .use_ratchet_tree_extension(true)
            .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .build();
        members[0].group =
            Some(MlsGroup::new(&c.provider, &c.signer, &legacy, c.credential()).expect("creates"));
        add(&mut members, 11);
        let bob = members[1].client.identity.public();
        let a = members[0].group.as_ref().expect("in").own_leaf_index();
        assert_eq!(
            effective_admins(members[0].group.as_ref().expect("in")).len(),
            2,
            "everyone is an admin before rules"
        );
        let alone = Policy::new(alice);
        assert_eq!(
            checked(&mut members[0], a, |g, p, s| rules(g, p, s, Some(&alone))),
            Err("a group's first rules must make every member an admin")
        );
        let everyone = Policy {
            admins: vec![alice, bob],
            ..Policy::new(alice)
        };
        assert_eq!(
            checked(&mut members[0], a, |g, p, s| rules(
                g,
                p,
                s,
                Some(&everyone)
            )),
            Ok(())
        );
    }

    #[test]
    fn policies_have_one_encoding() {
        let policy = Policy {
            admins: vec![[2; 32], [1; 32], [2; 32]],
            add: Who::Admins,
            edit: Who::Everyone,
            link: Some([9; 32]),
        };
        let bytes = policy.encode();
        let decoded = Policy::decode(&bytes).expect("decodes");
        assert_eq!(decoded.admins, vec![[1; 32], [2; 32]]);
        assert_eq!(decoded.encode(), bytes);
        // Admins out of order are a second encoding: refused.
        let mut unsorted = bytes.clone();
        unsorted[7..39].copy_from_slice(&[3; 32]);
        assert!(Policy::decode(&unsorted).is_err());
    }

    #[test]
    fn window_accepts_each_seq_once() {
        let mut w = Window::new();
        assert!(w.insert(1));
        assert!(!w.insert(1));
        assert!(w.insert(3));
        assert!(w.insert(2));
        assert!(!w.insert(2));
        assert!(!w.insert(3));
    }

    #[test]
    fn window_slides_across_word_boundaries() {
        let mut w = Window::new();
        for seq in [5, 70, 200, 64, 1, 129] {
            assert!(w.insert(seq), "{seq}");
        }
        for seq in [5, 70, 200, 64, 1, 129] {
            assert!(!w.insert(seq), "{seq} accepted twice");
        }
        assert!(w.insert(1000));
        assert!(!w.insert(200));
        // Far beyond the window, everything older is unknowable and refused.
        assert!(w.insert(1000 + DEDUP_WINDOW));
        assert!(!w.insert(999));
        assert!(w.insert(1001));
    }

    #[test]
    fn window_matches_a_set_model() {
        let rand = Rand::seeded(1);
        let mut w = Window::new();
        let mut seen = BTreeSet::new();
        let mut max = 0u64;
        for _ in 0..20_000 {
            let r = u64::from_le_bytes(rand.bytes());
            let seq = (max + (r % 64)).saturating_sub(r % 1500).max(1);
            let expected = if max >= DEDUP_WINDOW && seq <= max - DEDUP_WINDOW {
                false
            } else {
                !seen.contains(&seq)
            };
            assert_eq!(w.insert(seq), expected, "seq {seq} max {max}");
            if expected {
                seen.insert(seq);
                max = max.max(seq);
            }
        }
    }
}
