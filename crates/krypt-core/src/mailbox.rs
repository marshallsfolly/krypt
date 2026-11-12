//! The mailbox: the only shared infrastructure in krypt.
//!
//! It keeps an append-only log per conversation and per inbox, accepts exactly
//! one commit per MLS epoch (which is what keeps a group's history linear
//! without any member coordinating), stores ciphertext for offline members,
//! fans welcomes out to new members' inboxes, holds key packages, pushes new
//! entries to connected devices and wakes the rest. It never sees plaintext.
//!
//! One [`Mailbox`] serves one log over that log's [`Store`]. In production
//! each log is a Cloudflare Durable Object with its own SQLite database;
//! [`LocalMailbox`] runs every log in one process for tests, the simulator
//! and local development.
//!
//! ## What a message costs
//!
//! Storage is shaped by what Cloudflare bills: rows written cost a thousand
//! times more than rows read. An application message is one row written (its
//! entry). Duplicate submissions are found by reading recent entries rather
//! than through an index (an index would add a row written to every message),
//! and metadata is rewritten only on commits, evictions and at most daily
//! touches. Pushes carry the new entry itself, so receivers make no request.

use std::collections::BTreeMap;

use krypt_wire::codec::{DecodeError, Reader, Writer};
use krypt_wire::frame::{self, Frame, Kind, Route};
use krypt_wire::limits::{
    DAY_MS, FILE_BYTES_PER_DAY, FRAME_BODY_MAX, GROUP_MEMBERS_MAX, IDLE_DELETE_MS,
    JOIN_REQUESTS_MAX, KEY_PACKAGES_MAX, LOG_BYTES_MAX, LOG_ENTRIES_MAX, PAST_EPOCHS_MAX,
    PUSH_COALESCE_MS, RETENTION_MS, TURN_GRANTS_PER_DAY, WATCH_TTL_MS, WATCHERS_MAX,
};
use krypt_wire::msg::{
    Accepted, Entries, Entry, Fetch, FilePart, InboxWelcome, JoinRequest, KeyPackages,
    MLS_MESSAGE_MAX, OpenRequests, PushTarget, Reject, Rejected, Signal, Submit, TurnGrant, Watch,
};
use openmls::prelude::tls_codec::Deserialize as _;
use openmls::prelude::{
    BasicCredential, ContentType, KeyPackageIn, MlsMessageBodyIn, MlsMessageIn, ProtocolVersion,
};
use openmls_rust_crypto::RustCrypto;

use crate::client::{CIPHERSUITE, joins_new_conversations};
use crate::identity::{DeviceCert, IdentityKey};
use crate::{constant_time_eq, hash16};

pub type Hash = [u8; 16];

/// Label for the per-epoch key that proves a writer is a member. Exported
/// from MLS, so it reveals nothing about message keys, and a removed member
/// never learns the keys of epochs after its removal.
pub const WRITE_KEY_LABEL: &str = "krypt mailbox write v1";
/// Regular key packages handed out per inbox per hour; beyond that, only the
/// last-resort one, so draining an inbox gains an attacker nothing.
const CLAIMS_PER_HOUR: usize = 16;
const HOUR_MS: u64 = 60 * 60 * 1000;

/// The tag a member puts on a submission: keyed by its epoch's write key.
pub fn write_tag(key: &[u8; 32], route: &Route, message: &[u8]) -> [u8; 16] {
    tag(key, &[b"krypt write v1".as_slice(), route, message])
}

/// The tag on an upload of part of a file: keyed by the current epoch's
/// write key, so only members can store files.
pub fn file_tag(key: &[u8; 32], route: &Route, part: &FilePart) -> [u8; 16] {
    tag(
        key,
        &[
            b"krypt file v1".as_slice(),
            route,
            &part.file,
            &part.part.to_le_bytes(),
            &part.len.to_le_bytes(),
        ],
    )
}

/// The proof on a signal (typing, online): keyed by the current epoch's
/// write key, so only members can reach the others' screens.
pub fn signal_tag(key: &[u8; 32], route: &Route, sealed: &[u8]) -> [u8; 16] {
    tag(key, &[b"krypt signal v1".as_slice(), route, sealed])
}

/// The proof on a request for call relay credentials: keyed by the current
/// epoch's write key, so only members can use the relay.
pub fn turn_tag(key: &[u8; 32], route: &Route) -> [u8; 16] {
    tag(key, &[b"krypt turn v1".as_slice(), route])
}

/// What a conversation's creation key signs: its route and first commit.
pub fn creation_signed_bytes(route: &Route, message: &[u8]) -> Vec<u8> {
    [b"krypt create v1".as_slice(), route, message].concat()
}

/// A conversation's route is the hash of its creation key.
pub fn creation_route(key: &[u8; 32]) -> Route {
    hash16(&[b"krypt route v1".as_slice(), key].concat())
}

/// The proof on a watch of a conversation log.
pub fn watch_tag(key: &[u8; 32], signed: &[u8]) -> [u8; 16] {
    tag(key, &[signed])
}

fn tag(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new_keyed(key);
    for part in parts {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    out
}

/// How many of the most recent entries a submission is checked against for
/// an identical earlier one (a client retrying after a lost response).
/// Older duplicates are harmless: receivers drop them.
const DEDUP_SCAN: usize = 256;
/// Metadata is rewritten for a read at most this often.
const TOUCH_INTERVAL_MS: u64 = DAY_MS;
/// New entries up to this size travel inside the push itself.
const NOTIFY_INLINE_MAX: usize = 16 * 1024;
/// A full log evicts down to this fraction of its limits, so eviction (and
/// its metadata write) happens in batches rather than on every append.
const EVICT_TO_NUMERATOR: u64 = 15;
const EVICT_TO_DENOMINATOR: u64 = 16;

// ---- Storage --------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum LogKind {
    Conversation = 1,
    Inbox = 2,
    /// Requests to join a group through its invite link (decision 52).
    Requests = 3,
}

/// Per-log metadata. Rewritten rarely; never on an ordinary message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Meta {
    pub kind: LogKind,
    /// Epoch of the group after the last accepted commit.
    pub epoch: u64,
    /// Every seq at or below this has been evicted.
    pub evicted_through: u64,
    /// Last time anyone wrote or read the log (to the day).
    pub touched_ms: u64,
}

const META_VERSION: u8 = 1;

impl Meta {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(26);
        w.u8(META_VERSION)
            .u8(self.kind as u8)
            .u64(self.epoch)
            .u64(self.evicted_through)
            .u64(self.touched_ms);
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Meta, DecodeError> {
        let mut r = Reader::new(bytes);
        if r.u8()? != META_VERSION {
            return Err(DecodeError::BadValue);
        }
        let kind = match r.u8()? {
            1 => LogKind::Conversation,
            2 => LogKind::Inbox,
            3 => LogKind::Requests,
            _ => return Err(DecodeError::BadValue),
        };
        let meta = Meta {
            kind,
            epoch: r.u64()?,
            evicted_through: r.u64()?,
            touched_ms: r.u64()?,
        };
        r.finish()?;
        Ok(meta)
    }
}

/// Small per-log records, each one row.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Blob {
    KeyPackages = 1,
    Watchers = 2,
    WriteKeys = 3,
    FileQuota = 4,
    TurnQuota = 5,
    /// A requests log's admin key, token and header.
    Requests = 6,
    /// The welcomes a conversation forwarded to each inbox this hour.
    Invites = 7,
}

/// One log's storage. Every method is one SQL statement in production;
/// the comments say what each costs there.
pub trait Store {
    /// One row read.
    fn meta(&self) -> Option<Meta>;
    /// One row written.
    fn set_meta(&mut self, meta: &Meta);
    /// Highest retained seq. One row read.
    fn last_seq(&self) -> Option<u64>;
    /// One row written.
    fn append(&mut self, seq: u64, at_ms: u64, hash: &Hash, data: &[u8]);
    /// Up to `limit` entries with `seq > after`, in order, with no more than
    /// `max_bytes` of data in all (but always the first): only what one
    /// response can carry is ever read.
    fn range(&self, after: u64, limit: usize, max_bytes: u64) -> Vec<(u64, Vec<u8>)>;
    /// `(seq, length)` of up to `limit` entries with `seq > after`, in order,
    /// without reading their data.
    fn sizes(&self, after: u64, limit: usize) -> Vec<(u64, u64)>;
    /// `(seq, hash)` of the newest `count` entries.
    fn recent_hashes(&self, count: usize) -> Vec<(u64, Hash)>;
    /// The oldest retained entry's `(seq, at_ms)`.
    fn oldest(&self) -> Option<(u64, u64)>;
    /// Highest seq appended at or before `at_ms`.
    fn last_appended_by(&self, at_ms: u64) -> Option<u64>;
    /// One row written per entry removed.
    fn evict_through(&mut self, seq: u64);
    /// Retained entries and their total size.
    fn count(&self) -> u64;
    fn bytes(&self) -> u64;
    /// The accepted commit for an epoch, by hash, and its seq.
    fn commit(&self, epoch: u64) -> Option<(Hash, u64)>;
    fn put_commit(&mut self, epoch: u64, hash: &Hash, seq: u64);
    fn evict_commits_through(&mut self, seq: u64);
    fn blob(&self, which: Blob) -> Option<Vec<u8>>;
    fn set_blob(&mut self, which: Blob, value: &[u8]);
    /// Removes everything (the log is gone).
    fn clear(&mut self);
}

/// A [`Store`] in memory, for tests, the simulator and local development.
#[derive(Debug, Default)]
pub struct MemoryStore {
    meta: Option<Meta>,
    entries: BTreeMap<u64, (u64, Hash, Vec<u8>)>,
    bytes: u64,
    commits: BTreeMap<u64, (Hash, u64)>,
    blobs: BTreeMap<Blob, Vec<u8>>,
}

impl MemoryStore {
    /// Every stored payload, for scanning what the mailbox holds.
    pub fn values(&self) -> impl Iterator<Item = &[u8]> {
        let entries = self.entries.values().map(|(_, _, data)| data.as_slice());
        entries.chain(self.blobs.values().map(Vec::as_slice))
    }
}

impl Store for MemoryStore {
    fn meta(&self) -> Option<Meta> {
        self.meta
    }

    fn set_meta(&mut self, meta: &Meta) {
        self.meta = Some(*meta);
    }

    fn last_seq(&self) -> Option<u64> {
        self.entries.keys().next_back().copied()
    }

    fn append(&mut self, seq: u64, at_ms: u64, hash: &Hash, data: &[u8]) {
        assert!(self.last_seq().is_none_or(|last| seq > last));
        self.bytes += data.len() as u64;
        self.entries.insert(seq, (at_ms, *hash, data.to_vec()));
    }

    fn range(&self, after: u64, limit: usize, max_bytes: u64) -> Vec<(u64, Vec<u8>)> {
        let mut bytes = 0;
        self.entries
            .range(after.saturating_add(1)..)
            .take(limit)
            .take_while(|(_, (_, _, data))| {
                let first = bytes == 0;
                bytes += data.len() as u64;
                first || bytes <= max_bytes
            })
            .map(|(seq, (_, _, data))| (*seq, data.clone()))
            .collect()
    }

    fn sizes(&self, after: u64, limit: usize) -> Vec<(u64, u64)> {
        self.entries
            .range(after.saturating_add(1)..)
            .take(limit)
            .map(|(seq, (_, _, data))| (*seq, data.len() as u64))
            .collect()
    }

    fn recent_hashes(&self, count: usize) -> Vec<(u64, Hash)> {
        self.entries
            .iter()
            .rev()
            .take(count)
            .map(|(seq, (_, hash, _))| (*seq, *hash))
            .collect()
    }

    fn oldest(&self) -> Option<(u64, u64)> {
        self.entries
            .iter()
            .next()
            .map(|(seq, (at, _, _))| (*seq, *at))
    }

    fn last_appended_by(&self, at_ms: u64) -> Option<u64> {
        // Append times never decrease, so this is a prefix.
        self.entries
            .iter()
            .take_while(|(_, (at, _, _))| *at <= at_ms)
            .last()
            .map(|(seq, _)| *seq)
    }

    fn evict_through(&mut self, seq: u64) {
        let kept = self.entries.split_off(&(seq + 1));
        for (_, _, data) in std::mem::replace(&mut self.entries, kept).values() {
            self.bytes -= data.len() as u64;
        }
    }

    fn count(&self) -> u64 {
        self.entries.len() as u64
    }

    fn bytes(&self) -> u64 {
        self.bytes
    }

    fn commit(&self, epoch: u64) -> Option<(Hash, u64)> {
        self.commits.get(&epoch).copied()
    }

    fn put_commit(&mut self, epoch: u64, hash: &Hash, seq: u64) {
        self.commits.insert(epoch, (*hash, seq));
    }

    fn evict_commits_through(&mut self, seq: u64) {
        self.commits.retain(|_, (_, at)| *at > seq);
    }

    fn blob(&self, which: Blob) -> Option<Vec<u8>> {
        self.blobs.get(&which).cloned()
    }

    fn set_blob(&mut self, which: Blob, value: &[u8]) {
        self.blobs.insert(which, value.to_vec());
    }

    fn clear(&mut self) {
        *self = MemoryStore::default();
    }
}

// ---- Records kept as blobs -----------------------------------------------

const BLOB_VERSION: u8 = 1;

/// Key packages held for an inbox, and who owns the inbox.
#[derive(Debug, Default)]
struct Held {
    /// The identity that first published here. Only it may publish again,
    /// so nobody can stuff an inbox with key packages that are not its
    /// owner's.
    owner: Option<IdentityKey>,
    /// Single-use key packages and when each expires, oldest first.
    regular: Vec<(u64, Vec<u8>)>,
    /// Handed out, but never removed, once the regular ones run out, so an
    /// inbox can always be invited (RFC 9420, section 16.8).
    last_resort: Option<(u64, Vec<u8>)>,
    /// Recently published key packages. A publish that is retried or
    /// duplicated in flight must not store a package twice: two welcomes for
    /// one single-use package leave the second invitee unable to join.
    seen: Vec<Hash>,
    /// When regular key packages were last handed out (the past hour).
    claims: Vec<u64>,
}

const SEEN_MAX: usize = 8 * KEY_PACKAGES_MAX;

impl Held {
    fn load(store: &impl Store) -> Held {
        let Some(bytes) = store.blob(Blob::KeyPackages) else {
            return Held::default();
        };
        let mut r = Reader::new(&bytes);
        let decoded = (|| {
            if r.u8()? != BLOB_VERSION {
                return Err(DecodeError::BadValue);
            }
            let mut held = Held::default();
            if r.u8()? == 1 {
                held.owner = Some(r.array()?);
            }
            for _ in 0..r.count(KEY_PACKAGES_MAX)? {
                held.regular
                    .push((r.u64()?, r.bytes(MLS_MESSAGE_MAX)?.to_vec()));
            }
            if r.u8()? == 1 {
                held.last_resort = Some((r.u64()?, r.bytes(MLS_MESSAGE_MAX)?.to_vec()));
            }
            for _ in 0..r.count(SEEN_MAX)? {
                held.seen.push(r.array()?);
            }
            for _ in 0..r.count(CLAIMS_PER_HOUR)? {
                held.claims.push(r.u64()?);
            }
            Ok(held)
        })();
        decoded.expect("held key packages are corrupt")
    }

    fn save(&self, store: &mut impl Store) {
        let mut w = Writer::new();
        w.u8(BLOB_VERSION);
        match &self.owner {
            None => w.u8(0),
            Some(owner) => w.u8(1).array(owner),
        };
        w.count(self.regular.len());
        for (expires, kp) in &self.regular {
            w.u64(*expires).bytes(kp);
        }
        match &self.last_resort {
            None => w.u8(0),
            Some((expires, kp)) => w.u8(1).u64(*expires).bytes(kp),
        };
        w.count(self.seen.len());
        for hash in &self.seen {
            w.array(hash);
        }
        w.count(self.claims.len());
        for at in &self.claims {
            w.u64(*at);
        }
        store.set_blob(Blob::KeyPackages, &w.finish());
    }

    /// Drops expired key packages, and any for another ciphersuite (published
    /// before an upgrade); returns whether anything changed.
    fn expire(&mut self, now_ms: u64) -> bool {
        let before = self.regular.len();
        self.regular
            .retain(|(expires, kp)| *expires > now_ms && current_suite(kp));
        let mut changed = self.regular.len() != before;
        if self
            .last_resort
            .as_ref()
            .is_some_and(|(expires, kp)| *expires <= now_ms || !current_suite(kp))
        {
            self.last_resort = None;
            changed = true;
        }
        changed
    }

    fn next_expiry(&self) -> Option<u64> {
        let regular = self.regular.iter().map(|(expires, _)| *expires);
        regular
            .chain(self.last_resort.iter().map(|(expires, _)| *expires))
            .min()
    }
}

/// Whether a stored key package is for krypt's ciphersuite.
fn current_suite(key_package: &[u8]) -> bool {
    // A KeyPackage starts with its protocol version, then its ciphersuite.
    key_package.get(2..4) == Some(&(CIPHERSUITE as u16).to_be_bytes()[..])
}

/// Push targets registered for a log, with when each registration lapses.
#[derive(Debug, Default)]
struct Watchers(Vec<(u64, Vec<u8>)>);

impl Watchers {
    fn load(store: &impl Store) -> Watchers {
        let Some(bytes) = store.blob(Blob::Watchers) else {
            return Watchers::default();
        };
        let mut r = Reader::new(&bytes);
        let decoded = (|| {
            if r.u8()? != BLOB_VERSION {
                return Err(DecodeError::BadValue);
            }
            let mut watchers = Vec::new();
            for _ in 0..r.count(WATCHERS_MAX)? {
                watchers.push((
                    r.u64()?,
                    r.bytes(4 + krypt_wire::limits::PUSH_ADDRESS_MAX + 1)?
                        .to_vec(),
                ));
            }
            Ok(Watchers(watchers))
        })();
        decoded.expect("watchers are corrupt")
    }

    fn save(&self, store: &mut impl Store) {
        let mut w = Writer::new();
        w.u8(BLOB_VERSION).count(self.0.len());
        for (expires, target) in &self.0 {
            w.u64(*expires).bytes(target);
        }
        store.set_blob(Blob::Watchers, &w.finish());
    }
}

/// Epochs a log keeps write keys for: the current one and those whose
/// messages are still accepted.
#[allow(clippy::cast_possible_truncation)]
const WRITE_KEYS_MAX: usize = PAST_EPOCHS_MAX as usize + 1;

/// Write keys of the epochs a log still accepts writes for.
#[derive(Debug, Default)]
struct WriteKeys(Vec<(u64, [u8; 32])>);

impl WriteKeys {
    fn load(store: &impl Store) -> WriteKeys {
        let Some(bytes) = store.blob(Blob::WriteKeys) else {
            return WriteKeys::default();
        };
        let mut r = Reader::new(&bytes);
        let decoded = (|| {
            if r.u8()? != BLOB_VERSION {
                return Err(DecodeError::BadValue);
            }
            let mut keys = Vec::new();
            for _ in 0..r.count(WRITE_KEYS_MAX)? {
                keys.push((r.u64()?, r.array()?));
            }
            Ok(WriteKeys(keys))
        })();
        decoded.expect("write keys are corrupt")
    }

    fn save(&self, store: &mut impl Store) {
        let mut w = Writer::new();
        w.u8(BLOB_VERSION).count(self.0.len());
        for (epoch, key) in &self.0 {
            w.u64(*epoch).array(key);
        }
        store.set_blob(Blob::WriteKeys, &w.finish());
    }

    fn get(&self, epoch: u64) -> Option<&[u8; 32]> {
        self.0.iter().find(|(e, _)| *e == epoch).map(|(_, key)| key)
    }

    /// Adds an epoch's key, keeping only the epochs writes are accepted for.
    fn insert(&mut self, epoch: u64, key: [u8; 32]) {
        self.0
            .retain(|(e, _)| *e + PAST_EPOCHS_MAX >= epoch && *e != epoch);
        self.0.push((epoch, key));
    }
}

/// Welcomes one conversation may forward to one inbox in an hour: adding
/// someone (each of their devices has its own inbox) takes one. More would
/// only flood the inbox, evicting the invitations it should keep.
const WELCOMES_PER_INBOX_HOUR: u32 = 8;
/// Inboxes one conversation may invite in an hour: a whole new group.
const INVITED_INBOXES_HOUR: usize = 2 * GROUP_MEMBERS_MAX;

/// The welcomes this conversation forwarded to each inbox in the current
/// hour ([`Blob::Invites`]).
#[derive(Debug, Default)]
struct Invites {
    hour: u64,
    sent: Vec<(Route, u32)>,
}

impl Invites {
    fn load(store: &impl Store) -> Invites {
        let Some(bytes) = store.blob(Blob::Invites) else {
            return Invites::default();
        };
        let mut r = Reader::new(&bytes);
        let decoded = (|| {
            if r.u8()? != BLOB_VERSION {
                return Err(DecodeError::BadValue);
            }
            let hour = r.u64()?;
            let count = r.u32()? as usize;
            if count > INVITED_INBOXES_HOUR {
                return Err(DecodeError::BadValue);
            }
            let mut sent = Vec::with_capacity(count);
            for _ in 0..count {
                sent.push((r.array()?, r.u32()?));
            }
            r.finish()?;
            Ok(Invites { hour, sent })
        })();
        decoded.expect("invite counts are corrupt")
    }

    fn save(&self, store: &mut impl Store) {
        let mut w = Writer::with_capacity(11 + self.sent.len() * 20);
        w.u8(BLOB_VERSION)
            .u64(self.hour)
            .u32(u32::try_from(self.sent.len()).expect("bounded by INVITED_INBOXES_HOUR"));
        for (inbox, count) in &self.sent {
            w.array(inbox).u32(*count);
        }
        store.set_blob(Blob::Invites, &w.finish());
    }

    /// Counts one welcome to `inbox`: false if this hour's allowance for it
    /// (or for new inboxes) is spent.
    fn charge(&mut self, inbox: Route, now_ms: u64) -> bool {
        let hour = now_ms / HOUR_MS;
        if self.hour != hour {
            *self = Invites {
                hour,
                sent: Vec::new(),
            };
        }
        if let Some((_, count)) = self.sent.iter_mut().find(|(r, _)| *r == inbox) {
            if *count >= WELCOMES_PER_INBOX_HOUR {
                return false;
            }
            *count += 1;
            return true;
        }
        if self.sent.len() >= INVITED_INBOXES_HOUR {
            return false;
        }
        self.sent.push((inbox, 1));
        true
    }
}

/// What the conversation's members used of an allowance on one day (days
/// since the Unix epoch): file bytes stored, or relay credentials issued.
#[derive(Debug, Default)]
struct DailyQuota {
    day: u64,
    used: u64,
}

impl DailyQuota {
    fn load(store: &impl Store, blob: Blob) -> DailyQuota {
        let Some(bytes) = store.blob(blob) else {
            return DailyQuota::default();
        };
        let mut r = Reader::new(&bytes);
        let decoded = (|| {
            if r.u8()? != BLOB_VERSION {
                return Err(DecodeError::BadValue);
            }
            let quota = DailyQuota {
                day: r.u64()?,
                used: r.u64()?,
            };
            r.finish()?;
            Ok(quota)
        })();
        decoded.expect("daily quota is corrupt")
    }

    /// Charges `amount` against today's `max`, writing one row if it fits.
    fn charge(store: &mut impl Store, blob: Blob, now_ms: u64, amount: u64, max: u64) -> bool {
        let mut quota = DailyQuota::load(store, blob);
        let day = now_ms / DAY_MS;
        if quota.day != day {
            quota = DailyQuota { day, used: 0 };
        }
        let used = quota.used + amount;
        if used > max {
            return false;
        }
        quota.used = used;
        let mut w = Writer::with_capacity(17);
        w.u8(BLOB_VERSION).u64(quota.day).u64(quota.used);
        store.set_blob(blob, &w.finish());
        true
    }
}

/// Checks a proof of current membership in a conversation log: `epoch` is
/// the epoch it claims, and `proves` checks it against that epoch's write
/// key. Returns the log's epoch, or the response refusing it.
fn current_member(
    store: &impl Store,
    epoch: u64,
    proves: impl Fn(&[u8; 32]) -> bool,
) -> Result<u64, (Kind, Vec<u8>)> {
    let Some(meta) = store.meta() else {
        return Err(rejected(Reject::UnknownLog, 0));
    };
    if meta.kind != LogKind::Conversation {
        return Err(rejected(Reject::Malformed, 0));
    }
    if epoch < meta.epoch {
        return Err(rejected(Reject::StaleEpoch, meta.epoch));
    }
    if epoch > meta.epoch {
        return Err(rejected(Reject::FutureEpoch, meta.epoch));
    }
    if !WriteKeys::load(store).get(epoch).is_some_and(proves) {
        return Err(rejected(Reject::Forbidden, 0));
    }
    Ok(meta.epoch)
}

// ---- The state machine ---------------------------------------------------

/// An entry the driver must append to another log, at least once.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Forward {
    pub route: Route,
    pub entry: Vec<u8>,
}

/// The outcome of one request.
#[derive(Debug, Default)]
pub struct Handled {
    /// The response frame; `None` if the frame was not a request.
    pub response: Option<Vec<u8>>,
    /// Entries for other logs (welcomes for new members' inboxes).
    pub forwards: Vec<Forward>,
    /// A `Notify` frame for every device connected to this log.
    pub notify: Option<Vec<u8>>,
    /// Push targets to wake (encoded [`PushTarget`]s), already coalesced.
    pub wakeups: Vec<Vec<u8>>,
}

/// The outcome of delivering a forwarded entry.
#[derive(Debug, Default)]
pub struct Delivered {
    pub notify: Option<Vec<u8>>,
    pub wakeups: Vec<Vec<u8>>,
}

/// The mailbox for one log. Holds only a cache of when each push target was
/// last woken (losing it costs at most one extra push).
#[derive(Debug, Default)]
pub struct Mailbox {
    crypto: RustCrypto,
    last_push: BTreeMap<Hash, u64>,
}

/// What the mailbox read from an MLS message's public framing.
struct Framing {
    epoch: u64,
    content_type: ContentType,
}

fn framing(message: &[u8]) -> Option<Framing> {
    let message = MlsMessageIn::tls_deserialize_exact(message).ok()?;
    match message.extract() {
        MlsMessageBodyIn::PrivateMessage(private) => Some(Framing {
            epoch: private.epoch().as_u64(),
            content_type: private.content_type(),
        }),
        _ => None,
    }
}

fn rejected(reason: Reject, epoch: u64) -> (Kind, Vec<u8>) {
    (Kind::Rejected, Rejected { reason, epoch }.encode())
}

fn accepted(seq: u64) -> (Kind, Vec<u8>) {
    (Kind::Accepted, Accepted { seq }.encode())
}

/// The seq the next entry gets.
fn next_seq(store: &impl Store, meta: &Meta) -> u64 {
    store.last_seq().unwrap_or(0).max(meta.evicted_through) + 1
}

impl Mailbox {
    pub fn new() -> Mailbox {
        Mailbox::default()
    }

    /// Handles one request frame for this log.
    pub fn handle(&mut self, store: &mut impl Store, now_ms: u64, frame: &Frame<'_>) -> Handled {
        let mut handled = Handled::default();
        let (kind, body) = match frame.kind {
            Kind::Submit => self.submit(store, now_ms, frame.route, frame.body, &mut handled),
            Kind::Fetch => self.fetch(store, now_ms, frame.body),
            Kind::PublishKeyPackages => self.publish(store, now_ms, frame.route, frame.body),
            Kind::ClaimKeyPackage => self.claim(store, now_ms),
            Kind::Watch => self.watch(store, now_ms, frame.route, frame.body),
            Kind::AuthorizeFile => Self::authorize_file(store, now_ms, frame.route, frame.body),
            Kind::AuthorizeTurn => Self::authorize_turn(store, now_ms, frame.route, frame.body),
            Kind::Signal => Self::signal(store, frame.route, frame.body, &mut handled),
            Kind::OpenRequests => Self::open_requests(store, now_ms, frame.route, frame.body),
            Kind::JoinRequest => {
                self.join_request(store, now_ms, frame.route, frame.body, &mut handled)
            }
            Kind::JoinHeader => Self::join_header(store),
            _ => return handled,
        };
        handled.response = Some(frame::encode_vec(kind, frame.seq, frame.route, &body));
        handled
    }

    /// Appends a forwarded entry (a welcome) to this inbox unless it is
    /// already there.
    pub fn deliver(&mut self, store: &mut impl Store, now_ms: u64, forward: &Forward) -> Delivered {
        let mut meta = match store.meta() {
            Some(meta) if meta.kind == LogKind::Inbox => meta,
            Some(_) => return Delivered::default(),
            None => Meta {
                kind: LogKind::Inbox,
                epoch: 0,
                evicted_through: 0,
                touched_ms: now_ms,
            },
        };
        let hash = hash16(&forward.entry);
        if store
            .recent_hashes(DEDUP_SCAN)
            .iter()
            .any(|(_, h)| *h == hash)
        {
            return Delivered::default();
        }
        let seq = self.append(store, &mut meta, now_ms, &hash, &forward.entry);
        meta.touched_ms = now_ms;
        store.set_meta(&meta);
        let (notify, wakeups) =
            self.announce(store, now_ms, forward.route, seq, &forward.entry, true);
        Delivered { notify, wakeups }
    }

    /// Current epoch of a conversation log, if it exists.
    pub fn epoch(store: &impl Store) -> Option<u64> {
        store
            .meta()
            .filter(|meta| meta.kind == LogKind::Conversation)
            .map(|meta| meta.epoch)
    }

    /// Drops whatever has expired. Returns when to call again, or `None` once
    /// the log is gone (idle too long, or never created).
    pub fn expire(&mut self, store: &mut impl Store, now_ms: u64) -> Option<u64> {
        let mut meta = store.meta()?;
        if now_ms >= meta.touched_ms.saturating_add(IDLE_DELETE_MS) {
            store.clear();
            self.last_push.clear();
            return None;
        }
        if let Some(seq) = store.last_appended_by(now_ms.saturating_sub(RETENTION_MS)) {
            Self::evict(store, &mut meta, seq);
            store.set_meta(&meta);
        }
        let mut watchers = Watchers::load(store);
        let before = watchers.0.len();
        watchers.0.retain(|(expires, _)| *expires > now_ms);
        if watchers.0.len() != before {
            watchers.save(store);
        }
        let mut held = Held::load(store);
        if held.expire(now_ms) {
            held.save(store);
        }
        Self::deadline_of(store, &meta, &watchers, &held)
    }

    /// Drops a push target its push service says is gone (HTTP 404/410), so
    /// it is never woken again. `target` is the encoded [`PushTarget`].
    pub fn forget(store: &mut impl Store, target: &[u8]) {
        let mut watchers = Watchers::load(store);
        let before = watchers.0.len();
        watchers.0.retain(|(_, t)| t != target);
        if watchers.0.len() != before {
            watchers.save(store);
        }
    }

    /// When [`Mailbox::expire`] next has something to do.
    pub fn deadline(store: &impl Store) -> Option<u64> {
        let meta = store.meta()?;
        Self::deadline_of(store, &meta, &Watchers::load(store), &Held::load(store))
    }

    fn deadline_of(
        store: &impl Store,
        meta: &Meta,
        watchers: &Watchers,
        held: &Held,
    ) -> Option<u64> {
        let idle = meta.touched_ms.saturating_add(IDLE_DELETE_MS);
        let entry = store
            .oldest()
            .map(|(_, at)| at.saturating_add(RETENTION_MS));
        let watcher = watchers.0.iter().map(|(expires, _)| *expires).min();
        [Some(idle), entry, watcher, held.next_expiry()]
            .into_iter()
            .flatten()
            .min()
    }

    fn evict(store: &mut impl Store, meta: &mut Meta, through: u64) {
        store.evict_through(through);
        store.evict_commits_through(through);
        meta.evicted_through = meta.evicted_through.max(through);
    }

    /// Appends within the log's limits, evicting the oldest entries in a
    /// batch when either limit would be crossed.
    fn append(
        &mut self,
        store: &mut impl Store,
        meta: &mut Meta,
        now_ms: u64,
        hash: &Hash,
        data: &[u8],
    ) -> u64 {
        let len = data.len() as u64;
        if store.count() + 1 > LOG_ENTRIES_MAX as u64 || store.bytes() + len > LOG_BYTES_MAX {
            let keep_count = LOG_ENTRIES_MAX as u64 * EVICT_TO_NUMERATOR / EVICT_TO_DENOMINATOR;
            let keep_bytes = LOG_BYTES_MAX * EVICT_TO_NUMERATOR / EVICT_TO_DENOMINATOR
                - len.min(LOG_BYTES_MAX / 2);
            let mut through = meta.evicted_through;
            let (mut count, mut bytes) = (store.count(), store.bytes());
            for (seq, len) in store.sizes(meta.evicted_through, LOG_ENTRIES_MAX) {
                if count <= keep_count && bytes <= keep_bytes {
                    break;
                }
                count -= 1;
                bytes -= len;
                through = seq;
            }
            Self::evict(store, meta, through);
            store.set_meta(meta);
        }
        let seq = next_seq(store, meta);
        store.append(seq, now_ms, hash, data);
        seq
    }

    /// The push for a new entry: a `Notify` for connected devices (with the
    /// entry inline when small) and coalesced wakeups for the rest.
    fn announce(
        &mut self,
        store: &impl Store,
        now_ms: u64,
        route: Route,
        seq: u64,
        data: &[u8],
        wake: bool,
    ) -> (Option<Vec<u8>>, Vec<Vec<u8>>) {
        let entries = if data.len() <= NOTIFY_INLINE_MAX {
            vec![Entry { seq, data }]
        } else {
            Vec::new()
        };
        let body = Entries {
            next: seq + 1,
            entries,
        }
        .encode();
        let notify = frame::encode_vec(Kind::Notify, 0, route, &body);

        let mut wakeups = Vec::new();
        if !wake {
            return (Some(notify), wakeups);
        }
        for (expires, target) in Watchers::load(store).0 {
            if expires <= now_ms {
                continue;
            }
            let key = hash16(&target);
            let last = self.last_push.get(&key).copied();
            if last.is_none_or(|last| now_ms >= last + PUSH_COALESCE_MS) {
                self.last_push.insert(key, now_ms);
                wakeups.push(target);
            }
        }
        (Some(notify), wakeups)
    }

    /// Marks the log as used, writing metadata at most once a day.
    fn touch(store: &mut impl Store, meta: &mut Meta, now_ms: u64) {
        if now_ms >= meta.touched_ms + TOUCH_INTERVAL_MS {
            meta.touched_ms = now_ms;
            store.set_meta(meta);
        }
    }

    fn submit(
        &mut self,
        store: &mut impl Store,
        now_ms: u64,
        route: Route,
        body: &[u8],
        handled: &mut Handled,
    ) -> (Kind, Vec<u8>) {
        let Ok(submit) = Submit::decode(body) else {
            return rejected(Reject::Malformed, 0);
        };
        let Some(framing) = framing(submit.message) else {
            return rejected(Reject::Malformed, 0);
        };
        let hash = hash16(submit.message);
        let existing = store.meta();
        if existing.is_some_and(|meta| meta.kind != LogKind::Conversation) {
            return rejected(Reject::Malformed, 0);
        }

        let seq = match framing.content_type {
            ContentType::Commit => {
                let mut meta = match existing {
                    Some(meta) => meta,
                    // The first commit of a group, from epoch 0, creates its log.
                    None if framing.epoch == 0 => Meta {
                        kind: LogKind::Conversation,
                        epoch: 0,
                        evicted_through: 0,
                        touched_ms: now_ms,
                    },
                    None => return rejected(Reject::UnknownLog, 0),
                };
                // A retry of an accepted commit gets the original answer,
                // even though the log has moved on.
                if let Some((accepted_hash, seq)) = store.commit(framing.epoch)
                    && accepted_hash == hash
                {
                    return accepted(seq);
                }
                if framing.epoch < meta.epoch {
                    return rejected(Reject::StaleEpoch, meta.epoch);
                }
                if framing.epoch > meta.epoch {
                    return rejected(Reject::FutureEpoch, meta.epoch);
                }
                let Some(next_key) = submit.next_key else {
                    return rejected(Reject::Malformed, 0);
                };
                let mut keys = WriteKeys::load(store);
                // Only members may change the group. The commit that creates
                // the log must be signed by the key the route was derived from.
                let authorized = match existing {
                    Some(_) => keys.get(framing.epoch).is_some_and(|key| {
                        constant_time_eq(&write_tag(key, &route, submit.message), &submit.auth)
                    }),
                    None => submit.creation.is_some_and(|(key, signature)| {
                        creation_route(&key) == route
                            && ed25519_dalek::VerifyingKey::from_bytes(&key).is_ok_and(|key| {
                                let signed = creation_signed_bytes(&route, submit.message);
                                let signature = ed25519_dalek::Signature::from_bytes(&signature);
                                key.verify_strict(&signed, &signature).is_ok()
                            })
                    }),
                };
                if !authorized {
                    return rejected(Reject::Forbidden, 0);
                }
                let seq = self.append(store, &mut meta, now_ms, &hash, submit.message);
                store.put_commit(framing.epoch, &hash, seq);
                keys.insert(framing.epoch + 1, next_key);
                keys.save(store);
                meta.epoch += 1;
                meta.touched_ms = now_ms;
                store.set_meta(&meta);
                // Welcomes past an inbox's hourly allowance are dropped: the
                // commit stands, and that device is simply not invited.
                let mut invites = Invites::load(store);
                for welcome in &submit.welcomes {
                    if !invites.charge(welcome.inbox, now_ms) {
                        continue;
                    }
                    let entry = InboxWelcome {
                        conversation: route,
                        join_after: seq,
                        welcome: welcome.welcome,
                    };
                    handled.forwards.push(Forward {
                        route: welcome.inbox,
                        entry: entry.encode(),
                    });
                }
                if !submit.welcomes.is_empty() {
                    invites.save(store);
                }
                seq
            }
            ContentType::Application => {
                if !submit.welcomes.is_empty() {
                    return rejected(Reject::Malformed, 0);
                }
                let Some(mut meta) = existing else {
                    return rejected(Reject::UnknownLog, 0);
                };
                if let Some((seq, _)) = store
                    .recent_hashes(DEDUP_SCAN)
                    .into_iter()
                    .find(|(_, h)| *h == hash)
                {
                    return accepted(seq);
                }
                if framing.epoch > meta.epoch {
                    return rejected(Reject::FutureEpoch, meta.epoch);
                }
                if framing.epoch + PAST_EPOCHS_MAX < meta.epoch {
                    return rejected(Reject::TooOld, meta.epoch);
                }
                let authorized = WriteKeys::load(store)
                    .get(framing.epoch)
                    .is_some_and(|key| {
                        constant_time_eq(&write_tag(key, &route, submit.message), &submit.auth)
                    });
                if !authorized {
                    return rejected(Reject::Forbidden, 0);
                }
                let seq = self.append(store, &mut meta, now_ms, &hash, submit.message);
                Self::touch(store, &mut meta, now_ms);
                seq
            }
            ContentType::Proposal => return rejected(Reject::Malformed, 0),
        };
        // A quiet message (a receipt, an edit) reaches open sockets but wakes
        // nobody; commits always wake.
        let wake = !(submit.quiet && framing.content_type == ContentType::Application);
        let (notify, wakeups) = self.announce(store, now_ms, route, seq, submit.message, wake);
        handled.notify = notify;
        handled.wakeups = wakeups;
        accepted(seq)
    }

    /// Lets a member store one part of a file, within the conversation's
    /// daily allowance. One row written. Parts are stored by the edge, not
    /// here; only the current epoch's members are allowed, like messages.
    fn authorize_file(
        store: &mut impl Store,
        now_ms: u64,
        route: Route,
        body: &[u8],
    ) -> (Kind, Vec<u8>) {
        let Ok(part) = FilePart::decode(body) else {
            return rejected(Reject::Malformed, 0);
        };
        let epoch = match current_member(store, part.epoch, |key| {
            constant_time_eq(&file_tag(key, &route, &part), &part.auth)
        }) {
            Ok(epoch) => epoch,
            Err(response) => return response,
        };
        let len = u64::from(part.len);
        if !DailyQuota::charge(store, Blob::FileQuota, now_ms, len, FILE_BYTES_PER_DAY) {
            return rejected(Reject::OverQuota, epoch);
        }
        accepted(0)
    }

    /// Lets a member obtain call relay credentials, within the
    /// conversation's daily allowance. One row written. The edge issues
    /// them; only the current epoch's members are allowed.
    fn authorize_turn(
        store: &mut impl Store,
        now_ms: u64,
        route: Route,
        body: &[u8],
    ) -> (Kind, Vec<u8>) {
        let Ok(grant) = TurnGrant::decode(body) else {
            return rejected(Reject::Malformed, 0);
        };
        let epoch = match current_member(store, grant.epoch, |key| {
            constant_time_eq(&turn_tag(key, &route), &grant.auth)
        }) {
            Ok(epoch) => epoch,
            Err(response) => return response,
        };
        let max = u64::from(TURN_GRANTS_PER_DAY);
        if !DailyQuota::charge(store, Blob::TurnQuota, now_ms, 1, max) {
            return rejected(Reject::OverQuota, epoch);
        }
        accepted(0)
    }

    /// Relays a member's signal to every device connected to the log, as it
    /// came. Nothing is written: a device that is not connected never sees
    /// it, which is the point.
    fn signal(
        store: &impl Store,
        route: Route,
        body: &[u8],
        handled: &mut Handled,
    ) -> (Kind, Vec<u8>) {
        let Ok(signal) = Signal::decode(body) else {
            return rejected(Reject::Malformed, 0);
        };
        if let Err(response) = current_member(store, signal.epoch, |key| {
            constant_time_eq(&signal_tag(key, &route, signal.sealed), &signal.auth)
        }) {
            return response;
        }
        handled.notify = Some(frame::encode_vec(Kind::Signaled, 0, route, body));
        accepted(0)
    }

    /// Opens a group's requests log for its invite link, or (by the same
    /// admin key) keeps it open and refreshes its header. The first to open
    /// a route owns it; nobody else may write its header.
    fn open_requests(
        store: &mut impl Store,
        now_ms: u64,
        route: Route,
        body: &[u8],
    ) -> (Kind, Vec<u8>) {
        let Ok(open) = OpenRequests::decode(body) else {
            return rejected(Reject::Malformed, 0);
        };
        let signed = OpenRequests::signed_bytes(&route, &open.admin, &open.token, open.header);
        let signed_by_admin =
            ed25519_dalek::VerifyingKey::from_bytes(&open.admin).is_ok_and(|key| {
                key.verify_strict(
                    &signed,
                    &ed25519_dalek::Signature::from_bytes(&open.signature),
                )
                .is_ok()
            });
        // The route is the admin key's: nobody else can open it, even
        // once it has lapsed.
        if !signed_by_admin || crate::join::requests_route(&open.admin) != route {
            return rejected(Reject::Forbidden, 0);
        }
        let mut meta = match store.meta() {
            Some(meta) if meta.kind != LogKind::Requests => return rejected(Reject::Forbidden, 0),
            Some(meta) => {
                let held = store.blob(Blob::Requests).unwrap_or_default();
                if held.get(..32) != Some(&open.admin[..]) {
                    return rejected(Reject::Forbidden, 0);
                }
                meta
            }
            None => Meta {
                kind: LogKind::Requests,
                epoch: 0,
                evicted_through: 0,
                touched_ms: now_ms,
            },
        };
        store.set_blob(
            Blob::Requests,
            &[&open.admin[..], &open.token, open.header].concat(),
        );
        meta.touched_ms = now_ms;
        store.set_meta(&meta);
        accepted(0)
    }

    /// Someone with the link asks to join: kept (sealed; only the group's
    /// admins can read it) if it carries the link's token, up to the log's
    /// limit, and pushed to admins who have the app open. Nobody is woken.
    fn join_request(
        &mut self,
        store: &mut impl Store,
        now_ms: u64,
        route: Route,
        body: &[u8],
        handled: &mut Handled,
    ) -> (Kind, Vec<u8>) {
        let Ok(request) = JoinRequest::decode(body) else {
            return rejected(Reject::Malformed, 0);
        };
        let Some(mut meta) = store.meta().filter(|m| m.kind == LogKind::Requests) else {
            return rejected(Reject::UnknownLog, 0);
        };
        let held = store.blob(Blob::Requests).unwrap_or_default();
        if !held
            .get(32..48)
            .is_some_and(|token| constant_time_eq(token, &request.token))
        {
            return rejected(Reject::Forbidden, 0);
        }
        let hash = hash16(request.sealed);
        if let Some((seq, _)) = store
            .recent_hashes(DEDUP_SCAN)
            .into_iter()
            .find(|(_, h)| *h == hash)
        {
            return accepted(seq);
        }
        if store.count() >= JOIN_REQUESTS_MAX {
            return rejected(Reject::OverQuota, 0);
        }
        let seq = self.append(store, &mut meta, now_ms, &hash, request.sealed);
        Self::touch(store, &mut meta, now_ms);
        let (notify, _) = self.announce(store, now_ms, route, seq, request.sealed, false);
        handled.notify = notify;
        accepted(seq)
    }

    /// The header of a requests log, for whoever has the link.
    fn join_header(store: &impl Store) -> (Kind, Vec<u8>) {
        match (store.meta(), store.blob(Blob::Requests)) {
            (Some(meta), Some(held)) if meta.kind == LogKind::Requests && held.len() >= 48 => {
                (Kind::Header, held[48..].to_vec())
            }
            _ => rejected(Reject::UnknownLog, 0),
        }
    }

    fn fetch(&mut self, store: &mut impl Store, now_ms: u64, body: &[u8]) -> (Kind, Vec<u8>) {
        let Ok(fetch) = Fetch::decode(body) else {
            return rejected(Reject::Malformed, 0);
        };
        let Some(mut meta) = store.meta() else {
            // A log nobody has written to yet is simply empty.
            return (
                Kind::Entries,
                Entries {
                    next: 1,
                    entries: Vec::new(),
                }
                .encode(),
            );
        };
        // Invitations and requests that lapsed are simply gone, and their
        // reader carries on from what is left (stopping would leave an inbox
        // flooded with junk unreadable for good); a conversation's reader
        // must know it missed something.
        let after = match meta.kind {
            LogKind::Requests | LogKind::Inbox => fetch.after.max(meta.evicted_through),
            _ if fetch.after < meta.evicted_through => {
                return rejected(Reject::Evicted, meta.epoch);
            }
            _ => fetch.after,
        };
        let mut size = Entries::EMPTY_SIZE;
        let rows = store.range(after, fetch.max as usize, u64::from(FRAME_BODY_MAX));
        let mut entries = Vec::with_capacity(rows.len());
        for (seq, data) in &rows {
            let entry_size = Entries::entry_size(data.len());
            if size + entry_size > FRAME_BODY_MAX as usize {
                break;
            }
            size += entry_size;
            entries.push(Entry { seq: *seq, data });
        }
        let next = next_seq(store, &meta);
        Self::touch(store, &mut meta, now_ms);
        (Kind::Entries, Entries { next, entries }.encode())
    }

    /// An inbox's meta, or a new one (written only once something is
    /// stored: a refused publish leaves nothing behind).
    fn inbox_meta(store: &impl Store, now_ms: u64) -> Option<Meta> {
        match store.meta() {
            Some(meta) if meta.kind == LogKind::Inbox => Some(meta),
            Some(_) => None,
            None => Some(Meta {
                kind: LogKind::Inbox,
                epoch: 0,
                evicted_through: 0,
                touched_ms: now_ms,
            }),
        }
    }

    fn publish(
        &mut self,
        store: &mut impl Store,
        now_ms: u64,
        route: Route,
        body: &[u8],
    ) -> (Kind, Vec<u8>) {
        let Ok(list) = KeyPackages::decode(body) else {
            return rejected(Reject::Malformed, 0);
        };
        let existed = store.meta().is_some();
        let Some(mut meta) = Self::inbox_meta(store, now_ms) else {
            return rejected(Reject::Malformed, 0);
        };
        if list.list.is_empty() && !existed {
            return rejected(Reject::Malformed, 0);
        }
        let mut held = Held::load(store);
        // Only well-formed, correctly signed key packages, certified for this
        // inbox by its owner, are worth handing out.
        let mut validated = Vec::with_capacity(list.list.len());
        for bytes in &list.list {
            let Some(kp) = KeyPackageIn::tls_deserialize_exact(bytes)
                .ok()
                .and_then(|kp| kp.validate(&self.crypto, ProtocolVersion::Mls10).ok())
                .filter(|kp| kp.ciphersuite() == CIPHERSUITE)
            else {
                return rejected(Reject::Malformed, 0);
            };
            let leaf = kp.leaf_node();
            let cert = BasicCredential::try_from(leaf.credential().clone())
                .ok()
                .and_then(|basic| DeviceCert::decode(basic.identity()).ok())
                .filter(|cert| {
                    cert.inbox == route
                        && cert.mls_signature_key.as_slice() == leaf.signature_key().as_slice()
                });
            let Some(cert) = cert else {
                return rejected(Reject::Malformed, 0);
            };
            if *held.owner.get_or_insert(cert.identity) != cert.identity {
                return rejected(Reject::NotOwner, 0);
            }
            let expires = kp.life_time().not_after().saturating_mul(1000);
            validated.push((kp.last_resort(), expires, bytes.to_vec()));
        }
        for (last_resort, expires, key_package) in validated {
            let hash = hash16(&key_package);
            if held.seen.contains(&hash) || expires <= now_ms + DAY_MS {
                continue;
            }
            if held.seen.len() == SEEN_MAX {
                held.seen.remove(0);
            }
            held.seen.push(hash);
            if last_resort {
                held.last_resort = Some((expires, key_package));
                continue;
            }
            if held.regular.len() == KEY_PACKAGES_MAX {
                held.regular.remove(0);
            }
            held.regular.push((expires, key_package));
        }
        held.save(store);
        if existed {
            Self::touch(store, &mut meta, now_ms);
        } else {
            store.set_meta(&meta);
        }
        accepted(held.regular.len() as u64)
    }

    fn claim(&mut self, store: &mut impl Store, now_ms: u64) -> (Kind, Vec<u8>) {
        let mut held = Held::load(store);
        let mut changed = held.expire(now_ms);
        held.claims.retain(|at| at + HOUR_MS > now_ms);
        // Packages from before an update that conversations now need (from a
        // device not opened since, or queued ahead of its new set) would only
        // fail the invite: they go, and the inviter waits for ones that join.
        let key_package = loop {
            if held.regular.is_empty() || held.claims.len() >= CLAIMS_PER_HOUR {
                if held
                    .last_resort
                    .as_ref()
                    .is_some_and(|(_, kp)| !self.joins(kp))
                {
                    held.last_resort = None;
                    changed = true;
                }
                break held.last_resort.as_ref().map(|(_, kp)| kp.clone());
            }
            changed = true;
            let (_, key_package) = held.regular.remove(0);
            if self.joins(&key_package) {
                held.claims.push(now_ms);
                break Some(key_package);
            }
        };
        if changed {
            held.save(store);
        }
        match key_package {
            Some(key_package) => (Kind::KeyPackage, key_package),
            None => rejected(Reject::NoKeyPackages, 0),
        }
    }

    /// Whether a held key package (checked when it was published) can join
    /// the conversations krypt makes now.
    fn joins(&self, key_package: &[u8]) -> bool {
        KeyPackageIn::tls_deserialize_exact(key_package)
            .ok()
            .and_then(|kp| kp.validate(&self.crypto, ProtocolVersion::Mls10).ok())
            .is_some_and(|kp| joins_new_conversations(kp.leaf_node().capabilities()))
    }

    fn watch(
        &mut self,
        store: &mut impl Store,
        now_ms: u64,
        route: Route,
        body: &[u8],
    ) -> (Kind, Vec<u8>) {
        let Ok(watch) = Watch::decode(body) else {
            return rejected(Reject::Malformed, 0);
        };
        let Some(mut meta) = store.meta() else {
            return rejected(Reject::UnknownLog, 0);
        };
        // Who gets woken reveals when a log is active: only members of a
        // conversation, or the owner of an inbox, may register.
        let signed = Watch::signed_bytes(&route, watch.enable, &watch.target);
        let authorized = match meta.kind {
            LogKind::Conversation => WriteKeys::load(store)
                .0
                .iter()
                .any(|(_, key)| constant_time_eq(&watch_tag(key, &signed), watch.proof)),
            LogKind::Inbox => Held::load(store).owner.is_some_and(|owner| {
                let signature = <[u8; 64]>::try_from(watch.proof);
                let key = ed25519_dalek::VerifyingKey::from_bytes(&owner);
                matches!((key, signature), (Ok(key), Ok(sig))
                    if key.verify_strict(&signed, &ed25519_dalek::Signature::from_bytes(&sig)).is_ok())
            }),
            // Nobody is woken for requests: admins see them in the app.
            LogKind::Requests => false,
        };
        if !authorized {
            return rejected(Reject::Forbidden, 0);
        }
        let target = watch.target.encode();
        let mut watchers = Watchers::load(store);
        watchers
            .0
            .retain(|(expires, existing)| *existing != target && *expires > now_ms);
        if watch.enable {
            if watchers.0.len() == WATCHERS_MAX {
                // Make room by dropping the registration closest to lapsing.
                let soonest = (0..watchers.0.len())
                    .min_by_key(|&i| watchers.0[i].0)
                    .expect("full");
                watchers.0.swap_remove(soonest);
            }
            watchers.0.push((now_ms + WATCH_TTL_MS, target));
        }
        watchers.save(store);
        Self::touch(store, &mut meta, now_ms);
        accepted(0)
    }
}

/// Decodes a push target as stored for a watcher.
pub fn push_target(bytes: &[u8]) -> Option<PushTarget<'_>> {
    PushTarget::decode(bytes).ok()
}

// ---- Every log in one process -------------------------------------------

/// Every log in one process: for tests, benchmarks, the simulator and local
/// development. Production splits logs across Durable Objects.
#[derive(Debug, Default)]
pub struct LocalMailbox {
    logs: BTreeMap<Route, (Mailbox, MemoryStore)>,
    notifications: Vec<(Route, Vec<u8>)>,
    wakeups: Vec<(Route, Vec<u8>)>,
}

impl LocalMailbox {
    pub fn new() -> LocalMailbox {
        LocalMailbox::default()
    }

    fn log(&mut self, route: Route) -> &mut (Mailbox, MemoryStore) {
        self.logs.entry(route).or_default()
    }

    /// Handles a request, leaving forwards to the caller.
    pub fn handle_request(&mut self, now_ms: u64, request: &[u8]) -> Option<(Route, Handled)> {
        let frame = frame::decode(request).ok()?;
        let (mailbox, store) = self.log(frame.route);
        let handled = mailbox.handle(store, now_ms, &frame);
        Some((frame.route, handled))
    }

    pub fn deliver(&mut self, now_ms: u64, forward: &Forward) -> Delivered {
        let (mailbox, store) = self.log(forward.route);
        mailbox.deliver(store, now_ms, forward)
    }

    /// Handles a request, delivering its forwards at once, and returns the
    /// response frame. Pushes queue up for [`LocalMailbox::take_notifications`].
    pub fn handle(&mut self, now_ms: u64, request: &[u8]) -> Option<Vec<u8>> {
        let (route, handled) = self.handle_request(now_ms, request)?;
        if let Some(notify) = handled.notify {
            self.notifications.push((route, notify));
        }
        self.wakeups
            .extend(handled.wakeups.into_iter().map(|w| (route, w)));
        for forward in &handled.forwards {
            let delivered = self.deliver(now_ms, forward);
            if let Some(notify) = delivered.notify {
                self.notifications.push((forward.route, notify));
            }
            self.wakeups
                .extend(delivered.wakeups.into_iter().map(|w| (forward.route, w)));
        }
        handled.response
    }

    /// `Notify` frames produced since the last call, by route.
    pub fn take_notifications(&mut self) -> Vec<(Route, Vec<u8>)> {
        std::mem::take(&mut self.notifications)
    }

    /// Wakeups produced since the last call, by route.
    pub fn take_wakeups(&mut self) -> Vec<(Route, Vec<u8>)> {
        std::mem::take(&mut self.wakeups)
    }

    /// Runs expiry on every log, dropping the ones that are gone.
    pub fn expire(&mut self, now_ms: u64) {
        self.logs
            .retain(|_, (mailbox, store)| mailbox.expire(store, now_ms).is_some());
    }

    pub fn epoch(&self, route: &Route) -> Option<u64> {
        self.logs
            .get(route)
            .and_then(|(_, store)| Mailbox::epoch(store))
    }

    /// Whether a log (conversation or inbox) exists at `route`.
    pub fn exists(&self, route: &Route) -> bool {
        self.logs
            .get(route)
            .is_some_and(|(_, store)| store.meta().is_some())
    }

    /// Every stored payload, for scanning what the mailbox holds.
    pub fn values(&self) -> impl Iterator<Item = &[u8]> {
        self.logs.values().flat_map(|(_, store)| store.values())
    }

    /// The push targets (encoded) registered at a log.
    pub fn watchers(&self, route: &Route) -> Vec<Vec<u8>> {
        self.logs
            .get(route)
            .map(|(_, store)| {
                Watchers::load(store)
                    .0
                    .into_iter()
                    .map(|(_, t)| t)
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_packages_for_another_ciphersuite_are_dropped() {
        // A KeyPackage starts with its protocol version (MLS 1.0 is 1) and
        // ciphersuite; 0x0001 is the classic one.
        let classic = vec![0, 1, 0, 1, 7, 7];
        let current = [&[0, 1][..], &(CIPHERSUITE as u16).to_be_bytes(), &[7, 7]].concat();
        let mut held = Held {
            regular: vec![(DAY_MS, classic.clone()), (DAY_MS, current.clone())],
            last_resort: Some((DAY_MS, classic)),
            ..Held::default()
        };
        assert!(held.expire(0));
        assert_eq!(held.regular, vec![(DAY_MS, current.clone())]);
        assert_eq!(held.last_resort, None);

        held.last_resort = Some((DAY_MS, current));
        assert!(!held.expire(0), "current ones stay");
    }

    /// A key package whose leaf supports `extensions` (beyond krypt's
    /// ciphersuite), signed by a key made from `seed`.
    fn key_package(seed: u8, extensions: &[u16], last_resort: bool) -> Vec<u8> {
        use openmls::prelude::tls_codec::Serialize as _;
        use openmls::prelude::{Capabilities, CredentialWithKey, ExtensionType, KeyPackage};
        use openmls_basic_credential::SignatureKeyPair;
        use openmls_traits::types::SignatureScheme;

        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let signer = SignatureKeyPair::from_raw(
            SignatureScheme::ED25519,
            key.to_bytes().to_vec(),
            key.verifying_key().to_bytes().to_vec(),
        );
        let mut supported: Vec<ExtensionType> =
            extensions.iter().map(|&e| ExtensionType::Unknown(e)).collect();
        let builder = KeyPackage::builder();
        let builder = if last_resort {
            supported.push(ExtensionType::LastResort);
            builder.mark_as_last_resort()
        } else {
            builder
        };
        let provider = crate::provider::Provider::new(
            crate::provider::Rand::seeded(seed.into()),
            crate::mls_store::MlsStore::default(),
        );
        builder
            .leaf_node_capabilities(
                Capabilities::builder()
                    .ciphersuites(vec![CIPHERSUITE])
                    .extensions(supported)
                    .build(),
            )
            .build(
                CIPHERSUITE,
                &provider,
                &signer,
                CredentialWithKey {
                    credential: BasicCredential::new(vec![seed]).into(),
                    signature_key: signer.public().into(),
                },
            )
            .expect("builds")
            .key_package()
            .tls_serialize_detached()
            .expect("serializes")
    }

    #[test]
    fn key_packages_from_before_group_rules_are_never_handed_out() {
        // Before group rules (0xF0D2), leaves supported only the timer
        // (0xF0D1); every conversation krypt makes now requires both.
        let old = |seed| key_package(seed, &[0xF0D1], false);
        let current = key_package(3, &[0xF0D1, 0xF0D2], false);
        let mut mailbox = Mailbox::new();
        let mut store = MemoryStore::default();

        // A device's new set, published behind its old one.
        Held {
            regular: vec![(DAY_MS, old(1)), (DAY_MS, old(2)), (DAY_MS, current.clone())],
            last_resort: Some((DAY_MS, key_package(4, &[0xF0D1], true))),
            ..Held::default()
        }
        .save(&mut store);
        assert_eq!(
            mailbox.claim(&mut store, 0),
            (Kind::KeyPackage, current),
            "the first that joins"
        );
        let held = Held::load(&store);
        assert!(held.regular.is_empty(), "the old ones are gone");
        assert_eq!(held.claims.len(), 1, "one claim counted");

        // A device not opened since: nobody is handed a package that fails.
        assert_eq!(
            mailbox.claim(&mut store, 0),
            rejected(Reject::NoKeyPackages, 0)
        );
        assert_eq!(Held::load(&store).last_resort, None);
    }

    #[test]
    fn eviction_runs_in_batches_and_keeps_seqs_contiguous() {
        let mut mailbox = Mailbox::new();
        let mut store = MemoryStore::default();
        let mut meta = Meta {
            kind: LogKind::Conversation,
            epoch: 0,
            evicted_through: 0,
            touched_ms: 0,
        };
        for i in 0..LOG_ENTRIES_MAX as u64 + 1 {
            let data = i.to_le_bytes();
            assert_eq!(
                mailbox.append(&mut store, &mut meta, i, &hash16(&data), &data),
                i + 1
            );
        }
        // Crossing the limit evicted a batch down to 15/16 of it.
        assert_eq!(store.count(), LOG_ENTRIES_MAX as u64 * 15 / 16 + 1);
        assert_eq!(meta.evicted_through + 1, store.oldest().unwrap().0);
        assert_eq!(next_seq(&store, &meta), LOG_ENTRIES_MAX as u64 + 2);
    }

    #[test]
    fn expiry_evicts_old_entries_then_deletes_the_idle_log() {
        let mut mailbox = Mailbox::new();
        let mut store = MemoryStore::default();
        let mut meta = Meta {
            kind: LogKind::Conversation,
            epoch: 3,
            evicted_through: 0,
            touched_ms: 0,
        };
        store.set_meta(&meta);
        for at in [0, 10, 20] {
            mailbox.append(&mut store, &mut meta, at, &hash16(&at.to_le_bytes()), b"x");
        }
        assert_eq!(Mailbox::deadline(&store), Some(RETENTION_MS));
        assert_eq!(
            mailbox.expire(&mut store, RETENTION_MS + 10),
            Some(RETENTION_MS + 20)
        );
        assert_eq!(store.count(), 1);
        assert_eq!(store.meta().unwrap().evicted_through, 2);
        // The epoch survives eviction; only idleness removes the log.
        assert_eq!(Mailbox::epoch(&store), Some(3));
        assert_eq!(mailbox.expire(&mut store, IDLE_DELETE_MS), None);
        assert_eq!(store.meta(), None);
    }

    #[test]
    fn pushes_are_coalesced_per_target() {
        let mut mailbox = Mailbox::new();
        let mut store = MemoryStore::default();
        store.set_meta(&Meta {
            kind: LogKind::Conversation,
            epoch: 1,
            evicted_through: 0,
            touched_ms: 0,
        });
        let target = PushTarget {
            platform: krypt_wire::msg::Platform::WebPush,
            address: b"https://push.example/1",
        };
        let key = [7u8; 32];
        let mut keys = WriteKeys::default();
        keys.insert(1, key);
        keys.save(&mut store);
        let signed = Watch::signed_bytes(&[0; 16], true, &target);
        let forged = Watch {
            enable: true,
            target,
            proof: &[0; 16],
        }
        .encode();
        assert_eq!(
            mailbox.watch(&mut store, 0, [0; 16], &forged).0,
            Kind::Rejected
        );
        let proof = watch_tag(&key, &signed);
        let watch = Watch {
            enable: true,
            target,
            proof: &proof,
        }
        .encode();
        assert_eq!(
            mailbox.watch(&mut store, 0, [0; 16], &watch).0,
            Kind::Accepted
        );
        // A quiet entry (a read receipt, an edit) reaches open sockets but
        // wakes nobody, and does not hold back the next real wakeup.
        let (notify, quiet) = mailbox.announce(&store, 500, [0; 16], 1, b"r", false);
        assert!(notify.is_some() && quiet.is_empty());
        let (_, first) = mailbox.announce(&store, 1_000, [0; 16], 1, b"a", true);
        let (_, burst) = mailbox.announce(&store, 2_000, [0; 16], 2, b"b", true);
        let (_, later) = mailbox.announce(&store, 1_000 + PUSH_COALESCE_MS, [0; 16], 3, b"c", true);
        assert_eq!((first.len(), burst.len(), later.len()), (1, 0, 1));
        // And a lapsed registration wakes nobody.
        let (_, lapsed) = mailbox.announce(&store, WATCH_TTL_MS + 1, [0; 16], 4, b"d", true);
        assert!(lapsed.is_empty());
        // Nor does one its push service has declared gone.
        let due = 1_000 + 3 * PUSH_COALESCE_MS;
        let (_, woken) = mailbox.announce(&store, due, [0; 16], 5, b"e", true);
        assert_eq!(woken.len(), 1);
        Mailbox::forget(&mut store, &target.encode());
        let (_, gone) = mailbox.announce(&store, due + PUSH_COALESCE_MS, [0; 16], 6, b"f", true);
        assert!(gone.is_empty());
    }

    #[test]
    fn only_current_members_store_files_within_the_allowance() {
        let route = [3u8; 16];
        let mut store = MemoryStore::default();
        let authorize = |store: &mut MemoryStore, now: u64, part: &FilePart| {
            let (kind, body) = Mailbox::authorize_file(store, now, route, &part.encode());
            match kind {
                Kind::Accepted => Ok(()),
                _ => Err(Rejected::decode(&body).unwrap().reason),
            }
        };
        let key = [7u8; 32];
        let mut part = FilePart {
            file: [1; 16],
            part: 0,
            len: krypt_wire::limits::FILE_PART_SIZE + 16,
            epoch: 2,
            auth: [0; 16],
        };
        part.auth = file_tag(&key, &route, &part);
        assert_eq!(authorize(&mut store, 0, &part), Err(Reject::UnknownLog));

        store.set_meta(&Meta {
            kind: LogKind::Conversation,
            epoch: 2,
            evicted_through: 0,
            touched_ms: 0,
        });
        let mut keys = WriteKeys::default();
        keys.insert(2, key);
        keys.save(&mut store);
        assert_eq!(authorize(&mut store, 0, &part), Ok(()));

        // A proof for another part, length or route, or a guess, fails.
        let moved = FilePart { part: 1, ..part };
        assert_eq!(authorize(&mut store, 0, &moved), Err(Reject::Forbidden));
        let forged = FilePart {
            auth: [9; 16],
            ..part
        };
        assert_eq!(authorize(&mut store, 0, &forged), Err(Reject::Forbidden));
        let (kind, _) = Mailbox::authorize_file(&mut store, 0, [4; 16], &part.encode());
        assert_eq!(kind, Kind::Rejected);

        // After a commit, the old epoch's proof is stale, even from a member.
        store.set_meta(&Meta {
            kind: LogKind::Conversation,
            epoch: 3,
            evicted_through: 0,
            touched_ms: 0,
        });
        assert_eq!(authorize(&mut store, 0, &part), Err(Reject::StaleEpoch));

        // The day's allowance runs out, and comes back the next day.
        let key = [8u8; 32];
        let mut keys = WriteKeys::default();
        keys.insert(3, key);
        keys.save(&mut store);
        let mut part = FilePart { epoch: 3, ..part };
        part.auth = file_tag(&key, &route, &part);
        let per_day = FILE_BYTES_PER_DAY / u64::from(part.len);
        for _ in 0..per_day {
            assert_eq!(authorize(&mut store, DAY_MS, &part), Ok(()));
        }
        assert_eq!(authorize(&mut store, DAY_MS, &part), Err(Reject::OverQuota));
        assert_eq!(authorize(&mut store, 2 * DAY_MS, &part), Ok(()));
    }

    #[test]
    fn only_current_members_get_relay_credentials_within_the_allowance() {
        let route = [3u8; 16];
        let mut store = MemoryStore::default();
        let authorize = |store: &mut MemoryStore, now: u64, route: Route, grant: &TurnGrant| {
            let (kind, body) = Mailbox::authorize_turn(store, now, route, &grant.encode());
            match kind {
                Kind::Accepted => Ok(()),
                _ => Err(Rejected::decode(&body).unwrap().reason),
            }
        };
        let key = [7u8; 32];
        let grant = TurnGrant {
            epoch: 2,
            auth: turn_tag(&key, &route),
        };
        assert_eq!(
            authorize(&mut store, 0, route, &grant),
            Err(Reject::UnknownLog)
        );
        store.set_meta(&Meta {
            kind: LogKind::Conversation,
            epoch: 2,
            evicted_through: 0,
            touched_ms: 0,
        });
        let mut keys = WriteKeys::default();
        keys.insert(2, key);
        keys.save(&mut store);

        // A guess, or a proof for another conversation, fails, and costs nothing.
        let forged = TurnGrant {
            auth: [9; 16],
            ..grant
        };
        assert_eq!(
            authorize(&mut store, 0, route, &forged),
            Err(Reject::Forbidden)
        );
        let elsewhere = TurnGrant {
            auth: turn_tag(&key, &[4; 16]),
            ..grant
        };
        assert_eq!(
            authorize(&mut store, 0, route, &elsewhere),
            Err(Reject::Forbidden)
        );
        assert_eq!(
            authorize(&mut store, 0, route, &TurnGrant { epoch: 3, ..grant }),
            Err(Reject::FutureEpoch)
        );

        // The day's allowance runs out, and comes back the next day; the
        // file allowance is separate.
        for _ in 0..TURN_GRANTS_PER_DAY {
            assert_eq!(authorize(&mut store, 0, route, &grant), Ok(()));
        }
        assert_eq!(
            authorize(&mut store, 0, route, &grant),
            Err(Reject::OverQuota)
        );
        assert_eq!(authorize(&mut store, DAY_MS, route, &grant), Ok(()));
        assert!(store.blob(Blob::FileQuota).is_none());
    }

    #[test]
    fn notify_carries_small_entries_inline() {
        let mut mailbox = Mailbox::new();
        let store = MemoryStore::default();
        let (notify, _) = mailbox.announce(&store, 0, [5; 16], 9, b"hello", true);
        let notify = notify.unwrap();
        let frame = frame::decode(&notify).unwrap();
        assert_eq!(frame.kind, Kind::Notify);
        let entries = Entries::decode(frame.body).unwrap();
        assert_eq!(entries.next, 10);
        assert_eq!(
            entries.entries,
            vec![Entry {
                seq: 9,
                data: b"hello"
            }]
        );
    }

    #[test]
    fn deliver_is_idempotent() {
        let mut local = LocalMailbox::new();
        let forward = Forward {
            route: [2; 16],
            entry: b"welcome".to_vec(),
        };
        assert!(local.deliver(0, &forward).notify.is_some());
        assert!(local.deliver(0, &forward).notify.is_none());
        assert_eq!(local.logs[&[2; 16]].1.count(), 1);
    }
}
