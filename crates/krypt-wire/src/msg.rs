//! Frame bodies. Decoders borrow from the input and enforce every limit.

use crate::codec::{DecodeError, Reader, Writer};
use crate::frame::Route;
use crate::limits::{
    CALL_SDP_MAX, DISAPPEAR_MAX_S, FETCH_ENTRIES_MAX, FILE_NAME_MAX, FILE_PART_SIZE,
    FILE_PARTS_MAX, FILE_SIZE_MAX, FILE_TAG_SIZE, FILE_TYPE_MAX, FRAME_BODY_MAX, JOIN_HEADER_MAX,
    JOIN_REQUEST_MAX, KEY_PACKAGES_MAX, PUSH_ADDRESS_MAX, REACTION_MAX, RECEIPT_REFS_MAX,
    SIGNAL_SEALED_MAX, TEXT_MAX, THUMBNAIL_MAX, VOICE_DURATION_MAX_MS, VOICE_SIZE_MAX,
    WAVEFORM_LEN, WELCOMES_PER_SUBMIT_MAX,
};

/// Largest serialized MLS message (commit, welcome, application message or
/// key package). Leaves room for framing so any single log entry always fits
/// in one `Entries` response.
pub const MLS_MESSAGE_MAX: usize = FRAME_BODY_MAX as usize - 1024;

/// Client to mailbox: append an MLS message to the log named by the frame's
/// route. A commit may carry welcomes, which the mailbox delivers to each
/// new member's inbox atomically with accepting the commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Submit<'a> {
    pub message: &'a [u8],
    pub welcomes: Vec<WelcomeFor<'a>>,
    /// Proof the submitter is a member: a tag over the message keyed by the
    /// write key of the message's epoch (exported from MLS).
    pub auth: [u8; 16],
    /// For a commit: the write key of the epoch it starts, so the mailbox can
    /// check the members' next writes.
    pub next_key: Option<[u8; 32]>,
    /// For the commit that creates a conversation: the creation key (whose
    /// hash is the conversation's route) and its signature over the message,
    /// so nobody can create the log with a different first commit.
    pub creation: Option<([u8; 32], [u8; 64])>,
    /// Stored and pushed to open sockets, but wakes no device: a read
    /// receipt, an edit, a reaction taken back. Encoded only when set (older
    /// submits have no flags byte).
    pub quiet: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WelcomeFor<'a> {
    pub inbox: Route,
    pub welcome: &'a [u8],
}

/// The only flag a submit carries so far.
const SUBMIT_QUIET: u8 = 1;

impl<'a> Submit<'a> {
    pub fn encode(&self) -> Vec<u8> {
        assert!(self.message.len() <= MLS_MESSAGE_MAX);
        assert!(self.welcomes.len() <= WELCOMES_PER_SUBMIT_MAX);
        let mut w = Writer::new();
        w.bytes(self.message).count(self.welcomes.len());
        for welcome in &self.welcomes {
            assert!(welcome.welcome.len() <= MLS_MESSAGE_MAX);
            w.array(&welcome.inbox).bytes(welcome.welcome);
        }
        w.array(&self.auth);
        match &self.next_key {
            None => w.u8(0),
            Some(key) => w.u8(1).array(key),
        };
        match &self.creation {
            None => w.u8(0),
            Some((key, signature)) => w.u8(1).array(key).array(signature),
        };
        if self.quiet {
            w.u8(SUBMIT_QUIET);
        }
        w.finish()
    }

    /// Bytes of an encoded submit carrying a message and welcomes of these
    /// sizes, with every optional field present.
    pub fn size_max(message: usize, welcomes: impl IntoIterator<Item = usize>) -> usize {
        let welcomes: usize = welcomes.into_iter().map(|w| 16 + 4 + w).sum();
        4 + message + 4 + welcomes + 16 + (1 + 32) + (1 + 32 + 64) + 1
    }

    pub fn decode(bytes: &'a [u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let message = r.bytes(MLS_MESSAGE_MAX)?;
        let n = r.count(WELCOMES_PER_SUBMIT_MAX)?;
        let mut welcomes = Vec::with_capacity(n);
        for _ in 0..n {
            welcomes.push(WelcomeFor {
                inbox: r.array()?,
                welcome: r.bytes(MLS_MESSAGE_MAX)?,
            });
        }
        let auth = r.array()?;
        let next_key = match r.u8()? {
            0 => None,
            1 => Some(r.array()?),
            _ => return Err(DecodeError::BadValue),
        };
        let creation = match r.u8()? {
            0 => None,
            1 => Some((r.array()?, r.array()?)),
            _ => return Err(DecodeError::BadValue),
        };
        // Flags are present only when one is set, so each submit has one
        // encoding.
        let quiet = if r.remaining() > 0 {
            if r.u8()? != SUBMIT_QUIET {
                return Err(DecodeError::BadValue);
            }
            true
        } else {
            false
        };
        r.finish()?;
        Ok(Submit {
            message,
            welcomes,
            auth,
            next_key,
            creation,
            quiet,
        })
    }
}

/// Client to mailbox: read entries with `seq > after`, at most `max` of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fetch {
    pub after: u64,
    pub max: u32,
}

impl Fetch {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(12);
        w.u64(self.after).u32(self.max);
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let fetch = Fetch {
            after: r.u64()?,
            max: r.u32()?,
        };
        r.finish()?;
        if fetch.max == 0 || fetch.max > FETCH_ENTRIES_MAX {
            return Err(DecodeError::BadValue);
        }
        Ok(fetch)
    }
}

/// Mailbox to client: the submission was appended at `seq`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Accepted {
    pub seq: u64,
}

impl Accepted {
    pub fn encode(&self) -> Vec<u8> {
        self.seq.to_le_bytes().to_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let seq = r.u64()?;
        r.finish()?;
        Ok(Accepted { seq })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Reject {
    /// A commit for an epoch that is no longer current.
    StaleEpoch = 1,
    /// An application message from an epoch members no longer keep keys for.
    TooOld = 2,
    /// The log does not exist (and the submission could not create it).
    UnknownLog = 3,
    /// The body or the MLS message in it did not parse.
    Malformed = 4,
    /// The inbox has no key packages to hand out.
    NoKeyPackages = 5,
    /// The requested entries were evicted; the reader fell too far behind.
    Evicted = 6,
    /// A commit for an epoch the log has not reached.
    FutureEpoch = 7,
    /// Key packages for an inbox from someone other than its owner.
    NotOwner = 8,
    /// A write without valid proof of membership.
    Forbidden = 9,
    /// The conversation has stored its day's allowance of file bytes.
    OverQuota = 10,
}

impl Reject {
    fn from_u8(byte: u8) -> Option<Reject> {
        Some(match byte {
            1 => Reject::StaleEpoch,
            2 => Reject::TooOld,
            3 => Reject::UnknownLog,
            4 => Reject::Malformed,
            5 => Reject::NoKeyPackages,
            6 => Reject::Evicted,
            7 => Reject::FutureEpoch,
            8 => Reject::NotOwner,
            9 => Reject::Forbidden,
            10 => Reject::OverQuota,
            _ => return None,
        })
    }
}

/// Mailbox to client: the request was refused. `epoch` is the log's current
/// epoch where that is meaningful, so a client knows how far behind it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rejected {
    pub reason: Reject,
    pub epoch: u64,
}

impl Rejected {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(9);
        w.u8(self.reason as u8).u64(self.epoch);
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let reason = Reject::from_u8(r.u8()?).ok_or(DecodeError::BadValue)?;
        let epoch = r.u64()?;
        r.finish()?;
        Ok(Rejected { reason, epoch })
    }
}

/// Mailbox to client: a run of log entries in increasing `seq` order. `next`
/// is the seq the next appended entry will get, so `next - 1` is the tip.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entries<'a> {
    pub next: u64,
    pub entries: Vec<Entry<'a>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry<'a> {
    pub seq: u64,
    pub data: &'a [u8],
}

impl<'a> Entries<'a> {
    /// Bytes an entry adds to an encoded `Entries` body.
    pub const fn entry_size(data_len: usize) -> usize {
        8 + 4 + data_len
    }

    /// Bytes of an encoded `Entries` body with no entries.
    pub const EMPTY_SIZE: usize = 8 + 4;

    pub fn encode(&self) -> Vec<u8> {
        assert!(self.entries.len() <= FETCH_ENTRIES_MAX as usize);
        let mut w = Writer::new();
        w.u64(self.next).count(self.entries.len());
        for entry in &self.entries {
            w.u64(entry.seq).bytes(entry.data);
        }
        assert!(w.len() <= FRAME_BODY_MAX as usize);
        w.finish()
    }

    pub fn decode(bytes: &'a [u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let next = r.u64()?;
        let n = r.count(FETCH_ENTRIES_MAX as usize)?;
        let mut entries = Vec::with_capacity(n);
        let mut last = None;
        for _ in 0..n {
            let entry = Entry {
                seq: r.u64()?,
                data: r.bytes(FRAME_BODY_MAX as usize)?,
            };
            // Entries must be strictly increasing and below `next`.
            if last.is_some_and(|last| entry.seq <= last) || entry.seq >= next {
                return Err(DecodeError::BadValue);
            }
            last = Some(entry.seq);
            entries.push(entry);
        }
        r.finish()?;
        Ok(Entries { next, entries })
    }
}

/// An inbox log entry: an invitation into a conversation. The new member
/// starts reading the conversation log after `join_after`, the seq of the
/// commit that added it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InboxWelcome<'a> {
    pub conversation: Route,
    pub join_after: u64,
    pub welcome: &'a [u8],
}

impl<'a> InboxWelcome<'a> {
    pub fn encode(&self) -> Vec<u8> {
        assert!(self.welcome.len() <= MLS_MESSAGE_MAX);
        let mut w = Writer::with_capacity(16 + 8 + 4 + self.welcome.len());
        w.array(&self.conversation)
            .u64(self.join_after)
            .bytes(self.welcome);
        w.finish()
    }

    pub fn decode(bytes: &'a [u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let welcome = InboxWelcome {
            conversation: r.array()?,
            join_after: r.u64()?,
            welcome: r.bytes(MLS_MESSAGE_MAX)?,
        };
        r.finish()?;
        Ok(welcome)
    }
}

/// Client to mailbox: key packages to hold for the inbox named by the route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyPackages<'a> {
    pub list: Vec<&'a [u8]>,
}

impl<'a> KeyPackages<'a> {
    pub fn encode(&self) -> Vec<u8> {
        assert!(self.list.len() <= KEY_PACKAGES_MAX);
        let mut w = Writer::new();
        w.count(self.list.len());
        for key_package in &self.list {
            w.bytes(key_package);
        }
        assert!(w.len() <= FRAME_BODY_MAX as usize);
        w.finish()
    }

    pub fn decode(bytes: &'a [u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let n = r.count(KEY_PACKAGES_MAX)?;
        let mut list = Vec::with_capacity(n);
        for _ in 0..n {
            list.push(r.bytes(MLS_MESSAGE_MAX)?);
        }
        r.finish()?;
        Ok(KeyPackages { list })
    }
}

/// Where to send a content-free wakeup for a device that is not connected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PushTarget<'a> {
    pub platform: Platform,
    /// A Web Push endpoint URL, an APNs device token, or an FCM token.
    pub address: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Platform {
    WebPush = 1,
    Apns = 2,
    Fcm = 3,
}

impl Platform {
    pub fn from_u8(byte: u8) -> Option<Platform> {
        Some(match byte {
            1 => Platform::WebPush,
            2 => Platform::Apns,
            3 => Platform::Fcm,
            _ => return None,
        })
    }
}

impl<'a> PushTarget<'a> {
    pub fn encode(&self) -> Vec<u8> {
        assert!(self.address.len() <= PUSH_ADDRESS_MAX);
        let mut w = Writer::with_capacity(5 + self.address.len());
        w.u8(self.platform as u8).bytes(self.address);
        w.finish()
    }

    pub fn decode(bytes: &'a [u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let platform = Platform::from_u8(r.u8()?).ok_or(DecodeError::BadValue)?;
        let address = r.bytes(PUSH_ADDRESS_MAX)?;
        r.finish()?;
        if address.is_empty() {
            return Err(DecodeError::BadValue);
        }
        Ok(PushTarget { platform, address })
    }
}

/// Client to mailbox: wake this target when the route's log changes
/// (`enable`), or stop doing so.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Watch<'a> {
    pub enable: bool,
    pub target: PushTarget<'a>,
    /// Proof the requester belongs: for a conversation, a tag keyed by a
    /// current write key; for an inbox, its owner's signature.
    pub proof: &'a [u8],
}

/// Longest watch proof (an Ed25519 signature).
pub const PROOF_MAX: usize = 64;

impl<'a> Watch<'a> {
    pub fn encode(&self) -> Vec<u8> {
        assert!(self.proof.len() <= PROOF_MAX);
        let mut w = Writer::new();
        w.u8(u8::from(self.enable))
            .bytes(&self.target.encode())
            .bytes(self.proof);
        w.finish()
    }

    pub fn decode(bytes: &'a [u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let enable = match r.u8()? {
            0 => false,
            1 => true,
            _ => return Err(DecodeError::BadValue),
        };
        let target = PushTarget::decode(r.bytes(PUSH_ADDRESS_MAX + 5)?)?;
        let proof = r.bytes(PROOF_MAX)?;
        r.finish()?;
        Ok(Watch {
            enable,
            target,
            proof,
        })
    }

    /// What a watch proof covers.
    pub fn signed_bytes(route: &Route, enable: bool, target: &PushTarget<'_>) -> Vec<u8> {
        let mut w = Writer::new();
        w.array(b"krypt watch v1")
            .array(route)
            .u8(u8::from(enable))
            .bytes(&target.encode());
        w.finish()
    }
}

/// Edge to mailbox, for a device uploading part of a file (the upload itself
/// goes to blob storage, not through the mailbox): may it be stored under the
/// frame's route? Only members may store files, each part proven with the
/// current epoch's write key, and each conversation only so many bytes a day.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FilePart {
    pub file: [u8; 16],
    pub part: u32,
    /// Stored bytes: the encrypted part with its tag.
    pub len: u32,
    pub epoch: u64,
    pub auth: [u8; 16],
}

impl FilePart {
    pub const SIZE: usize = 16 + 4 + 4 + 8 + 16;

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(Self::SIZE);
        w.array(&self.file)
            .u32(self.part)
            .u32(self.len)
            .u64(self.epoch)
            .array(&self.auth);
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let part = FilePart {
            file: r.array()?,
            part: r.u32()?,
            len: r.u32()?,
            epoch: r.u64()?,
            auth: r.array()?,
        };
        r.finish()?;
        if part.part >= FILE_PARTS_MAX
            || part.len < FILE_TAG_SIZE
            || part.len > FILE_PART_SIZE + FILE_TAG_SIZE
        {
            return Err(DecodeError::BadValue);
        }
        Ok(part)
    }
}

/// Edge to mailbox, for a device asking for call relay (TURN) credentials:
/// is it a member of the frame's route, proven with the current epoch's
/// write key, within the conversation's daily allowance?
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TurnGrant {
    pub epoch: u64,
    pub auth: [u8; 16],
}

impl TurnGrant {
    pub const SIZE: usize = 8 + 16;

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(Self::SIZE);
        w.u64(self.epoch).array(&self.auth);
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let grant = TurnGrant {
            epoch: r.u64()?,
            auth: r.array()?,
        };
        r.finish()?;
        Ok(grant)
    }
}

/// A signal for the members of a conversation connected right now: typing,
/// stopped, online, offline. The mailbox relays it to the log's open sockets
/// and stores nothing. `auth` proves membership in the current epoch (keyed
/// by its write key); `sealed` is encrypted and signed by the sending device
/// with keys the mailbox does not have.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signal<'a> {
    pub epoch: u64,
    pub auth: [u8; 16],
    pub sealed: &'a [u8],
}

impl<'a> Signal<'a> {
    pub fn encode(&self) -> Vec<u8> {
        assert!(self.sealed.len() <= SIGNAL_SEALED_MAX);
        let mut w = Writer::with_capacity(8 + 16 + 4 + self.sealed.len());
        w.u64(self.epoch).array(&self.auth).bytes(self.sealed);
        w.finish()
    }

    pub fn decode(bytes: &'a [u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let signal = Signal {
            epoch: r.u64()?,
            auth: r.array()?,
            sealed: r.bytes(SIGNAL_SEALED_MAX)?,
        };
        r.finish()?;
        Ok(signal)
    }
}

/// An admin opens a group's requests log (or touches it, or refreshes its
/// header): the log's admin key, the token requests must carry, and the
/// header people with the link read, signed by the admin key over the route
/// and all of it. The first to open a route owns it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenRequests<'a> {
    pub admin: [u8; 32],
    pub token: [u8; 16],
    pub header: &'a [u8],
    pub signature: [u8; 64],
}

impl<'a> OpenRequests<'a> {
    pub fn signed_bytes(
        route: &Route,
        admin: &[u8; 32],
        token: &[u8; 16],
        header: &[u8],
    ) -> Vec<u8> {
        [b"krypt requests v1".as_slice(), route, admin, token, header].concat()
    }

    pub fn encode(&self) -> Vec<u8> {
        assert!(self.header.len() <= JOIN_HEADER_MAX);
        let mut w = Writer::with_capacity(32 + 16 + 4 + self.header.len() + 64);
        w.array(&self.admin)
            .array(&self.token)
            .bytes(self.header)
            .array(&self.signature);
        w.finish()
    }

    pub fn decode(bytes: &'a [u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let open = OpenRequests {
            admin: r.array()?,
            token: r.array()?,
            header: r.bytes(JOIN_HEADER_MAX)?,
            signature: r.array()?,
        };
        r.finish()?;
        Ok(open)
    }
}

/// A request to join, sealed to the group's admins, with the link's token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JoinRequest<'a> {
    pub token: [u8; 16],
    pub sealed: &'a [u8],
}

impl<'a> JoinRequest<'a> {
    pub fn encode(&self) -> Vec<u8> {
        assert!(self.sealed.len() <= JOIN_REQUEST_MAX);
        let mut w = Writer::with_capacity(16 + 4 + self.sealed.len());
        w.array(&self.token).bytes(self.sealed);
        w.finish()
    }

    pub fn decode(bytes: &'a [u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let request = JoinRequest {
            token: r.array()?,
            sealed: r.bytes(JOIN_REQUEST_MAX)?,
        };
        r.finish()?;
        Ok(request)
    }
}

/// What a signal says.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum SignalKind {
    Typing = 1,
    /// Stopped typing (sent the message, cleared it, or paused).
    Idle = 2,
    Online = 3,
    Offline = 4,
    /// Online, and asking who else is: those online answer `Online`.
    Hello = 5,
}

impl SignalKind {
    pub fn from_u8(byte: u8) -> Option<SignalKind> {
        Some(match byte {
            1 => SignalKind::Typing,
            2 => SignalKind::Idle,
            3 => SignalKind::Online,
            4 => SignalKind::Offline,
            5 => SignalKind::Hello,
            _ => return None,
        })
    }
}

/// The plaintext inside an MLS application message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppMessage<'a> {
    /// Per-sender, per-conversation sequence number, starting at 1.
    pub sender_seq: u64,
    /// Sender's wall clock in milliseconds since the Unix epoch. Display only.
    pub sent_at_ms: u64,
    /// The conversation's disappearing-message timer when it was sent: each
    /// device deletes the message this many seconds after showing it. Zero
    /// keeps it.
    pub expires_after_s: u32,
    pub body: Body<'a>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Body<'a> {
    /// A chat message for the user.
    Text(&'a str),
    /// A file, stored encrypted under the conversation's route.
    File(FileRef<'a>),
    /// A step in setting up, changing or ending a call.
    Call(CallSignal<'a>),
    /// The sender's identity leaves the group: members remove all of its
    /// devices (a member cannot commit its own removal in MLS).
    Leave,
    /// A chat message that answers another.
    Reply { to: MessageRef, text: &'a str },
    /// The sender's reaction to a message, replacing any earlier one; empty
    /// takes it back.
    React { to: MessageRef, emoji: &'a str },
    /// New text for one of the sender's own messages.
    Edit { to: MessageRef, text: &'a str },
    /// One of the sender's own messages, deleted for everyone.
    Delete { to: MessageRef },
    /// What the sender has read: the newest message of each sender device.
    Receipt(ReadThrough<'a>),
    /// A voice message: a file, its length and a waveform to draw.
    Voice(VoiceRef<'a>),
}

impl Body<'_> {
    /// Whether the message should wake devices that are asleep. Receipts,
    /// edits and reactions taken back are only seen when someone looks.
    pub fn wakes(&self) -> bool {
        !matches!(
            self,
            Body::Receipt(_) | Body::Edit { .. } | Body::React { emoji: "", .. }
        )
    }
}

/// A message as every member names it: the device that sent it, and that
/// device's sequence number in the conversation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MessageRef {
    pub device: [u8; 32],
    pub seq: u64,
}

impl MessageRef {
    const SIZE: usize = 32 + 8;

    fn write(&self, w: &mut Writer) {
        w.array(&self.device).u64(self.seq);
    }

    fn read(r: &mut Reader<'_>) -> Result<MessageRef, DecodeError> {
        let device = r.array()?;
        let seq = r.u64()?;
        if seq == 0 {
            return Err(DecodeError::BadValue);
        }
        Ok(MessageRef { device, seq })
    }
}

/// Read watermarks, one per sender device, kept encoded so a body can
/// borrow them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadThrough<'a>(&'a [u8]);

impl<'a> ReadThrough<'a> {
    /// Encodes watermarks: 1 to `RECEIPT_REFS_MAX`, one per device.
    pub fn encode(refs: &[MessageRef]) -> Vec<u8> {
        assert!(!refs.is_empty() && refs.len() <= RECEIPT_REFS_MAX);
        let mut w = Writer::with_capacity(refs.len() * MessageRef::SIZE);
        for r in refs {
            r.write(&mut w);
        }
        let bytes = w.finish();
        assert!(
            ReadThrough::parse(&bytes).is_some(),
            "one watermark per device"
        );
        bytes
    }

    pub fn parse(bytes: &'a [u8]) -> Option<ReadThrough<'a>> {
        if bytes.is_empty()
            || !bytes.len().is_multiple_of(MessageRef::SIZE)
            || bytes.len() / MessageRef::SIZE > RECEIPT_REFS_MAX
        {
            return None;
        }
        let refs = ReadThrough(bytes);
        let mut devices: Vec<[u8; 32]> = Vec::with_capacity(bytes.len() / MessageRef::SIZE);
        for r in refs.try_iter() {
            let r = r.ok()?;
            if devices.contains(&r.device) {
                return None;
            }
            devices.push(r.device);
        }
        Some(refs)
    }

    fn try_iter(&self) -> impl Iterator<Item = Result<MessageRef, DecodeError>> + 'a {
        self.0
            .as_chunks::<{ MessageRef::SIZE }>()
            .0
            .iter()
            .map(|chunk| MessageRef::read(&mut Reader::new(chunk)))
    }

    pub fn iter(&self) -> impl Iterator<Item = MessageRef> + 'a {
        self.try_iter().map(|r| r.expect("checked when parsed"))
    }

    pub fn as_bytes(&self) -> &'a [u8] {
        self.0
    }
}

/// A voice message: an audio file (WebM or MP4, with Opus or AAC), its
/// length, and its loudness in `WAVEFORM_LEN` steps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VoiceRef<'a> {
    pub file: FileRef<'a>,
    pub duration_ms: u32,
    pub waveform: &'a [u8],
}

impl VoiceRef<'_> {
    pub fn valid(&self) -> bool {
        self.file.valid()
            && self.file.size <= VOICE_SIZE_MAX
            && matches!(self.file.media_type, "audio/webm" | "audio/mp4")
            && self.file.width == 0
            && self.file.height == 0
            && self.file.thumbnail.is_empty()
            && self.duration_ms <= VOICE_DURATION_MAX_MS
            && self.waveform.len() == WAVEFORM_LEN
    }
}

/// Whether `emoji` can be a reaction: short, and no control characters.
pub fn reaction_valid(emoji: &str) -> bool {
    emoji.len() <= REACTION_MAX && !emoji.chars().any(char::is_control)
}

/// Call signaling (WebRTC). Session descriptions carry each side's DTLS
/// fingerprint, so delivering them inside MLS authenticates the keys that
/// encrypt the call's media, end to end, even when it is relayed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallSignal<'a> {
    /// Random, chosen by the caller.
    pub call: [u8; 16],
    /// The device this is for, or all zeros for every device of the other
    /// members (a new call, and its end).
    pub to: [u8; 32],
    pub kind: CallKind,
    /// Whether the call has video (offers).
    pub video: bool,
    /// The session description of an offer or answer, newline-separated ICE
    /// candidates, or empty (an end).
    pub sdp: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallKind {
    /// A new call, or (to one device, during a call) a renegotiation.
    Offer,
    Answer,
    /// ICE candidates found after the description was sent.
    Candidates,
    End(CallEnd),
    /// This device is in the group call (to everyone): the first one rings
    /// the others, and each later joiner offers to everyone already in it.
    Join,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CallEnd {
    Hangup = 1,
    Declined = 2,
    /// The callee is in another call.
    Busy = 3,
    /// Nobody answered in time.
    Unanswered = 4,
    /// The connection could not be made, or was lost.
    Failed = 5,
}

impl CallEnd {
    fn from_u8(byte: u8) -> Option<CallEnd> {
        Some(match byte {
            1 => CallEnd::Hangup,
            2 => CallEnd::Declined,
            3 => CallEnd::Busy,
            4 => CallEnd::Unanswered,
            5 => CallEnd::Failed,
            _ => return None,
        })
    }
}

impl CallSignal<'_> {
    /// Whether every field is within its limit and fits its kind.
    pub fn valid(&self) -> bool {
        self.sdp.len() <= CALL_SDP_MAX
            && match self.kind {
                CallKind::Offer | CallKind::Answer | CallKind::Candidates => !self.sdp.is_empty(),
                CallKind::End(_) | CallKind::Join => self.sdp.is_empty(),
            }
    }
}

/// What a member needs to fetch and decrypt a shared file. The file's parts
/// are stored under the conversation's route and `id`; only the message
/// carries the key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileRef<'a> {
    pub id: [u8; 16],
    pub key: [u8; 32],
    /// Plaintext bytes.
    pub size: u64,
    pub name: &'a str,
    /// Media type, as the sender's device named it.
    pub media_type: &'a str,
    /// Pixel size of an image or video, or zero.
    pub width: u32,
    pub height: u32,
    /// A small preview image (JPEG), or empty.
    pub thumbnail: &'a [u8],
}

impl<'a> FileRef<'a> {
    fn write(&self, w: &mut Writer) {
        w.array(&self.id)
            .array(&self.key)
            .u64(self.size)
            .bytes(self.name.as_bytes())
            .bytes(self.media_type.as_bytes())
            .u32(self.width)
            .u32(self.height)
            .bytes(self.thumbnail);
    }

    fn read(r: &mut Reader<'a>) -> Result<FileRef<'a>, DecodeError> {
        let text = |bytes: &'a [u8]| std::str::from_utf8(bytes).map_err(|_| DecodeError::BadValue);
        let id = r.array()?;
        let key = r.array()?;
        let size = r.u64()?;
        let file = FileRef {
            id,
            key,
            size,
            name: text(r.bytes(FILE_NAME_MAX)?)?,
            media_type: text(r.bytes(FILE_TYPE_MAX)?)?,
            width: r.u32()?,
            height: r.u32()?,
            thumbnail: r.bytes(THUMBNAIL_MAX)?,
        };
        if !file.valid() {
            return Err(DecodeError::BadValue);
        }
        Ok(file)
    }

    /// Whether every field is within its limit.
    pub fn valid(&self) -> bool {
        self.size <= FILE_SIZE_MAX
            && self.name.len() <= FILE_NAME_MAX
            && self.media_type.len() <= FILE_TYPE_MAX
            && self.thumbnail.len() <= THUMBNAIL_MAX
    }
}

const APP_MESSAGE_VERSION: u8 = 2;
/// Before disappearing messages: no timer field, only text and files.
const APP_MESSAGE_VERSION_1: u8 = 1;
const APP_KIND_TEXT: u8 = 1;
// 2 was the retired direct-path presence message.
const APP_KIND_FILE: u8 = 3;
const APP_KIND_CALL: u8 = 4;
const APP_KIND_LEAVE: u8 = 5;
const APP_KIND_REPLY: u8 = 6;
const APP_KIND_REACT: u8 = 7;
const APP_KIND_EDIT: u8 = 8;
const APP_KIND_DELETE: u8 = 9;
const APP_KIND_RECEIPT: u8 = 10;
const APP_KIND_VOICE: u8 = 11;

const CALL_OFFER: u8 = 1;
const CALL_ANSWER: u8 = 2;
const CALL_CANDIDATES: u8 = 3;
const CALL_END: u8 = 4;
const CALL_JOIN: u8 = 5;

impl<'a> AppMessage<'a> {
    pub fn encode(&self) -> Vec<u8> {
        assert!(self.sender_seq > 0);
        assert!(self.expires_after_s <= DISAPPEAR_MAX_S);
        let kind = match self.body {
            Body::Text(_) => APP_KIND_TEXT,
            Body::File(_) => APP_KIND_FILE,
            Body::Call(_) => APP_KIND_CALL,
            Body::Leave => APP_KIND_LEAVE,
            Body::Reply { .. } => APP_KIND_REPLY,
            Body::React { .. } => APP_KIND_REACT,
            Body::Edit { .. } => APP_KIND_EDIT,
            Body::Delete { .. } => APP_KIND_DELETE,
            Body::Receipt(_) => APP_KIND_RECEIPT,
            Body::Voice(_) => APP_KIND_VOICE,
        };
        let mut w = Writer::with_capacity(64);
        w.u8(APP_MESSAGE_VERSION)
            .u8(kind)
            .u64(self.sender_seq)
            .u64(self.sent_at_ms)
            .u32(self.expires_after_s);
        match self.body {
            Body::Text(text) => {
                assert!(text.len() <= TEXT_MAX, "text exceeds TEXT_MAX");
                w.bytes(text.as_bytes());
            }
            Body::File(file) => {
                assert!(file.valid(), "file exceeds its limits");
                file.write(&mut w);
            }
            Body::Call(call) => {
                assert!(call.valid(), "call signal exceeds its limits");
                let (kind, reason) = match call.kind {
                    CallKind::Offer => (CALL_OFFER, 0),
                    CallKind::Answer => (CALL_ANSWER, 0),
                    CallKind::Candidates => (CALL_CANDIDATES, 0),
                    CallKind::End(reason) => (CALL_END, reason as u8),
                    CallKind::Join => (CALL_JOIN, 0),
                };
                w.array(&call.call)
                    .array(&call.to)
                    .u8(kind)
                    .u8(reason)
                    .u8(u8::from(call.video))
                    .bytes(call.sdp.as_bytes());
            }
            Body::Leave => {}
            Body::Reply { to, text } | Body::Edit { to, text } => {
                assert!(text.len() <= TEXT_MAX, "text exceeds TEXT_MAX");
                to.write(&mut w);
                w.bytes(text.as_bytes());
            }
            Body::React { to, emoji } => {
                assert!(reaction_valid(emoji), "not a reaction");
                to.write(&mut w);
                w.bytes(emoji.as_bytes());
            }
            Body::Delete { to } => to.write(&mut w),
            Body::Receipt(refs) => {
                w.bytes(refs.as_bytes());
            }
            Body::Voice(voice) => {
                assert!(voice.valid(), "voice message exceeds its limits");
                voice.file.write(&mut w);
                w.u32(voice.duration_ms).bytes(voice.waveform);
            }
        }
        w.finish()
    }

    pub fn decode(bytes: &'a [u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let version = r.u8()?;
        if version != APP_MESSAGE_VERSION && version != APP_MESSAGE_VERSION_1 {
            return Err(DecodeError::BadValue);
        }
        let kind = r.u8()?;
        let sender_seq = r.u64()?;
        let sent_at_ms = r.u64()?;
        let expires_after_s = if version == APP_MESSAGE_VERSION_1 {
            if kind != APP_KIND_TEXT && kind != APP_KIND_FILE {
                return Err(DecodeError::BadValue);
            }
            0
        } else {
            r.u32()?
        };
        if expires_after_s > DISAPPEAR_MAX_S {
            return Err(DecodeError::BadValue);
        }
        let text = |bytes: &'a [u8]| std::str::from_utf8(bytes).map_err(|_| DecodeError::BadValue);
        let body = match kind {
            APP_KIND_TEXT => Body::Text(text(r.bytes(TEXT_MAX)?)?),
            APP_KIND_FILE => Body::File(FileRef::read(&mut r)?),
            APP_KIND_CALL => {
                let call = r.array()?;
                let to = r.array()?;
                let kind = match (r.u8()?, r.u8()?) {
                    (CALL_OFFER, 0) => CallKind::Offer,
                    (CALL_ANSWER, 0) => CallKind::Answer,
                    (CALL_CANDIDATES, 0) => CallKind::Candidates,
                    (CALL_JOIN, 0) => CallKind::Join,
                    (CALL_END, reason) => {
                        CallKind::End(CallEnd::from_u8(reason).ok_or(DecodeError::BadValue)?)
                    }
                    _ => return Err(DecodeError::BadValue),
                };
                let video = match r.u8()? {
                    0 => false,
                    1 => true,
                    _ => return Err(DecodeError::BadValue),
                };
                let signal = CallSignal {
                    call,
                    to,
                    kind,
                    video,
                    sdp: text(r.bytes(CALL_SDP_MAX)?)?,
                };
                if !signal.valid() {
                    return Err(DecodeError::BadValue);
                }
                Body::Call(signal)
            }
            APP_KIND_LEAVE => Body::Leave,
            APP_KIND_REPLY => Body::Reply {
                to: MessageRef::read(&mut r)?,
                text: text(r.bytes(TEXT_MAX)?)?,
            },
            APP_KIND_EDIT => Body::Edit {
                to: MessageRef::read(&mut r)?,
                text: text(r.bytes(TEXT_MAX)?)?,
            },
            APP_KIND_REACT => {
                let to = MessageRef::read(&mut r)?;
                let emoji = text(r.bytes(REACTION_MAX)?)?;
                if !reaction_valid(emoji) {
                    return Err(DecodeError::BadValue);
                }
                Body::React { to, emoji }
            }
            APP_KIND_DELETE => Body::Delete {
                to: MessageRef::read(&mut r)?,
            },
            APP_KIND_RECEIPT => Body::Receipt(
                ReadThrough::parse(r.bytes(RECEIPT_REFS_MAX * MessageRef::SIZE)?)
                    .ok_or(DecodeError::BadValue)?,
            ),
            APP_KIND_VOICE => {
                let voice = VoiceRef {
                    file: FileRef::read(&mut r)?,
                    duration_ms: r.u32()?,
                    waveform: r.bytes(WAVEFORM_LEN)?,
                };
                if !voice.valid() {
                    return Err(DecodeError::BadValue);
                }
                Body::Voice(voice)
            }
            _ => return Err(DecodeError::BadValue),
        };
        r.finish()?;
        if sender_seq == 0 {
            return Err(DecodeError::BadValue);
        }
        Ok(AppMessage {
            sender_seq,
            sent_at_ms,
            expires_after_s,
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn submit_roundtrip() {
        let submit = Submit {
            message: b"commit",
            welcomes: vec![
                WelcomeFor {
                    inbox: [1; 16],
                    welcome: b"w1",
                },
                WelcomeFor {
                    inbox: [2; 16],
                    welcome: b"w2",
                },
            ],
            auth: [3; 16],
            next_key: Some([4; 32]),
            creation: Some(([5; 32], [6; 64])),
            quiet: true,
        };
        assert_eq!(Submit::decode(&submit.encode()).unwrap(), submit);
        assert_eq!(Submit::size_max(6, [2, 2]), submit.encode().len());
        // Not quiet: no flags byte, as before flags existed; an explicit
        // zero would be a second encoding, so it is refused.
        let loud = Submit {
            quiet: false,
            ..submit.clone()
        };
        let bytes = loud.encode();
        assert_eq!(bytes.len() + 1, submit.encode().len());
        assert_eq!(Submit::decode(&bytes).unwrap(), loud);
        assert!(Submit::decode(&[bytes.as_slice(), &[0]].concat()).is_err());
    }

    #[test]
    fn the_newer_message_kinds_round_trip_and_hold_their_limits() {
        let to = MessageRef {
            device: [7; 32],
            seq: 3,
        };
        let receipts = ReadThrough::encode(&[
            to,
            MessageRef {
                device: [8; 32],
                seq: 9,
            },
        ]);
        let waveform = [5u8; WAVEFORM_LEN];
        let voice = VoiceRef {
            file: FileRef {
                id: [1; 16],
                key: [2; 32],
                size: 4096,
                name: "voice.webm",
                media_type: "audio/webm",
                width: 0,
                height: 0,
                thumbnail: &[],
            },
            duration_ms: 3_000,
            waveform: &waveform,
        };
        let bodies = [
            Body::Reply { to, text: "yes" },
            Body::React {
                to, emoji: "👍🏽"
            },
            Body::React { to, emoji: "" },
            Body::Edit { to, text: "fixed" },
            Body::Delete { to },
            Body::Receipt(ReadThrough::parse(&receipts).unwrap()),
            Body::Voice(voice),
        ];
        for body in bodies {
            let message = AppMessage {
                sender_seq: 4,
                sent_at_ms: 5,
                expires_after_s: 0,
                body,
            };
            let bytes = message.encode();
            assert_eq!(AppMessage::decode(&bytes).unwrap(), message);
        }
        assert!(!Body::Receipt(ReadThrough::parse(&receipts).unwrap()).wakes());
        assert!(!Body::React { to, emoji: "" }.wakes());
        assert!(
            Body::React {
                to, emoji: "❤️"
            }
            .wakes()
        );
        assert!(
            Body::Delete { to }.wakes(),
            "a deletion reaches sleeping devices"
        );

        // One watermark per device; none at seq zero; none empty.
        let twice = [receipts.as_slice(), &receipts[..40]].concat();
        assert!(ReadThrough::parse(&twice).is_none());
        assert!(ReadThrough::parse(&[]).is_none());
        let mut zero = receipts.clone();
        zero[32..40].copy_from_slice(&0u64.to_le_bytes());
        assert!(ReadThrough::parse(&zero).is_none());
        // Reactions are short and printable.
        assert!(!reaction_valid("\u{7}"));
        assert!(!reaction_valid(&"😀".repeat(9)));
        // Voice messages are audio, small, short, with a full waveform.
        for bad in [
            VoiceRef {
                file: FileRef {
                    media_type: "text/html",
                    ..voice.file
                },
                ..voice
            },
            VoiceRef {
                file: FileRef {
                    size: VOICE_SIZE_MAX + 1,
                    ..voice.file
                },
                ..voice
            },
            VoiceRef {
                duration_ms: VOICE_DURATION_MAX_MS + 1,
                ..voice
            },
            VoiceRef {
                waveform: &waveform[1..],
                ..voice
            },
        ] {
            assert!(!bad.valid());
        }
    }

    #[test]
    fn entries_roundtrip_and_ordering() {
        let entries = Entries {
            next: 10,
            entries: vec![Entry { seq: 3, data: b"a" }, Entry { seq: 9, data: b"b" }],
        };
        assert_eq!(Entries::decode(&entries.encode()).unwrap(), entries);

        let unordered = Entries {
            next: 10,
            entries: vec![Entry { seq: 5, data: b"a" }, Entry { seq: 4, data: b"b" }],
        };
        assert_eq!(
            Entries::decode(&unordered.encode()),
            Err(DecodeError::BadValue)
        );

        let beyond_next = Entries {
            next: 4,
            entries: vec![Entry { seq: 4, data: b"a" }],
        };
        assert_eq!(
            Entries::decode(&beyond_next.encode()),
            Err(DecodeError::BadValue)
        );
    }

    #[test]
    fn fetch_bounds() {
        let ok = Fetch {
            after: 7,
            max: FETCH_ENTRIES_MAX,
        };
        assert_eq!(Fetch::decode(&ok.encode()).unwrap(), ok);
        assert!(Fetch::decode(&Fetch { after: 0, max: 0 }.encode()).is_err());
        assert!(
            Fetch::decode(
                &Fetch {
                    after: 0,
                    max: FETCH_ENTRIES_MAX + 1
                }
                .encode()
            )
            .is_err()
        );
    }

    #[test]
    fn rejected_roundtrip() {
        let rejected = Rejected {
            reason: Reject::StaleEpoch,
            epoch: 12,
        };
        assert_eq!(Rejected::decode(&rejected.encode()).unwrap(), rejected);
        assert!(Rejected::decode(&[0, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
    }

    #[test]
    fn app_message_roundtrip_and_validation() {
        let message = AppMessage {
            sender_seq: 3,
            sent_at_ms: 1_700_000_000_000,
            expires_after_s: 3600,
            body: Body::Text("hej ✓"),
        };
        assert_eq!(AppMessage::decode(&message.encode()).unwrap(), message);

        let mut bad_utf8 = AppMessage {
            sender_seq: 1,
            sent_at_ms: 0,
            expires_after_s: 0,
            body: Body::Text("ab"),
        }
        .encode();
        let n = bad_utf8.len();
        bad_utf8[n - 1] = 0xFF;
        assert_eq!(AppMessage::decode(&bad_utf8), Err(DecodeError::BadValue));
    }

    #[test]
    fn version_1_messages_still_decode() {
        // Version 1 had no timer field, and only text and files.
        let mut w = Writer::new();
        w.u8(1).u8(APP_KIND_TEXT).u64(5).u64(9).bytes(b"old");
        let encoded = w.finish();
        let message = AppMessage::decode(&encoded).unwrap();
        assert_eq!(
            message,
            AppMessage {
                sender_seq: 5,
                sent_at_ms: 9,
                expires_after_s: 0,
                body: Body::Text("old"),
            }
        );
        let mut w = Writer::new();
        w.u8(1).u8(APP_KIND_CALL).u64(5).u64(9).array(&[0; 48]);
        assert_eq!(AppMessage::decode(&w.finish()), Err(DecodeError::BadValue));
    }

    #[test]
    fn call_messages_roundtrip_and_limits() {
        let offer = CallSignal {
            call: [3; 16],
            to: [0; 32],
            kind: CallKind::Offer,
            video: true,
            sdp: "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\n",
        };
        let ends = [
            CallEnd::Hangup,
            CallEnd::Declined,
            CallEnd::Busy,
            CallEnd::Unanswered,
            CallEnd::Failed,
        ];
        let mut signals = vec![
            offer,
            CallSignal {
                kind: CallKind::Answer,
                to: [9; 32],
                video: false,
                ..offer
            },
            CallSignal {
                kind: CallKind::Candidates,
                sdp: "candidate:1 1 udp 2122260223 192.0.2.1 54400 typ host",
                ..offer
            },
        ];
        signals.push(CallSignal {
            kind: CallKind::Join,
            sdp: "",
            ..offer
        });
        signals.extend(ends.map(|reason| CallSignal {
            kind: CallKind::End(reason),
            sdp: "",
            ..offer
        }));
        for (i, signal) in signals.into_iter().enumerate() {
            let message = AppMessage {
                sender_seq: i as u64 + 1,
                sent_at_ms: 2,
                expires_after_s: 0,
                body: Body::Call(signal),
            };
            assert_eq!(AppMessage::decode(&message.encode()).unwrap(), message);
        }
        for seconds in [0, 300, DISAPPEAR_MAX_S] {
            let message = AppMessage {
                sender_seq: 1,
                sent_at_ms: 2,
                expires_after_s: seconds,
                body: Body::Text("x"),
            };
            assert_eq!(AppMessage::decode(&message.encode()).unwrap(), message);
        }

        let leave = AppMessage {
            sender_seq: 9,
            sent_at_ms: 2,
            expires_after_s: 0,
            body: Body::Leave,
        };
        assert_eq!(AppMessage::decode(&leave.encode()).unwrap(), leave);
        assert!(
            !CallSignal {
                kind: CallKind::Join,
                ..offer
            }
            .valid(),
            "a join carries no description"
        );

        // An end carries no description, the others must; descriptions are bounded.
        assert!(
            !CallSignal {
                kind: CallKind::End(CallEnd::Hangup),
                ..offer
            }
            .valid()
        );
        assert!(!CallSignal { sdp: "", ..offer }.valid());
        let long = "a".repeat(CALL_SDP_MAX + 1);
        assert!(
            !CallSignal {
                sdp: &long,
                ..offer
            }
            .valid()
        );

        // Unknown end reasons, timers past the limit and bad flags are refused.
        let message = AppMessage {
            sender_seq: 1,
            sent_at_ms: 2,
            expires_after_s: 0,
            body: Body::Call(CallSignal {
                kind: CallKind::End(CallEnd::Failed),
                sdp: "",
                ..offer
            }),
        };
        let encoded = message.encode();
        let reason = 1 + 1 + 8 + 8 + 4 + 16 + 32 + 1;
        for (at, byte) in [(reason, 0u8), (reason, 6), (reason + 1, 2)] {
            let mut bad = encoded.clone();
            bad[at] = byte;
            assert_eq!(AppMessage::decode(&bad), Err(DecodeError::BadValue));
        }
        let mut w = Writer::new();
        w.u8(APP_MESSAGE_VERSION)
            .u8(APP_KIND_TEXT)
            .u64(1)
            .u64(2)
            .u32(DISAPPEAR_MAX_S + 1)
            .bytes(b"x");
        assert_eq!(AppMessage::decode(&w.finish()), Err(DecodeError::BadValue));
    }

    #[test]
    fn turn_grant_roundtrip() {
        let grant = TurnGrant {
            epoch: 4,
            auth: [7; 16],
        };
        let encoded = grant.encode();
        assert_eq!(encoded.len(), TurnGrant::SIZE);
        assert_eq!(TurnGrant::decode(&encoded).unwrap(), grant);
        assert!(TurnGrant::decode(&encoded[1..]).is_err());
    }

    #[test]
    fn file_message_roundtrip_and_limits() {
        let file = FileRef {
            id: [1; 16],
            key: [2; 32],
            size: FILE_SIZE_MAX,
            name: "IMG_0001.jpg",
            media_type: "image/jpeg",
            width: 4032,
            height: 3024,
            thumbnail: &[0xFF, 0xD8, 0xFF, 0xD9],
        };
        let message = AppMessage {
            sender_seq: 7,
            sent_at_ms: 1,
            expires_after_s: 0,
            body: Body::File(file),
        };
        assert_eq!(AppMessage::decode(&message.encode()).unwrap(), message);

        let too_big = FileRef {
            size: FILE_SIZE_MAX + 1,
            ..file
        };
        assert!(!too_big.valid());
        let mut encoded = message.encode();
        // The size field follows version, kind, two u64s, the timer, id and key.
        let at = 2 + 8 + 8 + 4 + 16 + 32;
        encoded[at..at + 8].copy_from_slice(&(FILE_SIZE_MAX + 1).to_le_bytes());
        assert_eq!(AppMessage::decode(&encoded), Err(DecodeError::BadValue));
    }

    #[test]
    fn file_part_roundtrip_and_limits() {
        let part = FilePart {
            file: [3; 16],
            part: FILE_PARTS_MAX - 1,
            len: FILE_PART_SIZE + FILE_TAG_SIZE,
            epoch: 9,
            auth: [4; 16],
        };
        let encoded = part.encode();
        assert_eq!(encoded.len(), FilePart::SIZE);
        assert_eq!(FilePart::decode(&encoded).unwrap(), part);
        for bad in [
            FilePart {
                part: FILE_PARTS_MAX,
                ..part
            },
            FilePart {
                len: FILE_TAG_SIZE - 1,
                ..part
            },
            FilePart {
                len: FILE_PART_SIZE + FILE_TAG_SIZE + 1,
                ..part
            },
        ] {
            assert_eq!(FilePart::decode(&bad.encode()), Err(DecodeError::BadValue));
        }
    }

    #[test]
    fn watch_and_notify_roundtrip() {
        let watch = Watch {
            enable: true,
            target: PushTarget {
                platform: Platform::WebPush,
                address: b"https://push.example/abc",
            },
            proof: &[9; 16],
        };
        assert_eq!(Watch::decode(&watch.encode()).unwrap(), watch);
        assert!(Watch::decode(&[2]).is_err());
        assert!(
            PushTarget::decode(
                &PushTarget {
                    platform: Platform::Apns,
                    address: b""
                }
                .encode()
            )
            .is_err()
        );
    }

    #[test]
    fn inbox_welcome_and_key_packages_roundtrip() {
        let welcome = InboxWelcome {
            conversation: [9; 16],
            join_after: 4,
            welcome: b"w",
        };
        assert_eq!(InboxWelcome::decode(&welcome.encode()).unwrap(), welcome);
        let kps = KeyPackages {
            list: vec![b"kp1", b"kp2"],
        };
        assert_eq!(KeyPackages::decode(&kps.encode()).unwrap(), kps);
    }

    #[test]
    fn largest_entry_fits_in_one_response() {
        let size = Entries::EMPTY_SIZE + Entries::entry_size(MLS_MESSAGE_MAX + 16 + 8 + 4);
        assert!(size <= FRAME_BODY_MAX as usize);
    }
}
