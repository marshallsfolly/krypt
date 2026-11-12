//! Hard limits. Every queue, buffer and list in krypt is bounded by one of
//! these, and every decoder rejects input that exceeds them.

/// Largest frame body, so that a whole frame fits in 1 MiB. The largest
/// thing a frame must carry is a commit plus the welcome for the member it
/// adds; with post-quantum keys that is about 750 KB at `GROUP_MEMBERS_MAX`
/// (see krypt-core's `sizes` test). Bulk data (files) never travels in frames.
#[allow(clippy::cast_possible_truncation)]
pub const FRAME_BODY_MAX: u32 = (1024 * 1024 - crate::frame::HEADER_SIZE) as u32;

/// Largest UTF-8 text in a single chat message.
pub const TEXT_MAX: usize = 16 * 1024;

/// Most members (devices) a conversation may have. A welcome carries the
/// whole ratchet tree, about 2.8 KB per member with post-quantum keys, so
/// this bounds the largest message.
pub const GROUP_MEMBERS_MAX: usize = 256;

/// Most members one commit may add (and so welcomes one submit may carry).
pub const WELCOMES_PER_SUBMIT_MAX: usize = 16;

/// Most log entries returned by one fetch.
pub const FETCH_ENTRIES_MAX: u32 = 64;

/// Most entries a mailbox retains per log before evicting the oldest.
pub const LOG_ENTRIES_MAX: usize = 4096;

/// Most bytes of entries a mailbox retains per log before evicting the oldest.
pub const LOG_BYTES_MAX: u64 = 64 * 1024 * 1024;

/// How long a mailbox keeps a log entry. A device offline for longer must
/// rejoin its conversations.
pub const RETENTION_MS: u64 = 30 * DAY_MS;

/// A log or inbox nobody has written to or read from for this long is
/// deleted entirely.
pub const IDLE_DELETE_MS: u64 = 90 * DAY_MS;

/// How long a push registration lasts unless the device renews it.
pub const WATCH_TTL_MS: u64 = 30 * DAY_MS;

/// At most one push per device per log in this window: a burst of messages
/// wakes a phone once.
pub const PUSH_COALESCE_MS: u64 = 10_000;

/// Most push registrations a mailbox keeps per log.
pub const WATCHERS_MAX: usize = 512;

/// Largest push address (a Web Push endpoint URL, an APNs or FCM token).
pub const PUSH_ADDRESS_MAX: usize = 1024;

pub const DAY_MS: u64 = 24 * 60 * 60 * 1000;

/// Most key packages a mailbox holds per inbox.
pub const KEY_PACKAGES_MAX: usize = 32;

/// Most requests a client has in flight to the mailbox at once.
pub const INFLIGHT_MAX: usize = 64;

/// Most unacknowledged outgoing messages per conversation.
pub const OUTBOX_MAX: usize = 256;

/// How many epochs behind the log an application message may be, and so how
/// many past epochs' keys a member keeps. None: the log puts every message
/// after the commits before it, so each is decrypted in the epoch it was
/// sealed in; one sealed just before a commit lands is refused (`TooOld`) and
/// re-sealed. Keeping past epochs would cost forward secrecy, and OpenMLS
/// rewrites every member's public keys for each kept epoch on every message
/// sent or received: 1.35 MB per message in a 33-member post-quantum group.
pub const PAST_EPOCHS_MAX: u64 = 0;

/// Width, in sequence numbers, of the per-sender duplicate window.
pub const DEDUP_WINDOW: u64 = 1024;

/// Most conversations one device may be part of.
pub const CONVERSATIONS_MAX: usize = 4096;

/// Largest file one message can share.
pub const FILE_SIZE_MAX: u64 = 100 * 1024 * 1024;

/// Files are encrypted and stored in parts of this many plaintext bytes (the
/// last one shorter): each part is one upload, retried on its own, and
/// decrypted in bounded memory.
pub const FILE_PART_SIZE: u32 = 4 * 1024 * 1024;

/// Most parts a file has.
#[allow(clippy::cast_possible_truncation)]
pub const FILE_PARTS_MAX: u32 = FILE_SIZE_MAX.div_ceil(FILE_PART_SIZE as u64) as u32;

/// Bytes the authentication tag adds to each stored part.
pub const FILE_TAG_SIZE: u32 = 16;

/// Longest file name, in UTF-8 bytes.
pub const FILE_NAME_MAX: usize = 255;

/// Longest media type (`image/jpeg`).
pub const FILE_TYPE_MAX: usize = 127;

/// Largest preview image carried inside a file message, so a photo shows at
/// once, before (or without) downloading it.
pub const THUMBNAIL_MAX: usize = 32 * 1024;

/// Largest reaction: one emoji, however many code points it takes.
pub const REACTION_MAX: usize = 32;
/// Most senders' devices one read receipt speaks for.
pub const RECEIPT_REFS_MAX: usize = 64;
/// Largest voice message (15 minutes of Opus at a generous bitrate).
pub const VOICE_SIZE_MAX: u64 = 8 * 1024 * 1024;
pub const VOICE_DURATION_MAX_MS: u32 = 15 * 60 * 1000;
/// A voice message's waveform: this many levels, one byte each.
pub const WAVEFORM_LEN: usize = 64;

/// A requests log's header: the key requests are sealed to (X-Wing) and the
/// group's name, sealed.
pub const JOIN_HEADER_MAX: usize = 2048;
/// A sealed request to join: a card, a name, a one-time key package and a
/// signature, sealed (X-Wing).
pub const JOIN_REQUEST_MAX: usize = 8 * 1024;
/// Requests a log holds; past this, the link is full until reset.
pub const JOIN_REQUESTS_MAX: u64 = 512;

/// File bytes members of one conversation may store per day. Stored files
/// cost money for as long as they are kept (`RETENTION_MS`), and anyone can
/// create a conversation, so this and the edge's per-address limit bound
/// what abuse can cost.
pub const FILE_BYTES_PER_DAY: u64 = 1024 * 1024 * 1024;

/// Largest session description (or batch of ICE candidates) in one call
/// signal. Browsers' offers with audio, video and every candidate are 4 to
/// 10 KB.
pub const CALL_SDP_MAX: usize = 32 * 1024;

/// Relay credentials members of one conversation may obtain per day. Each
/// lets a device relay call media through Cloudflare's TURN servers, which
/// costs money past the free tier; with the edge's per-address limit this
/// bounds abuse.
pub const TURN_GRANTS_PER_DAY: u32 = 64;

/// A sealed signal (typing, online): a nonce, a short body, a signature and
/// a tag, with room to spare.
pub const SIGNAL_SEALED_MAX: usize = 192;
/// A signal sent further than this from the receiver's clock is dropped, so
/// an old one replayed later says nothing.
pub const SIGNAL_SKEW_MS: u64 = 2 * 60 * 1000;

/// Longest disappearing-message timer: four weeks.
pub const DISAPPEAR_MAX_S: u32 = 28 * 24 * 60 * 60;

/// Longest group name, in UTF-8 bytes.
pub const GROUP_NAME_MAX: usize = 64;
