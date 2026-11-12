//! The krypt device core for browsers (and the Tauri apps, which run the web
//! client). JavaScript owns all I/O: it persists each step's writes, and
//! only once they are durable sends the step's requests and shows its
//! events, exactly as `krypt-net` does natively.
//!
//! Byte identifiers (conversations, identities, devices) cross the boundary
//! as lowercase hex.

use js_sys::{Array, Reflect, Uint8Array};
use krypt_core::client::{
    Call, Client, Config, Content, Effect, Event, LinkChange, MUTED_FOREVER, Policy, SharedFile,
    SharedVoice, Step, Who,
};
use krypt_core::file;
use krypt_core::identity::{ContactCard, IdentityKey, fingerprint, safety_number};
use krypt_core::join::{JoinCode, LinkKeys};
use krypt_core::link::{Backup, LinkCode, LinkError, LinkPayload};
use krypt_core::provider::Rand;
use krypt_wire::Route;
use krypt_wire::limits::{
    CALL_SDP_MAX, DISAPPEAR_MAX_S, FILE_NAME_MAX, FILE_PART_SIZE, FILE_SIZE_MAX, FILE_TYPE_MAX,
    PUSH_ADDRESS_MAX, THUMBNAIL_MAX,
};
use krypt_wire::msg::{CallEnd, CallKind, MessageRef, Platform, PushTarget, SignalKind};
use serde::de::Visitor;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(typescript_custom_section)]
const TYPES: &str = r#"
/** One step of the device: persist `writes` atomically (a `null` value
 * deletes the key), and only then send `requests` and show `events`. */
export interface Step {
  writes: [Uint8Array, Uint8Array | null][];
  requests: Uint8Array[];
  events: KryptEvent[];
}
export type KryptEvent =
  | { type: "started"; conversation: string }
  | { type: "joined"; conversation: string; members: string[]; epoch: number; viaLink: boolean; addedBy: string }
  | { type: "joinRequest"; conversation: string; id: string; identity: string; name: string }
  | { type: "membersAdded"; conversation: string; identities: string[] }
  | { type: "membersRemoved"; conversation: string; identities: string[]; by?: string }
  | { type: "removed"; conversation: string }
  | { type: "message"; conversation: string; from: string; device: string;
      senderSeq: number; sentAtMs: number; expiresAfterS: number;
      text?: string; file?: SharedFile; call?: CallSignal; left?: boolean;
      replyTo?: MessageRef; react?: { to: MessageRef; emoji: string };
      edit?: { to: MessageRef; text: string }; delete?: MessageRef;
      receipt?: MessageRef[]; voice?: { durationMs: number; waveform: Uint8Array } }
  | { type: "renamed"; conversation: string; by: string; name: string }
  | { type: "timer"; conversation: string; by: string; seconds: number }
  | { type: "timerRefused"; conversation: string; reason: string }
  | { type: "sealed"; conversation: string; senderSeq: number }
  | { type: "sent"; conversation: string; senderSeq: number }
  | { type: "inviteFailed"; conversation: string; identity: string }
  | { type: "undecryptable"; conversation: string; reason: string }
  | { type: "desync"; conversation: string; reason: string }
  | { type: "signal"; conversation: string; from: string; device: string; kind: SignalKind }
  | { type: "refused"; conversation: string; reason: string }
  | { type: "rules"; conversation: string; by: string; adminsAdded: string[]; adminsRemoved: string[];
      add?: Who; edit?: Who; link?: "on" | "reset" | "off" };
/** Who may add people, or rename the group and change its timer. */
export type Who = "everyone" | "admins";
/** A group's rules. `link` is the invite link's secret (hex), if any. */
export interface Policy {
  admins: string[];
  add: Who;
  edit: Who;
  link?: string;
}
/** A message as every member names it: its sender device and seq there. */
export interface MessageRef {
  device: string;
  seq: number;
}
/** What `sendContent` sends. */
export type OutgoingContent =
  | { type: "reply"; to: MessageRef; text: string }
  | { type: "react"; to: MessageRef; emoji: string }
  | { type: "edit"; to: MessageRef; text: string }
  | { type: "delete"; to: MessageRef }
  | { type: "receipt"; through: MessageRef[] }
  | { type: "voice"; file: SharedFile; durationMs: number; waveform: Uint8Array };
/** What a signal says: typing, stopped (idle), online, offline, or online
 * and asking who else is (hello). */
export type SignalKind = "typing" | "idle" | "online" | "offline" | "hello";
/** A shared file: its parts are stored under the conversation and `id`,
 * sealed with `key` (hex). */
export interface SharedFile {
  id: string;
  key: string;
  size: number;
  name: string;
  mediaType: string;
  width: number;
  height: number;
  thumbnail: Uint8Array;
}
/** WebRTC signaling, carried inside MLS. `to` is a device id (hex), or all
 * zeros for every other member's devices. */
export interface CallSignal {
  call: string;
  to: string;
  kind: "offer" | "answer" | "candidates" | "end" | "join";
  reason?: "hangup" | "declined" | "busy" | "unanswered" | "failed";
  video: boolean;
  sdp: string;
}
export interface CallLimits {
  sdpMax: number;
  timerMax: number;
}
export interface FileLimits {
  partSize: number;
  sizeMax: number;
  nameMax: number;
  typeMax: number;
  thumbnailMax: number;
}
export interface ConversationInfo {
  id: string;
  members: string[];
  active: boolean;
  epoch: number;
}
"#;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn route(text: &str) -> Result<Route, JsError> {
    let bytes = unhex(text).ok_or_else(|| JsError::new("not a hex id"))?;
    bytes
        .try_into()
        .map_err(|_| JsError::new("not a conversation id"))
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

/// JavaScript numbers hold integers exactly up to 2^53; every count and time
/// krypt sends across stays far below that.
#[allow(clippy::cast_precision_loss)]
fn number(n: u64) -> f64 {
    n as f64
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn millis(now: f64) -> u64 {
    now.max(0.0) as u64
}

#[derive(Serialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
enum JsEvent {
    Started {
        conversation: String,
    },
    Joined {
        conversation: String,
        members: Vec<String>,
        epoch: f64,
        via_link: bool,
        added_by: String,
    },
    JoinRequest {
        conversation: String,
        id: String,
        identity: String,
        name: String,
    },
    MembersAdded {
        conversation: String,
        identities: Vec<String>,
    },
    MembersRemoved {
        conversation: String,
        identities: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        by: Option<String>,
    },
    Removed {
        conversation: String,
    },
    // Boxed: by far the largest event. (A plain struct, not `flatten`,
    // which would make it a `Map` in JavaScript.)
    Message(Box<JsMessage>),
    Renamed {
        conversation: String,
        by: String,
        name: String,
    },
    Signal {
        conversation: String,
        from: String,
        device: String,
        kind: &'static str,
    },
    Refused {
        conversation: String,
        reason: String,
    },
    Rules {
        conversation: String,
        by: String,
        admins_added: Vec<String>,
        admins_removed: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        add: Option<&'static str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        edit: Option<&'static str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        link: Option<&'static str>,
    },
    Timer {
        conversation: String,
        by: String,
        seconds: u32,
    },
    TimerRefused {
        conversation: String,
        reason: String,
    },
    Sealed {
        conversation: String,
        sender_seq: f64,
    },
    Sent {
        conversation: String,
        sender_seq: f64,
    },
    InviteFailed {
        conversation: String,
        identity: String,
    },
    Undecryptable {
        conversation: String,
        reason: String,
    },
    Desync {
        conversation: String,
        reason: String,
    },
}

/// Bytes cross as a `Uint8Array`, not an array of numbers.
fn as_bytes<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_bytes(bytes)
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsFile {
    id: String,
    key: String,
    size: f64,
    name: String,
    media_type: String,
    width: u32,
    height: u32,
    #[serde(serialize_with = "as_bytes", deserialize_with = "bytes_in")]
    thumbnail: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct JsRef {
    device: String,
    seq: f64,
}

impl From<MessageRef> for JsRef {
    fn from(r: MessageRef) -> JsRef {
        JsRef {
            device: hex(&r.device),
            seq: number(r.seq),
        }
    }
}

impl TryFrom<JsRef> for MessageRef {
    type Error = JsError;

    fn try_from(r: JsRef) -> Result<MessageRef, JsError> {
        let device = unhex(&r.device)
            .and_then(|d| <[u8; 32]>::try_from(d).ok())
            .ok_or_else(|| JsError::new("not a device id"))?;
        if !(1.0..=9_007_199_254_740_991.0).contains(&r.seq) || r.seq.fract() != 0.0 {
            return Err(JsError::new("not a message number"));
        }
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        Ok(MessageRef {
            device,
            seq: r.seq as u64,
        })
    }
}

#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct JsMessage {
    conversation: String,
    from: String,
    device: String,
    sender_seq: f64,
    sent_at_ms: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    file: Option<Box<JsFile>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    call: Option<Box<JsCall>>,
    /// The sender left the group.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    left: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    reply_to: Option<JsRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    react: Option<JsReact>,
    #[serde(skip_serializing_if = "Option::is_none")]
    edit: Option<JsEdit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    delete: Option<JsRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt: Option<Vec<JsRef>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    voice: Option<JsVoice>,
    expires_after_s: u32,
}

#[derive(Serialize)]
struct JsReact {
    to: JsRef,
    emoji: String,
}

#[derive(Serialize)]
struct JsEdit {
    to: JsRef,
    text: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsVoice {
    duration_ms: u32,
    #[serde(serialize_with = "as_bytes")]
    waveform: Vec<u8>,
}

/// What `sendContent` accepts (see `OutgoingContent`).
#[derive(Deserialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
enum JsOutgoing {
    Reply {
        to: JsRef,
        text: String,
    },
    React {
        to: JsRef,
        emoji: String,
    },
    Edit {
        to: JsRef,
        text: String,
    },
    Delete {
        to: JsRef,
    },
    Receipt {
        through: Vec<JsRef>,
    },
    Voice {
        file: JsFile,
        duration_ms: u32,
        #[serde(deserialize_with = "bytes_in")]
        waveform: Vec<u8>,
    },
}

impl TryFrom<JsOutgoing> for Content {
    type Error = JsError;

    fn try_from(outgoing: JsOutgoing) -> Result<Content, JsError> {
        Ok(match outgoing {
            JsOutgoing::Reply { to, text } => Content::Reply {
                to: to.try_into()?,
                text,
            },
            JsOutgoing::React { to, emoji } => Content::React {
                to: to.try_into()?,
                emoji,
            },
            JsOutgoing::Edit { to, text } => Content::Edit {
                to: to.try_into()?,
                text,
            },
            JsOutgoing::Delete { to } => Content::Delete { to: to.try_into()? },
            JsOutgoing::Receipt { through } => Content::Receipt(
                through
                    .into_iter()
                    .map(MessageRef::try_from)
                    .collect::<Result<_, _>>()?,
            ),
            JsOutgoing::Voice {
                file,
                duration_ms,
                waveform,
            } => Content::Voice(Box::new(SharedVoice {
                file: file.try_into()?,
                duration_ms,
                waveform,
            })),
        })
    }
}

/// Reads a `Uint8Array` back into bytes.
fn bytes_in<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    struct Bytes;

    impl Visitor<'_> for Bytes {
        type Value = Vec<u8>;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a Uint8Array")
        }

        fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Vec<u8>, E> {
            Ok(v.to_vec())
        }

        fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Vec<u8>, E> {
            Ok(v)
        }
    }

    deserializer.deserialize_byte_buf(Bytes)
}

impl From<SharedFile> for JsFile {
    fn from(file: SharedFile) -> JsFile {
        JsFile {
            id: hex(&file.id),
            key: hex(&file.key),
            size: number(file.size),
            name: file.name,
            media_type: file.media_type,
            width: file.width,
            height: file.height,
            thumbnail: file.thumbnail,
        }
    }
}

impl TryFrom<JsFile> for SharedFile {
    type Error = JsError;

    fn try_from(file: JsFile) -> Result<SharedFile, JsError> {
        Ok(SharedFile {
            id: array(&file.id)?,
            key: array(&file.key)?,
            size: size(file.size)?,
            name: file.name,
            media_type: file.media_type,
            width: file.width,
            height: file.height,
            thumbnail: file.thumbnail,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsCall {
    call: String,
    to: String,
    kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    video: bool,
    sdp: String,
}

const CALL_ENDS: [(CallEnd, &str); 5] = [
    (CallEnd::Hangup, "hangup"),
    (CallEnd::Declined, "declined"),
    (CallEnd::Busy, "busy"),
    (CallEnd::Unanswered, "unanswered"),
    (CallEnd::Failed, "failed"),
];

impl From<Call> for JsCall {
    fn from(call: Call) -> JsCall {
        let (kind, reason) = match call.kind {
            CallKind::Offer => ("offer", None),
            CallKind::Answer => ("answer", None),
            CallKind::Candidates => ("candidates", None),
            CallKind::Join => ("join", None),
            CallKind::End(end) => (
                "end",
                CALL_ENDS
                    .iter()
                    .find(|(e, _)| *e == end)
                    .map(|(_, name)| (*name).to_owned()),
            ),
        };
        JsCall {
            call: hex(&call.call),
            to: hex(&call.to),
            kind: kind.to_owned(),
            reason,
            video: call.video,
            sdp: call.sdp,
        }
    }
}

impl TryFrom<JsCall> for Call {
    type Error = JsError;

    fn try_from(call: JsCall) -> Result<Call, JsError> {
        let kind = match call.kind.as_str() {
            "offer" => CallKind::Offer,
            "answer" => CallKind::Answer,
            "candidates" => CallKind::Candidates,
            "join" => CallKind::Join,
            "end" => CallKind::End(
                CALL_ENDS
                    .iter()
                    .find(|(_, name)| Some(*name) == call.reason.as_deref())
                    .map(|(end, _)| *end)
                    .ok_or_else(|| JsError::new("unknown call end reason"))?,
            ),
            _ => return Err(JsError::new("unknown call signal")),
        };
        Ok(Call {
            call: array(&call.call)?,
            to: array(&call.to)?,
            kind,
            video: call.video,
            sdp: call.sdp,
        })
    }
}

fn array<const N: usize>(text: &str) -> Result<[u8; N], JsError> {
    unhex(text)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| JsError::new("not a hex key or id"))
}

/// A file size from JavaScript: a whole number within the file limit.
fn size(n: f64) -> Result<u64, JsError> {
    #[allow(clippy::cast_precision_loss)]
    let max = FILE_SIZE_MAX as f64;
    if !(0.0..=max).contains(&n) || n.fract() != 0.0 {
        return Err(JsError::new("file size out of range"));
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Ok(n as u64)
}

fn who_name(who: Who) -> &'static str {
    match who {
        Who::Everyone => "everyone",
        Who::Admins => "admins",
    }
}

#[derive(Serialize, Deserialize)]
struct JsPolicy {
    admins: Vec<String>,
    add: String,
    edit: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    link: Option<String>,
}

impl From<Policy> for JsPolicy {
    fn from(policy: Policy) -> JsPolicy {
        JsPolicy {
            admins: hexes(&policy.admins),
            add: who_name(policy.add).to_owned(),
            edit: who_name(policy.edit).to_owned(),
            link: policy.link.map(|seed| hex(&seed)),
        }
    }
}

impl TryFrom<JsPolicy> for Policy {
    type Error = JsError;

    fn try_from(policy: JsPolicy) -> Result<Policy, JsError> {
        let who = |w: &str| match w {
            "everyone" => Ok(Who::Everyone),
            "admins" => Ok(Who::Admins),
            _ => Err(JsError::new("not who")),
        };
        let key = |text: &str| {
            unhex(text)
                .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                .ok_or_else(|| JsError::new("not a key"))
        };
        Ok(Policy {
            admins: policy
                .admins
                .iter()
                .map(|a| key(a))
                .collect::<Result<_, _>>()?,
            add: who(&policy.add)?,
            edit: who(&policy.edit)?,
            link: policy.link.as_deref().map(key).transpose()?,
        })
    }
}

fn signal_name(kind: SignalKind) -> &'static str {
    match kind {
        SignalKind::Typing => "typing",
        SignalKind::Idle => "idle",
        SignalKind::Online => "online",
        SignalKind::Offline => "offline",
        SignalKind::Hello => "hello",
    }
}

fn hexes(keys: &[[u8; 32]]) -> Vec<String> {
    keys.iter().map(|k| hex(k)).collect()
}

impl From<Event> for JsEvent {
    fn from(event: Event) -> JsEvent {
        match event {
            Event::Started { conversation } => JsEvent::Started {
                conversation: hex(&conversation),
            },
            Event::Joined {
                conversation,
                members,
                epoch,
                via_link,
                added_by,
            } => JsEvent::Joined {
                conversation: hex(&conversation),
                members: hexes(&members),
                epoch: number(epoch),
                via_link,
                added_by: hex(&added_by),
            },
            Event::JoinRequest {
                conversation,
                id,
                identity,
                name,
            } => JsEvent::JoinRequest {
                conversation: hex(&conversation),
                id: hex(&id),
                identity: hex(&identity),
                name,
            },
            Event::MembersAdded {
                conversation,
                identities,
            } => JsEvent::MembersAdded {
                conversation: hex(&conversation),
                identities: hexes(&identities),
            },
            Event::MembersRemoved {
                conversation,
                identities,
                by,
            } => JsEvent::MembersRemoved {
                conversation: hex(&conversation),
                identities: hexes(&identities),
                by: by.map(|by| hex(&by)),
            },
            Event::Removed { conversation } => JsEvent::Removed {
                conversation: hex(&conversation),
            },
            Event::Message {
                conversation,
                from,
                device,
                sender_seq,
                sent_at_ms,
                expires_after_s,
                content,
            } => {
                let mut m = Box::new(JsMessage {
                    conversation: hex(&conversation),
                    from: hex(&from),
                    device: hex(&device),
                    sender_seq: number(sender_seq),
                    sent_at_ms: number(sent_at_ms),
                    expires_after_s,
                    ..JsMessage::default()
                });
                match content {
                    Content::Text(t) => m.text = Some(t),
                    Content::File(f) => m.file = Some(Box::new((*f).into())),
                    Content::Call(c) => m.call = Some(Box::new((*c).into())),
                    Content::Leave => m.left = true,
                    Content::Reply { to, text: t } => {
                        m.reply_to = Some(to.into());
                        m.text = Some(t);
                    }
                    Content::React { to, emoji } => {
                        m.react = Some(JsReact {
                            to: to.into(),
                            emoji,
                        });
                    }
                    Content::Edit { to, text } => {
                        m.edit = Some(JsEdit {
                            to: to.into(),
                            text,
                        });
                    }
                    Content::Delete { to } => m.delete = Some(to.into()),
                    Content::Receipt(refs) => {
                        m.receipt = Some(refs.into_iter().map(JsRef::from).collect());
                    }
                    Content::Voice(v) => {
                        let SharedVoice {
                            file: f,
                            duration_ms,
                            waveform,
                        } = *v;
                        m.file = Some(Box::new(f.into()));
                        m.voice = Some(JsVoice {
                            duration_ms,
                            waveform,
                        });
                    }
                }
                JsEvent::Message(m)
            }
            Event::Renamed {
                conversation,
                by,
                name,
            } => JsEvent::Renamed {
                conversation: hex(&conversation),
                by: hex(&by),
                name,
            },
            Event::Refused {
                conversation,
                reason,
            } => JsEvent::Refused {
                conversation: hex(&conversation),
                reason,
            },
            Event::Rules {
                conversation,
                by,
                admins_added,
                admins_removed,
                add,
                edit,
                link,
            } => JsEvent::Rules {
                conversation: hex(&conversation),
                by: hex(&by),
                admins_added: hexes(&admins_added),
                admins_removed: hexes(&admins_removed),
                add: add.map(who_name),
                edit: edit.map(who_name),
                link: link.map(|l| match l {
                    LinkChange::On => "on",
                    LinkChange::Reset => "reset",
                    LinkChange::Off => "off",
                }),
            },
            Event::Signal {
                conversation,
                from,
                device,
                kind,
            } => JsEvent::Signal {
                conversation: hex(&conversation),
                from: hex(&from),
                device: hex(&device),
                kind: signal_name(kind),
            },
            Event::Timer {
                conversation,
                by,
                seconds,
            } => JsEvent::Timer {
                conversation: hex(&conversation),
                by: hex(&by),
                seconds,
            },
            Event::TimerRefused {
                conversation,
                reason,
            } => JsEvent::TimerRefused {
                conversation: hex(&conversation),
                reason,
            },
            Event::Sealed {
                conversation,
                sender_seq,
                ..
            } => JsEvent::Sealed {
                conversation: hex(&conversation),
                sender_seq: number(sender_seq),
            },
            Event::Sent {
                conversation,
                sender_seq,
            } => JsEvent::Sent {
                conversation: hex(&conversation),
                sender_seq: number(sender_seq),
            },
            Event::InviteFailed {
                conversation,
                identity,
            } => JsEvent::InviteFailed {
                conversation: hex(&conversation),
                identity: hex(&identity),
            },
            Event::Undecryptable {
                conversation,
                reason,
            } => JsEvent::Undecryptable {
                conversation: hex(&conversation),
                reason,
            },
            Event::Desync {
                conversation,
                reason,
            } => JsEvent::Desync {
                conversation: hex(&conversation),
                reason,
            },
        }
    }
}

fn set(object: &JsValue, key: &str, value: &JsValue) -> Result<(), JsError> {
    Reflect::set(object, &key.into(), value)
        .map(drop)
        .map_err(|_| JsError::new("building a step"))
}

fn step_to_js(step: Step) -> Result<JsValue, JsError> {
    let writes = Array::new();
    for (key, value) in step.writes {
        let pair = Array::new();
        pair.push(&Uint8Array::from(key.as_slice()));
        pair.push(&value.map_or(JsValue::NULL, |v| Uint8Array::from(v.as_slice()).into()));
        writes.push(&pair);
    }
    let requests = Array::new();
    let events = Array::new();
    for effect in step.effects {
        match effect {
            Effect::Mailbox(frame) => {
                requests.push(&Uint8Array::from(frame.as_slice()));
            }
            Effect::Event(event) => {
                events.push(&serde_wasm_bindgen::to_value(&JsEvent::from(event))?);
            }
        }
    }
    let out: JsValue = js_sys::Object::new().into();
    set(&out, "writes", &writes)?;
    set(&out, "requests", &requests)?;
    set(&out, "events", &events)?;
    Ok(out)
}

/// One device: the client state machine. Not thread-safe, and there must be
/// exactly one per stored device (the web client holds a lock for it).
#[wasm_bindgen]
#[derive(Debug)]
pub struct Device {
    client: Client,
    /// The step that created or restored the device, until taken.
    startup: Option<Step>,
}

#[wasm_bindgen]
impl Device {
    /// A brand-new device with a fresh identity.
    pub fn create(now: f64) -> Device {
        let (client, step) = Client::create(Config::default(), Rand::os(), millis(now));
        Device {
            client,
            startup: Some(step),
        }
    }

    /// The device stored as `records`: an array of `[key, value]` pairs,
    /// everything previous steps wrote.
    pub fn restore(records: Array, now: f64) -> Result<Device, JsError> {
        let mut entries = Vec::with_capacity(records.length() as usize);
        for pair in records.iter() {
            let pair: Array = pair.dyn_into().map_err(|_| JsError::new("record pair"))?;
            let key: Uint8Array = pair.get(0).dyn_into().map_err(|_| JsError::new("key"))?;
            let value: Uint8Array = pair.get(1).dyn_into().map_err(|_| JsError::new("value"))?;
            entries.push((key.to_vec(), value.to_vec()));
        }
        let (client, step) = Client::restore(Config::default(), Rand::os(), entries, millis(now))
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(Device {
            client,
            startup: Some(step),
        })
    }

    /// A new device of an existing identity, from a link payload (a sealed
    /// `LinkInvite` opened) or a restored backup.
    #[wasm_bindgen(js_name = createLinked)]
    pub fn create_linked(payload: &[u8], now: f64) -> Result<Device, JsError> {
        let payload =
            LinkPayload::decode(payload).map_err(|_| JsError::new("not a link payload"))?;
        let (client, step) =
            Client::create_linked(Config::default(), Rand::os(), &payload, millis(now));
        Ok(Device {
            client,
            startup: Some(step),
        })
    }

    /// The step from `create` or `restore`; persist it like any other.
    #[wasm_bindgen(js_name = takeStartup, unchecked_return_type = "Step")]
    pub fn take_startup(&mut self) -> Result<JsValue, JsError> {
        step_to_js(self.startup.take().unwrap_or(Step {
            writes: Vec::new(),
            effects: Vec::new(),
        }))
    }

    pub fn identity(&self) -> String {
        hex(&self.client.identity())
    }

    /// This device's id (hex), as call signals address it.
    #[wasm_bindgen(js_name = deviceId)]
    pub fn device_id(&self) -> String {
        hex(&self.client.device())
    }

    pub fn fingerprint(&self) -> String {
        fingerprint(&self.client.identity())
    }

    /// The text others paste (or open as a link) to start a chat.
    #[wasm_bindgen(js_name = contactCard)]
    pub fn contact_card(&self) -> String {
        self.client.contact_card().to_text()
    }

    /// The logs this device follows, for its WebSocket subscriptions.
    pub fn routes(&self) -> Vec<String> {
        self.client.routes().iter().map(|r| hex(r)).collect()
    }

    #[wasm_bindgen(unchecked_return_type = "ConversationInfo[]")]
    pub fn conversations(&self) -> Result<JsValue, JsError> {
        #[derive(Serialize)]
        struct Info {
            id: String,
            members: Vec<String>,
            active: bool,
            epoch: f64,
        }
        let list: Vec<Info> = self
            .client
            .conversations()
            .map(|id| Info {
                id: hex(&id),
                members: hexes(&self.client.members(&id)),
                active: self.client.is_active(&id),
                epoch: number(self.client.epoch(&id).map_or(0, |(epoch, _)| epoch)),
            })
            .collect();
        Ok(serde_wasm_bindgen::to_value(&list)?)
    }

    #[wasm_bindgen(unchecked_return_type = "Step")]
    pub fn tick(&mut self, now: f64) -> Result<JsValue, JsError> {
        step_to_js(self.client.tick(millis(now)))
    }

    /// The Web Push endpoint the mailbox wakes this device at, if any.
    #[wasm_bindgen(getter, js_name = pushTarget)]
    pub fn push_target(&self) -> Option<String> {
        self.client
            .push_target()
            .filter(|t| t.platform == Platform::WebPush)
            .and_then(|t| String::from_utf8(t.address.to_vec()).ok())
    }

    /// Wakes this device at a Web Push endpoint when it is not connected, or
    /// (`null`) stops waking it.
    #[wasm_bindgen(js_name = setPushTarget, unchecked_return_type = "Step")]
    pub fn set_push_target(
        &mut self,
        now: f64,
        endpoint: Option<String>,
    ) -> Result<JsValue, JsError> {
        if endpoint
            .as_ref()
            .is_some_and(|e| e.len() > PUSH_ADDRESS_MAX)
        {
            return Err(JsError::new("push endpoint too long"));
        }
        let target = endpoint.as_ref().map(|e| PushTarget {
            platform: Platform::WebPush,
            address: e.as_bytes(),
        });
        step_to_js(self.client.set_push_target(millis(now), target))
    }

    /// A frame from the mailbox: a response, or a pushed `Notify`.
    #[wasm_bindgen(unchecked_return_type = "Step")]
    pub fn receive(&mut self, now: f64, frame: &[u8]) -> Result<JsValue, JsError> {
        step_to_js(self.client.receive(millis(now), frame))
    }

    /// Fetches everything new: call when a subscription (re)connects.
    #[wasm_bindgen(js_name = pollNow, unchecked_return_type = "Step")]
    pub fn poll_now(&mut self, now: f64) -> Result<JsValue, JsError> {
        step_to_js(self.client.poll_now(millis(now)))
    }

    /// Starts a conversation with the person whose card this is. Returns
    /// `{ conversation, step }`.
    #[wasm_bindgen(
        js_name = startConversation,
        unchecked_return_type = "{ conversation: string; step: Step }"
    )]
    pub fn start_conversation(&mut self, now: f64, card: &str) -> Result<JsValue, JsError> {
        let card = ContactCard::from_text(card).ok_or_else(|| JsError::new("not a krypt card"))?;
        let (id, step) = self
            .client
            .start_conversation(millis(now), card)
            .map_err(|e| JsError::new(&e.to_string()))?;
        let out: JsValue = js_sys::Object::new().into();
        set(&out, "conversation", &hex(&id).into())?;
        set(&out, "step", &step_to_js(step)?)?;
        Ok(out)
    }

    #[wasm_bindgen(unchecked_return_type = "Step")]
    pub fn invite(&mut self, now: f64, conversation: &str, card: &str) -> Result<JsValue, JsError> {
        let card = ContactCard::from_text(card).ok_or_else(|| JsError::new("not a krypt card"))?;
        let step = self
            .client
            .invite(millis(now), route(conversation)?, card)
            .map_err(|e| JsError::new(&e.to_string()))?;
        step_to_js(step)
    }

    /// Queues a message. Returns `{ senderSeq, step }`.
    #[wasm_bindgen(unchecked_return_type = "{ senderSeq: number; step: Step }")]
    pub fn send(&mut self, now: f64, conversation: &str, text: &str) -> Result<JsValue, JsError> {
        let (seq, step) = self
            .client
            .send(millis(now), route(conversation)?, text)
            .map_err(|e| JsError::new(&e.to_string()))?;
        let out: JsValue = js_sys::Object::new().into();
        set(&out, "senderSeq", &number(seq).into())?;
        set(&out, "step", &step_to_js(step)?)?;
        Ok(out)
    }

    /// A new file's id and key (hex), for sealing and uploading its parts.
    #[wasm_bindgen(js_name = newFile, unchecked_return_type = "{ id: string; key: string }")]
    pub fn new_file(&self) -> Result<JsValue, JsError> {
        let (id, key) = self.client.new_file();
        let out: JsValue = js_sys::Object::new().into();
        set(&out, "id", &hex(&id).into())?;
        set(&out, "key", &hex(&key).into())?;
        Ok(out)
    }

    /// The `krypt-auth` header for uploading part `part` (`len` stored
    /// bytes) of file `id`: proof this device is a member right now. The
    /// mailbox refuses it after the next commit; ask again then.
    #[wasm_bindgen(js_name = fileAuth)]
    pub fn file_auth(
        &mut self,
        conversation: &str,
        id: &str,
        part: u32,
        len: u32,
    ) -> Result<String, JsError> {
        let part = self
            .client
            .file_auth(route(conversation)?, array(id)?, part, len)
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(format!(
            "{}{}",
            hex(&part.epoch.to_le_bytes()),
            hex(&part.auth)
        ))
    }

    /// Shares an uploaded file. Returns `{ senderSeq, step }`.
    /// Sends a reply, reaction, edit, deletion, read receipt or voice
    /// message. A read receipt replaces one not yet sent.
    #[wasm_bindgen(js_name = sendContent, unchecked_return_type = "{ senderSeq: number; step: Step }")]
    pub fn send_content(
        &mut self,
        now: f64,
        conversation: &str,
        #[wasm_bindgen(unchecked_param_type = "OutgoingContent")] content: JsValue,
    ) -> Result<JsValue, JsError> {
        let content: JsOutgoing = serde_wasm_bindgen::from_value(content)?;
        let (seq, step) = self
            .client
            .send_content(millis(now), route(conversation)?, content.try_into()?)
            .map_err(|e| JsError::new(&e.to_string()))?;
        let out: JsValue = js_sys::Object::new().into();
        set(&out, "senderSeq", &number(seq).into())?;
        set(&out, "step", &step_to_js(step)?)?;
        Ok(out)
    }

    #[wasm_bindgen(js_name = sendFile, unchecked_return_type = "{ senderSeq: number; step: Step }")]
    pub fn send_file(
        &mut self,
        now: f64,
        conversation: &str,
        #[wasm_bindgen(unchecked_param_type = "SharedFile")] file: JsValue,
    ) -> Result<JsValue, JsError> {
        let file: JsFile = serde_wasm_bindgen::from_value(file)?;
        let (seq, step) = self
            .client
            .send_file(millis(now), route(conversation)?, file.try_into()?)
            .map_err(|e| JsError::new(&e.to_string()))?;
        let out: JsValue = js_sys::Object::new().into();
        set(&out, "senderSeq", &number(seq).into())?;
        set(&out, "step", &step_to_js(step)?)?;
        Ok(out)
    }

    /// Sends a call signal. Returns `{ senderSeq, step }`.
    #[wasm_bindgen(js_name = sendCall, unchecked_return_type = "{ senderSeq: number; step: Step }")]
    pub fn send_call(
        &mut self,
        now: f64,
        conversation: &str,
        #[wasm_bindgen(unchecked_param_type = "CallSignal")] signal: JsValue,
    ) -> Result<JsValue, JsError> {
        let call: JsCall = serde_wasm_bindgen::from_value(signal)?;
        let (seq, step) = self
            .client
            .send_call(millis(now), route(conversation)?, call.try_into()?)
            .map_err(|e| JsError::new(&e.to_string()))?;
        let out: JsValue = js_sys::Object::new().into();
        set(&out, "senderSeq", &number(seq).into())?;
        set(&out, "step", &step_to_js(step)?)?;
        Ok(out)
    }

    /// The `krypt-auth` header for asking the edge for call relay
    /// credentials: proof this device is a member right now.
    #[wasm_bindgen(js_name = turnAuth)]
    pub fn turn_auth(&mut self, conversation: &str) -> Result<String, JsError> {
        let grant = self
            .client
            .turn_auth(route(conversation)?)
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(format!(
            "{}{}",
            hex(&grant.epoch.to_le_bytes()),
            hex(&grant.auth)
        ))
    }

    /// Sets the conversation's disappearing-message timer for everyone (a
    /// commit: a `timer` event follows once it is in the log).
    /// The group's rules, or `undefined` for a group from before admins
    /// (where everyone may do everything).
    #[wasm_bindgen(unchecked_return_type = "Policy | undefined")]
    pub fn policy(&self, conversation: &str) -> Result<JsValue, JsError> {
        match self.client.policy(&route(conversation)?) {
            Some(policy) => Ok(serde_wasm_bindgen::to_value(&JsPolicy::from(policy))?),
            None => Ok(JsValue::UNDEFINED),
        }
    }

    /// The group's admins now (everyone, before the group has rules).
    pub fn admins(&self, conversation: &str) -> Result<Vec<String>, JsError> {
        Ok(hexes(&self.client.admins(&route(conversation)?)))
    }

    /// Asks to join a group with its invite link (`code`, what follows
    /// `#join=`), given the requests log's header: returns the frame to
    /// leave at the log, and the step to persist first.
    #[wasm_bindgen(js_name = joinRequest, unchecked_return_type = "{ frame: Uint8Array; step: Step }")]
    pub fn join_request(
        &mut self,
        now: f64,
        code: &str,
        header: &[u8],
        name: &str,
    ) -> Result<JsValue, JsError> {
        let code = JoinCode::from_text(code).map_err(|e| JsError::new(&e.to_string()))?;
        let header = code
            .read_header(header)
            .map_err(|e| JsError::new(&e.to_string()))?;
        let (frame, step) = self
            .client
            .join_request(millis(now), &code, &header, name)
            .map_err(|e| JsError::new(&e.to_string()))?;
        let out: JsValue = js_sys::Object::new().into();
        set(&out, "frame", &Uint8Array::from(frame.as_slice()).into())?;
        set(&out, "step", &step_to_js(step)?)?;
        Ok(out)
    }

    /// Groups this device asked to join with a link, by name, still waiting.
    #[wasm_bindgen(js_name = pendingJoins)]
    pub fn pending_joins(&self) -> Vec<String> {
        self.client.pending_joins()
    }

    /// Approves a request to join (as an admin), by its id.
    #[wasm_bindgen(js_name = approveJoin, unchecked_return_type = "Step")]
    pub fn approve_join(
        &mut self,
        now: f64,
        conversation: &str,
        id: &str,
    ) -> Result<JsValue, JsError> {
        let id: [u8; 16] = unhex(id)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| JsError::new("not a request id"))?;
        let step = self
            .client
            .approve_join(millis(now), route(conversation)?, id)
            .map_err(|e| JsError::new(&e.to_string()))?;
        step_to_js(step)
    }

    /// Removes everyone's devices of an identity from the group (the app
    /// offers it to admins).
    #[wasm_bindgen(js_name = removeMember, unchecked_return_type = "Step")]
    pub fn remove_member(
        &mut self,
        now: f64,
        conversation: &str,
        identity: &str,
    ) -> Result<JsValue, JsError> {
        let identity: IdentityKey = unhex(identity)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| JsError::new("not an identity"))?;
        let step = self
            .client
            .remove(millis(now), route(conversation)?, identity)
            .map_err(|e| JsError::new(&e.to_string()))?;
        step_to_js(step)
    }

    /// Changes the group's rules (only an admin may).
    #[wasm_bindgen(js_name = setPolicy, unchecked_return_type = "Step")]
    pub fn set_policy(
        &mut self,
        now: f64,
        conversation: &str,
        #[wasm_bindgen(unchecked_param_type = "Policy")] policy: JsValue,
    ) -> Result<JsValue, JsError> {
        let policy: JsPolicy = serde_wasm_bindgen::from_value(policy)?;
        let step = self
            .client
            .set_policy(millis(now), route(conversation)?, policy.try_into()?)
            .map_err(|e| JsError::new(&e.to_string()))?;
        step_to_js(step)
    }

    /// Mutes a conversation until `until` (ms; `Infinity`: until unmuted),
    /// or unmutes it (`undefined`): its wakeups are withdrawn meanwhile.
    #[wasm_bindgen(js_name = setMuted, unchecked_return_type = "Step")]
    pub fn set_muted(
        &mut self,
        now: f64,
        conversation: &str,
        until: Option<f64>,
    ) -> Result<JsValue, JsError> {
        let until = until.map(|u| {
            if u.is_infinite() {
                MUTED_FOREVER
            } else {
                millis(u)
            }
        });
        let step = self
            .client
            .set_muted(millis(now), route(conversation)?, until)
            .map_err(|e| JsError::new(&e.to_string()))?;
        step_to_js(step)
    }

    /// Until when a conversation is muted (`Infinity`: until unmuted).
    #[wasm_bindgen(js_name = mutedUntil)]
    pub fn muted_until(&self, conversation: &str) -> Result<Option<f64>, JsError> {
        Ok(self.client.muted_until(&route(conversation)?).map(|until| {
            if until == MUTED_FOREVER {
                f64::INFINITY
            } else {
                number(until)
            }
        }))
    }

    /// Tells the members of a conversation connected right now that this
    /// device is typing, stopped, online or offline: relayed, never stored.
    #[wasm_bindgen(unchecked_return_type = "Step")]
    pub fn signal(
        &mut self,
        now: f64,
        conversation: &str,
        #[wasm_bindgen(unchecked_param_type = "SignalKind")] kind: &str,
    ) -> Result<JsValue, JsError> {
        let kind = match kind {
            "typing" => SignalKind::Typing,
            "idle" => SignalKind::Idle,
            "online" => SignalKind::Online,
            "offline" => SignalKind::Offline,
            "hello" => SignalKind::Hello,
            _ => return Err(JsError::new("unknown signal")),
        };
        let step = self
            .client
            .signal(millis(now), route(conversation)?, kind)
            .map_err(|e| JsError::new(&e.to_string()))?;
        step_to_js(step)
    }

    #[wasm_bindgen(js_name = setTimer, unchecked_return_type = "Step")]
    pub fn set_timer(
        &mut self,
        now: f64,
        conversation: &str,
        seconds: u32,
    ) -> Result<JsValue, JsError> {
        let step = self
            .client
            .set_timer(millis(now), route(conversation)?, seconds)
            .map_err(|e| JsError::new(&e.to_string()))?;
        step_to_js(step)
    }

    /// The conversation's disappearing-message timer, in seconds (zero: off).
    pub fn timer(&self, conversation: &str) -> Result<u32, JsError> {
        Ok(self.client.timer(&route(conversation)?))
    }

    /// Starts a group with these people (cards), named `name` (may be
    /// empty). Returns `{ conversation, step }`.
    #[wasm_bindgen(
        js_name = startGroup,
        unchecked_return_type = "{ conversation: string; step: Step }"
    )]
    pub fn start_group(
        &mut self,
        now: f64,
        cards: Vec<String>,
        name: &str,
    ) -> Result<JsValue, JsError> {
        let contacts = cards
            .iter()
            .map(|card| {
                ContactCard::from_text(card).ok_or_else(|| JsError::new("not a krypt card"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let (id, step) = self
            .client
            .start_group(millis(now), &contacts, name)
            .map_err(|e| JsError::new(&e.to_string()))?;
        let out: JsValue = js_sys::Object::new().into();
        set(&out, "conversation", &hex(&id).into())?;
        set(&out, "step", &step_to_js(step)?)?;
        Ok(out)
    }

    /// Names the group for everyone (empty: no name).
    #[wasm_bindgen(unchecked_return_type = "Step")]
    pub fn rename(&mut self, now: f64, conversation: &str, name: &str) -> Result<JsValue, JsError> {
        let step = self
            .client
            .rename(millis(now), route(conversation)?, name)
            .map_err(|e| JsError::new(&e.to_string()))?;
        step_to_js(step)
    }

    /// The group's name (empty: none).
    #[wasm_bindgen(js_name = groupName)]
    pub fn group_name(&self, conversation: &str) -> Result<String, JsError> {
        Ok(self.client.group_name(&route(conversation)?))
    }

    /// Tells the group this identity leaves. Returns `{ senderSeq, step }`;
    /// forget the conversation once that message is sent.
    #[wasm_bindgen(unchecked_return_type = "{ senderSeq: number; step: Step }")]
    pub fn leave(&mut self, now: f64, conversation: &str) -> Result<JsValue, JsError> {
        let (seq, step) = self
            .client
            .leave(millis(now), route(conversation)?)
            .map_err(|e| JsError::new(&e.to_string()))?;
        let out: JsValue = js_sys::Object::new().into();
        set(&out, "senderSeq", &number(seq).into())?;
        set(&out, "step", &step_to_js(step)?)?;
        Ok(out)
    }

    /// Everyone this device shares a conversation with, one card each.
    #[wasm_bindgen(js_name = knownContacts)]
    pub fn known_contacts(&self) -> Vec<String> {
        self.client
            .known_contacts()
            .iter()
            .map(ContactCard::to_text)
            .collect()
    }

    /// Forgets a conversation on this device (silently: nobody is told).
    #[wasm_bindgen(unchecked_return_type = "Step")]
    pub fn forget(&mut self, now: f64, conversation: &str) -> Result<JsValue, JsError> {
        let step = self
            .client
            .forget(millis(now), route(conversation)?)
            .map_err(|e| JsError::new(&e.to_string()))?;
        step_to_js(step)
    }

    /// Blocks an identity (hex): no invitations or messages from it.
    #[wasm_bindgen(unchecked_return_type = "Step")]
    pub fn block(&mut self, identity: &str) -> Result<JsValue, JsError> {
        let step = self
            .client
            .block(array(identity)?)
            .map_err(|e| JsError::new(&e.to_string()))?;
        step_to_js(step)
    }

    #[wasm_bindgen(unchecked_return_type = "Step")]
    pub fn unblock(&mut self, identity: &str) -> Result<JsValue, JsError> {
        step_to_js(self.client.unblock(array(identity)?))
    }

    /// Identities (hex) this device blocks.
    pub fn blocked(&self) -> Vec<String> {
        self.client.blocked().map(|i| hex(&i)).collect()
    }

    /// What a new device of this identity receives (seal it with
    /// `LinkOffer`): the identity, its devices and the app's `app` bytes.
    #[wasm_bindgen(js_name = linkPayload)]
    pub fn link_payload(&self, app: Vec<u8>) -> Vec<u8> {
        self.client.link_payload(app).encode()
    }

    /// Adds a newly linked device (its card): it joins every conversation.
    #[wasm_bindgen(js_name = addDevice, unchecked_return_type = "Step")]
    pub fn add_device(&mut self, now: f64, card: &str) -> Result<JsValue, JsError> {
        let card = ContactCard::from_text(card).ok_or_else(|| JsError::new("not a krypt card"))?;
        let step = self
            .client
            .add_device(millis(now), card)
            .map_err(|e| JsError::new(&e.to_string()))?;
        step_to_js(step)
    }

    /// Unlinks one of this identity's devices (by its card).
    #[wasm_bindgen(js_name = removeDevice, unchecked_return_type = "Step")]
    pub fn remove_device(&mut self, now: f64, card: &str) -> Result<JsValue, JsError> {
        let card = ContactCard::from_text(card).ok_or_else(|| JsError::new("not a krypt card"))?;
        step_to_js(self.client.remove_device(millis(now), card.inbox))
    }

    /// This identity's other devices, as cards.
    pub fn devices(&self) -> Vec<String> {
        self.client
            .devices()
            .iter()
            .map(ContactCard::to_text)
            .collect()
    }

    /// A backup of this identity and its contacts with the app's `app`
    /// bytes, sealed under a passkey's PRF output.
    #[wasm_bindgen(js_name = sealBackup)]
    pub fn seal_backup(&self, app: Vec<u8>, prf: &[u8]) -> Result<Vec<u8>, JsError> {
        let prf: [u8; 32] = prf
            .try_into()
            .map_err(|_| JsError::new("a PRF output is 32 bytes"))?;
        Ok(self.client.backup(app).seal(&Rand::os(), &prf))
    }

    /// This identity's signature claiming `handle` for this device's card.
    #[wasm_bindgen(js_name = signHandle)]
    pub fn sign_handle(&self, handle: &str, challenge: &[u8]) -> Vec<u8> {
        self.client.sign_handle(handle, challenge).to_vec()
    }
}

/// The new device's side of linking: leave `publicKey` at `keyDrop`, then
/// show `code`, wait at `drop` for the sealed payload, `open` it, and answer
/// at `replyDrop`.
#[wasm_bindgen]
#[derive(Debug)]
pub struct LinkInvite(krypt_core::link::LinkInvite);

#[wasm_bindgen]
impl LinkInvite {
    #[wasm_bindgen(constructor)]
    pub fn new() -> LinkInvite {
        LinkInvite(krypt_core::link::LinkInvite::new(&Rand::os()))
    }

    #[wasm_bindgen(getter)]
    pub fn code(&self) -> String {
        self.0.code.to_text()
    }

    #[wasm_bindgen(getter, js_name = keyDrop)]
    pub fn key_drop(&self) -> String {
        hex(&self.0.code.key_drop())
    }

    /// The X-Wing public key, to leave at `keyDrop` before showing `code`.
    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> Vec<u8> {
        self.0.public_key().to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn drop(&self) -> String {
        hex(&self.0.code.drop())
    }

    #[wasm_bindgen(getter, js_name = replyDrop)]
    pub fn reply_drop(&self) -> String {
        hex(&self.0.code.reply_drop())
    }

    /// Opens the sealed payload: a link payload for `Device.createLinked`.
    pub fn open(&mut self, sealed: &[u8]) -> Result<Vec<u8>, JsError> {
        self.0
            .open(sealed)
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// Seals this (new) device's card as the answer.
    pub fn reply(&self, card: &str) -> Result<Vec<u8>, JsError> {
        let card = ContactCard::from_text(card).ok_or_else(|| JsError::new("not a krypt card"))?;
        Ok(self.0.reply(&card))
    }
}

impl Default for LinkInvite {
    fn default() -> LinkInvite {
        LinkInvite::new()
    }
}

/// The existing device's side: fetch the new device's key from
/// `linkKeyDrop(code)`, seal a payload for the code and that key, leave it
/// at `drop`, then open the answer from `replyDrop`.
#[wasm_bindgen]
#[derive(Debug)]
pub struct LinkOffer {
    offer: krypt_core::link::LinkOffer,
    sealed: Vec<u8>,
}

#[wasm_bindgen]
impl LinkOffer {
    pub fn seal(code: &str, public_key: &[u8], payload: &[u8]) -> Result<LinkOffer, JsError> {
        let code = LinkCode::from_text(code).map_err(|e| JsError::new(&e.to_string()))?;
        let (offer, sealed) = krypt_core::link::LinkOffer::seal(code, public_key, payload)
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(LinkOffer { offer, sealed })
    }

    #[wasm_bindgen(getter)]
    pub fn sealed(&self) -> Vec<u8> {
        self.sealed.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn drop(&self) -> String {
        hex(&self.offer.code.drop())
    }

    #[wasm_bindgen(getter, js_name = replyDrop)]
    pub fn reply_drop(&self) -> String {
        hex(&self.offer.code.reply_drop())
    }

    /// The new device's card, from its sealed answer.
    #[wasm_bindgen(js_name = openReply)]
    pub fn open_reply(&self, sealed: &[u8]) -> Result<String, JsError> {
        self.offer
            .open_reply(sealed)
            .map(|card| card.to_text())
            .map_err(|e| JsError::new(&e.to_string()))
    }
}

/// Whether `text` is a link code (an old one too, so it can be refused
/// with a reason).
#[wasm_bindgen(js_name = isLinkCode)]
pub fn is_link_code(text: &str) -> bool {
    matches!(LinkCode::from_text(text), Ok(_) | Err(LinkError::OldCode))
}

/// The request that fetches what an invite link points at (its group's
/// name, and the key requests are sealed to).
#[wasm_bindgen(js_name = joinHeaderFrame)]
pub fn join_header_frame(code: &str) -> Result<Vec<u8>, JsError> {
    JoinCode::from_text(code)
        .map(|code| code.header_frame())
        .map_err(|e| JsError::new(&e.to_string()))
}

/// The group's name in an invite link's header (checked against the link).
#[wasm_bindgen(js_name = joinHeaderName)]
pub fn join_header_name(code: &str, header: &[u8]) -> Result<String, JsError> {
    let code = JoinCode::from_text(code).map_err(|e| JsError::new(&e.to_string()))?;
    code.read_header(header)
        .map(|h| h.name)
        .map_err(|e| JsError::new(&e.to_string()))
}

/// An invite link's code (what follows `#join=`), from its seed (hex, in
/// the group's rules) and the group it belongs to.
#[wasm_bindgen(js_name = linkCodeOf)]
pub fn link_code_of(seed: &str, conversation: &str) -> Result<String, JsError> {
    let seed: [u8; 32] = unhex(seed)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| JsError::new("not a link seed"))?;
    Ok(LinkKeys::from_seed(&seed, &route(conversation)?)
        .code
        .to_text())
}

/// Where the device showing `code` left its public key.
#[wasm_bindgen(js_name = linkKeyDrop)]
pub fn link_key_drop(code: &str) -> Result<String, JsError> {
    LinkCode::from_text(code)
        .map(|code| hex(&code.key_drop()))
        .map_err(|e| JsError::new(&e.to_string()))
}

/// The identity (hex) a link payload makes the new device part of: shown
/// on it, to be checked against the other device's, before it joins.
#[wasm_bindgen(js_name = linkIdentity)]
pub fn link_identity(payload: &[u8]) -> Result<String, JsError> {
    LinkPayload::decode(payload)
        .map(|p| hex(&krypt_core::identity::Identity::from_seed(p.identity_seed).public()))
        .map_err(|_| JsError::new("not a link payload"))
}

/// The app's bytes inside a link payload.
#[wasm_bindgen(js_name = linkApp)]
pub fn link_app(payload: &[u8]) -> Result<Vec<u8>, JsError> {
    LinkPayload::decode(payload)
        .map(|p| p.app)
        .map_err(|_| JsError::new("not a link payload"))
}

/// Opens a sealed backup with a passkey's PRF output: a link payload to
/// create the restored device from (just the identity: old devices are not
/// trusted again), the contacts' cards, and the app's bytes.
#[wasm_bindgen(
    js_name = openBackup,
    unchecked_return_type = "{ payload: Uint8Array; contacts: string[]; app: Uint8Array }"
)]
pub fn open_backup(sealed: &[u8], prf: &[u8]) -> Result<JsValue, JsError> {
    let prf: [u8; 32] = prf
        .try_into()
        .map_err(|_| JsError::new("a PRF output is 32 bytes"))?;
    let backup = Backup::open(sealed, &prf).map_err(|e| JsError::new(&e.to_string()))?;
    let payload = LinkPayload {
        identity_seed: backup.identity_seed,
        devices: Vec::new(),
        app: Vec::new(),
    };
    let contacts = Array::new();
    for card in &backup.contacts {
        contacts.push(&card.to_text().into());
    }
    let out: JsValue = js_sys::Object::new().into();
    set(
        &out,
        "payload",
        &Uint8Array::from(payload.encode().as_slice()),
    )?;
    set(&out, "contacts", &contacts)?;
    set(&out, "app", &Uint8Array::from(backup.app.as_slice()))?;
    Ok(out)
}

#[wasm_bindgen(js_name = callLimits, unchecked_return_type = "CallLimits")]
pub fn call_limits() -> Result<JsValue, JsError> {
    let out: JsValue = js_sys::Object::new().into();
    set(&out, "sdpMax", &number(CALL_SDP_MAX as u64).into())?;
    set(&out, "timerMax", &DISAPPEAR_MAX_S.into())?;
    Ok(out)
}

#[wasm_bindgen(js_name = fileLimits, unchecked_return_type = "FileLimits")]
pub fn file_limits() -> Result<JsValue, JsError> {
    let out: JsValue = js_sys::Object::new().into();
    set(&out, "partSize", &FILE_PART_SIZE.into())?;
    set(&out, "sizeMax", &number(FILE_SIZE_MAX).into())?;
    set(&out, "nameMax", &number(FILE_NAME_MAX as u64).into())?;
    set(&out, "typeMax", &number(FILE_TYPE_MAX as u64).into())?;
    set(&out, "thumbnailMax", &number(THUMBNAIL_MAX as u64).into())?;
    Ok(out)
}

/// How many parts a file of `size` bytes is stored in.
#[wasm_bindgen(js_name = fileParts)]
pub fn file_parts(size: f64) -> Result<u32, JsError> {
    Ok(file::parts(self::size(size)?))
}

/// Seals part `part` of a file of `size` bytes: its plaintext in, what to
/// store out.
#[wasm_bindgen(js_name = sealPart)]
pub fn seal_part(key: &str, size: f64, part: u32, plaintext: Vec<u8>) -> Result<Vec<u8>, JsError> {
    let size = self::size(size)?;
    if part >= file::parts(size) || plaintext.len() != file::plain_len(size, part) as usize {
        return Err(JsError::new("part has the wrong length"));
    }
    let mut buffer = plaintext;
    file::seal(&array(key)?, size, part, &mut buffer);
    Ok(buffer)
}

/// Opens a stored part; throws if it is damaged or not part of this file.
#[wasm_bindgen(js_name = openPart)]
pub fn open_part(key: &str, size: f64, part: u32, stored: Vec<u8>) -> Result<Vec<u8>, JsError> {
    let mut buffer = stored;
    file::open(&array(key)?, self::size(size)?, part, &mut buffer)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(buffer)
}

/// The 60-digit safety number two identities compare, in groups of five.
#[wasm_bindgen(js_name = safetyNumber)]
pub fn safety_number_text(a: &str, b: &str) -> Result<String, JsError> {
    let key = |text: &str| -> Result<[u8; 32], JsError> {
        unhex(text)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| JsError::new("not an identity"))
    };
    Ok(safety_number(&key(a)?, &key(b)?)
        .iter()
        .map(|group| format!("{group:05}"))
        .collect::<Vec<_>>()
        .join(" "))
}

/// The short fingerprint of an identity (hex), as shown next to its name.
#[wasm_bindgen(js_name = fingerprintOf)]
pub fn fingerprint_of(identity: &str) -> Result<String, JsError> {
    let key: [u8; 32] = unhex(identity)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| JsError::new("not an identity"))?;
    Ok(fingerprint(&key))
}

/// A QR code for `text` (medium error correction): `{ size, modules }`,
/// with `modules[y * size + x]` 1 for dark. Drawing is the caller's.
#[wasm_bindgen(js_name = qrCode, unchecked_return_type = "{ size: number; modules: Uint8Array }")]
pub fn qr_code(text: &str) -> Result<JsValue, JsError> {
    let code = qrcode::QrCode::with_error_correction_level(text, qrcode::EcLevel::M)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let modules: Vec<u8> = code
        .to_colors()
        .into_iter()
        .map(|c| u8::from(c == qrcode::Color::Dark))
        .collect();
    let out: JsValue = js_sys::Object::new().into();
    #[allow(clippy::cast_precision_loss)]
    set(&out, "size", &(code.width() as f64).into())?;
    set(&out, "modules", &Uint8Array::from(modules.as_slice()))?;
    Ok(out)
}

/// Whether `text` is a valid contact card.
#[wasm_bindgen(js_name = isContactCard)]
pub fn is_contact_card(text: &str) -> bool {
    ContactCard::from_text(text).is_some()
}

/// The identity (hex) a contact card names, if `text` is a valid card.
#[wasm_bindgen(js_name = cardIdentity)]
pub fn card_identity(text: &str) -> Option<String> {
    ContactCard::from_text(text).map(|card| hex(&card.identity))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let id = [0xAB; 16];
        assert_eq!(route(&hex(&id)).unwrap(), id);
        assert!(unhex("abc").is_none());
        assert!(unhex("zz").is_none());
    }
}

/// The kind of photo or video `prefix` (its first bytes) starts: "jpeg",
/// "png", "webp", "gif" or "mp4" (QuickTime too) and "webm", which krypt
/// cleans, or "still" (HEIF, AVIF), which only drawing again cleans.
#[wasm_bindgen(js_name = mediaFormat)]
pub fn media_format(prefix: &[u8]) -> Option<String> {
    use krypt_core::scrub::Format;
    Some(
        match krypt_core::scrub::detect(prefix)? {
            Format::Jpeg => "jpeg",
            Format::Png => "png",
            Format::Webp => "webp",
            Format::Mp4 => "mp4",
            Format::Gif => "gif",
            Format::Webm => "webm",
            Format::StillImage => "still",
        }
        .to_owned(),
    )
}

/// A JPEG, PNG, WebP or GIF without its location, camera and editing
/// metadata.
#[wasm_bindgen(js_name = scrubImage)]
pub fn scrub_image(bytes: &[u8]) -> Result<Vec<u8>, JsError> {
    krypt_core::scrub::scrub_image(bytes).map_err(|e| JsError::new(&e.to_string()))
}

/// Blanks the metadata boxes of an MP4/MOV, or of one of its top-level
/// boxes, in place (sizes unchanged). Returns how many it blanked.
#[wasm_bindgen(js_name = scrubMp4)]
pub fn scrub_mp4(bytes: &mut [u8]) -> Result<u32, JsError> {
    let blanked = krypt_core::scrub::scrub_mp4(bytes).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(u32::try_from(blanked).unwrap_or(u32::MAX))
}

/// A voice message (WebM) without the recorder's name, the browser's, a
/// title or the date, in place.
#[wasm_bindgen(js_name = scrubWebm)]
pub fn scrub_webm(bytes: &mut [u8]) -> Result<u32, JsError> {
    let scrubbed =
        krypt_core::scrub::scrub_webm(bytes).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(u32::try_from(scrubbed).unwrap_or(u32::MAX))
}
