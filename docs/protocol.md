# krypt protocol (v1, as implemented)

## Pieces

- **Device (client):** owns an identity, MLS state and a durable store.
- **Mailbox:** the only shared infrastructure. It runs as a Cloudflare Durable
  Object in production and as the same state machine (`krypt_core::mailbox`)
  in the simulator. It orders, stores and forwards ciphertext, and never sees
  plaintext.
- **No direct path for messages** (decision 8): every message goes through
  the mailbox, which pushes it to members over WebSockets. No peer ever
  learns another device's IP address from messaging. WebRTC (with Cloudflare
  TURN) opens on demand for calls only (decision 31).
- **File storage:** an R2 bucket behind the same Worker holds files that
  members share, encrypted on the sender's device (decision 29).

## Identity

- **Identity root:** an Ed25519 key, generated on the device. There is no
  phone number, email or account.
- **Device certificate:**
  - Signed by the root.
  - Binds the device's MLS signature key, its device id (32 random bytes) and
    its inbox.
  - It *is* the device's MLS credential, so any member can verify that a leaf
    belongs to the identity it claims.
- **Contact card:** `{identity, inbox}`, exchanged out of band (QR code or link).
  When inviting, the inviter checks that the claimed key package's certificate
  matches the card. A malicious mailbox therefore cannot substitute a key
  package.
- **Fingerprints and safety numbers:**
  - Fingerprint: BLAKE3 of the identity key, shown as `7F3A 91C2 0B4E D5A8`.
  - Safety number: 60 digits from 5,200 iterated BLAKE3 hashes per identity,
    symmetric between the two parties.

## Conversations

Every conversation is an MLS group (RFC 9420); 1:1 chats are groups of two.

| Setting | Value |
|---|---|
| Ciphersuite | `MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519` (0x004F, hybrid post-quantum) |
| Wire format | Pure ciphertext (handshakes encrypted too) |
| Ratchet tree | Shipped in the Welcome |
| Past epochs kept | None |
| Members | At most 256 (devices) |
| Padding | Plaintexts padded to 32 bytes |
| Out-of-order tolerance | 128 generations |

### Post-quantum encryption (decision 27)

Everything in MLS that carries group secrets to members goes through HPKE:
welcomes to new members' key packages, and the path secrets in every commit.
krypt's ciphersuite does HPKE with **X-Wing**, a hybrid KEM of X25519 and
ML-KEM-768 (FIPS 203). Recording today's traffic and breaking it with a
future quantum computer gets nothing: every epoch's secrets descend from
X-Wing-encrypted values. If ML-KEM turns out to be weak, X25519 still gives
today's guarantees.

- **Signatures stay Ed25519.** Forging a signature needs a quantum computer
  at the moment of the attack, not afterwards, so there is time to move to
  ML-DSA. ML-DSA would add 2.4 KB to every message (each one is signed).
- **Symmetric crypto is unchanged:** AES-128-GCM and SHA-256 are NIST's
  category-1 choices against quantum attackers too.
- **The code point is provisional** (draft-ietf-mls-pq-ciphersuites).
  krypt talks only to itself, so a change only means re-pinning it.
- **Only post-quantum.** Devices publish only post-quantum key packages,
  inviters refuse anything else, the mailbox drops any other, and a device
  joins only post-quantum conversations. Devices upgraded from before this
  replace their published key packages on first start. Conversations created
  before 2026-11-06 stay classic; starting a new one gets the protection.

**Cost** (keys are 38× larger, so only messages that carry keys grow):

| | Classic | Post-quantum |
|---|---|---|
| Key package | 432 B | 2.8 KB |
| Welcome into a full group, per member | 415 B | 2.8 KB (720 KB at 256) |
| Commit encrypting to every member (blank tree), per member | 90 B | 1.25 KB |
| Chat message | unchanged | unchanged |
| Storage written per message sent | 4.4 KB | 0.9 KB (with no past epochs kept, see below, and OpenMLS state stored as postcard, decision 39) |

Frames are therefore up to 1 MiB (was 256 KiB). A test builds a 32-member
group, fills its tree and checks that the largest submissions scaled to 256
members still fit. The client refuses invites past 256 members and drops any
commit too large to send instead of storing it.

### The conversation log

The mailbox keeps one append-only log per conversation, with contiguous
sequence numbers starting at 1.

**Commits:**
- The mailbox accepts **exactly one commit per epoch**. A commit for an older
  epoch gets `StaleEpoch`. This keeps history linear with no coordination
  between members.
- The first commit (from epoch 0) creates the log.
- A commit may carry welcomes. On acceptance the mailbox appends
  `InboxWelcome{conversation, join_after, welcome}` to each new member's inbox,
  atomically with the commit: at most 8 an hour from one conversation to one
  inbox (512 inboxes an hour), the rest dropped, so no conversation can
  flood an inbox until it evicts the invitations it should keep. An inbox's
  reader carries on past entries that were evicted; a conversation's reader
  is told it fell behind.
- A welcome is checked before anything is stored (its group id is the log
  it came from, its rules read, every certificate valid, nobody blocked).
  Past 1,024 conversations this device never sent anything in, welcomes
  from people it does not talk with are dropped.

**Application messages:**
- Accepted only in the log's current epoch (`TooOld` if older, `FutureEpoch`
  if newer). The log then puts every message after the commits before it, so
  each is decrypted in the epoch it was sealed in and **no member keeps past
  epochs' keys**. That is better forward secrecy, and much less writing:
  OpenMLS stores every member's public keys for each past epoch it keeps and
  rewrites them on every message. With 8 epochs kept, a 33-member
  post-quantum group wrote 1.35 MB per message; now 1.3 KB.

**Only members write (decision 16).** Every submission carries a 16-byte tag:
BLAKE3 keyed by the epoch's *write key* over the route and the message. The
write key is exported from MLS (`"krypt mailbox write v1"`, context = route),
so it reveals nothing about message keys, and a removed member never learns
the keys of later epochs.
- Each commit also carries the next epoch's write key, taken from the pending
  commit, so the mailbox can check the members' next writes. It keeps the
  key of the current epoch only.
- A commit or message with a missing or wrong tag gets `Forbidden`.
  Resubmissions of accepted entries are answered before the check.
- **Creation:** a conversation's route is the hash of a fresh Ed25519
  *creation key*. The first commit is signed by that key, so nobody can create
  the log first or create it with a different first commit. The creator
  forgets the key once the log exists.

**Resubmissions:** answered with the original seq. The mailbox dedups by
content hash, which is what makes client retries safe.

### Client rules

1. **Group state advances only in log order.**
   - Own commits are merged on reading them back (as `OwnPrivateMessage`
     matching the pending commit's hash).
   - Another member's commit at the same epoch means ours lost. The mailbox
     rejects ours; we clear it, catch up and retry the intent.
2. **Membership changes are intents** (`Add`, `Remove`, `Update`):
   - Queued durably and applied one at a time.
   - Idempotent: already done counts as done. This handles two members
     inviting the same person concurrently.
3. **Sending:**
   - Messages get a per-sender, per-conversation `sender_seq` and wait in a
     durable outbox.
   - They are sealed (encrypted) only when the device is caught up with the
     log, and only within a **32-message send window** from the oldest unsent
     one.
   - The window guarantees no message is overtaken by 32 or more of the same
     sender's later messages in the log. That keeps every
     receiver inside the ratchet's out-of-order tolerance (128), so a message
     never becomes undecryptable because later ones arrived first.
   - A message refused as `TooOld` is re-sealed with the same `sender_seq`
     after catching up.
4. **Receiving:**
   - Entries are processed strictly in log order, whether pushed or fetched;
     a pushed entry past a gap triggers a fetch.
   - Duplicates are dropped in two layers: content hash (cheap, for the same
     ciphertext) and a 1,024-wide per-sender `sender_seq` window (for
     re-sealed copies).
   - A message that cannot be decrypted is reported as `Event::Undecryptable`,
     never dropped silently.
5. **Key packages:**
   - Each device keeps several single-use key packages plus one **last-resort**
     package (RFC 9420 §16.8) published at its inbox, so it can always be
     invited. They are refreshed every 14 days.
   - The mailbox remembers recent key package hashes and never stores, or
     hands out, one twice. Otherwise a retried publish would create members
     who can never join.
   - An inbox belongs to whoever first publishes to it with a certificate
     naming that inbox. Later publishes must come from the same identity
     (`NotOwner`).
   - At most 16 regular key packages are handed out per inbox per hour; after
     that, claims get the last-resort package, so draining an inbox gains an
     attacker nothing.

## Push

- **Live:** a device keeps one WebSocket per log it follows
  (`wss://api.krypt.chat/v1/ws/<route hex>`). Every entry appended to the log
  is pushed to every socket as a `Notify` frame. Entries up to 16 KiB ride
  inline; larger ones arrive as a bare wakeup that the device fetches.
- **Requests** for that log are sent over the same socket; responses come back
  on it, matched by request id.
- **Reconnects** back off from 0.5 s to 30 s with jitter, and every (re)connect
  fetches whatever was missed. Polling remains only as a 5-minute safety net.
- **Keepalive:** `"ping"` every 30 s, answered by the edge without waking the
  log's object.
- **Wakeups** for devices that are not connected: a `Watch` registers a push
  target (Web Push, APNs or FCM) for 30 days.
  - A conversation's watch must carry a tag from a current write key; an
    inbox's watch must be signed by the inbox's owner. The mailbox learns the
    owner from the first key packages, so a new device registers its inbox
    only once they are accepted.
  - Devices renew weekly and persist when each log is due, so restarting
    re-registers nothing.
  - Each target is woken at most once per 10 s.
- **Web Push** (live): an empty POST (RFC 8030) with a VAPID token (RFC 8292),
  `TTL: 86400`, `Urgency: high`. With no payload, push services learn only
  that something happened.
  - Tokens are signed once per push service per twelve hours.
  - Only known browser push services are contacted (FCM, Mozilla, Apple,
    WNS), so a member cannot make the mailbox call arbitrary URLs. An
    endpoint is parsed as `fetch` parses it (no credentials, fragment or
    other port), and the parsed URL is the one sent to.
  - A target its push service reports gone (404/410) is forgotten.
  - The service worker shows "New activity in your chats", never content,
    and nothing when the app is already in front.
  - Web Push only: krypt is a web app (decision 53 removed the native ones).
  - The VAPID private key is in `secrets/push.yaml` and the Worker secret
    `VAPID_PRIVATE_KEY` (`just edge-push-secret`).

## Files (decision 29)

A shared file never passes through MLS or the log: only its key does.

1. **Clean.** Photos and videos lose their metadata on the sender's device
   before anything else happens (`krypt_core::scrub`):
   - JPEG: EXIF, XMP, IPTC and comments go. A photo's orientation survives
     as a minimal EXIF block holding only that tag.
   - PNG: text, EXIF and time chunks go.
   - WebP: EXIF and XMP chunks go, and the header flags are fixed.
   - MP4/MOV: every `udta`, `meta` and `uuid` box becomes a `free` box of the
     same size with its contents zeroed, so no offset changes. The browser
     reads only box headers and the `moov` box, never the whole video.
   - Other images (HEIC, AVIF…) are re-encoded as JPEG, which keeps only the
     pixels. A photo or video that cannot be cleaned is not sent.
2. **Seal.** The file gets a random id and a random 256-bit key. It is split
   into 4 MiB parts, each sealed with ChaCha20-Poly1305 (`krypt_core::file`):
   - The nonce holds the part's index and whether it is the last.
   - The associated data holds the file's size.
   - So parts cannot be reordered, dropped, repeated or truncated without
     failing to open, and a key is never reused.
3. **Store.** Each part is `PUT /v1/file/<route>/<file>/<part>` with a
   `krypt-auth` header: the current epoch and a tag over
   (route, file, part, length) keyed by the epoch's write key.
   - The Worker asks the conversation's object (an `AuthorizeFile` frame),
     which checks the tag like a submission and charges the conversation's
     daily allowance (1 GiB). Only then does the body stream into R2,
     without passing through the Worker.
   - A part is never replaced once stored; a retry gets 200.
   - A stale proof (409) means a commit landed: the device catches up and
     asks again.
4. **Share.** Once every part is stored, a message (`Body::File`) carries
   what is needed to fetch and open it, encrypted like any message:
   - the id, the key and the size
   - the name and media type
   - pixel dimensions
   - a preview of at most 32 KiB, so a photo shows before it downloads
5. **Fetch.** Members `GET` each part and open it. Photos and videos up to
   16 MiB download by themselves; anything else waits for a tap.

| Limit | Value |
|---|---|
| File size | 100 MiB |
| Part size | 4 MiB (plus a 16-byte tag) |
| Kept in R2 | 30 days after upload (bucket lifecycle rule, `just cf-r2-apply`) |
| Per conversation | 1 GiB of parts a day |
| Per address | 32 parts a minute |

Uploads survive reloads: the cleaned file waits on the device with a count of
parts stored, and resumes. Received files are kept on the device.

**In the browser, only these display inline:**
- images: JPEG, PNG, WebP, GIF and AVIF;
- video: MP4, WebM and QuickTime.

Everything else is stored as `application/octet-stream` and can only be
saved, never opened, because a document opened from a `blob:` URL would run
with krypt's origin and could read its keys. File names lose path separators,
control characters and text-direction overrides.

**What the server can see:** the size of each part, when it was stored, and
how often it is fetched. Reading a part, like reading a log, needs only its
route and file id, which are random and shared only with members.

## Calls (decision 31)

A call is WebRTC between two devices. Its signaling travels inside the
conversation as MLS application messages (`Body::Call`), which carry:

| Field | Meaning |
|---|---|
| `call` | 16 random bytes, chosen by the caller |
| `to` | the device it is for, or zeros for every device of the other members |
| `kind` | offer, answer, candidates (ICE, newline-separated) or end (hangup, declined, busy, unanswered, failed) |
| `video` | whether the call has video |
| `sdp` | the session description, at most 32 KiB |

Session descriptions carry each side's DTLS fingerprint. Because MLS
authenticates who sent them, the keys that encrypt the media (DTLS-SRTP) are
authenticated end to end: neither the mailbox nor a relay can step in.

1. **Ring.** The caller sends an offer to everyone, with the candidates
   gathered in 1.5 s. Every device of the callee rings, and asks for relay
   credentials meanwhile. An offer older than 60 s when it arrives (the
   device was offline) is recorded as a missed call instead.
2. **Answer.** The first device to accept answers the caller's device. Only
   then does anything about the callee, its addresses included, reach the
   caller. The callee's other devices see the answer and stop ringing; a
   second answer gets an end from the caller.
3. **Media.** Both sides always negotiate audio and video, so the camera
   turns on and off mid-call without renegotiating. When the connection
   breaks (Wi-Fi to cellular), the caller restarts ICE with a new offer to
   the callee's device; after 12 s without media the call ends.
4. **End.** Either side sends an end to everyone. Each device records the
   call in the conversation's history, which only it keeps.

**Glare.** If both call each other at once, the lower call id wins on both
sides, and the other caller answers it.

**Relay.** `POST /v1/turn/<route>` with a `krypt-auth` header (the epoch and
a tag over the route keyed by the epoch's write key) returns `iceServers`.
The conversation's object checks the tag (`AuthorizeTurn`) and the day's
allowance; the Worker then asks Cloudflare for credentials that last 6 h,
and a longer call renews them. Without a TURN key the Worker returns STUN
only. "Always relay calls" sets `iceTransportPolicy: relay`, so the other
side never learns this device's address.

| Limit | Value |
|---|---|
| Relay credentials per conversation | 64 a day |
| Per address | 10 a minute |
| Credentials last | 6 hours |
| Unanswered call | 45 s |

**Group calls (decision 43).** In a conversation with more than one other
person a call is a mesh. `join` (to everyone, no description) says a device
is in the call; the first one rings the group, and devices that see a call
running can join it later. For each pair of devices in the call, the one
with the lower device id sends the offer, so two never offer at once; the
other answers, and candidates and restarts work as in a one-to-one call. An
`end` to everyone leaves. A call holds at most 8 devices, and each device's
video upload (2.5 Mbit/s) is shared among its connections.

## Groups (decision 44)

A group's name lives in its MLS group context, in the same extension as the
disappearing-message timer: the timer (u32), then a length byte and the name
(UTF-8, at most 64 bytes). Renaming is a commit, so all members, and anyone
added later, agree on it. `Client::start_group` creates a group with several
people at once. Leaving sends a `Leave` application message; every member
that receives it queues the removal of all of the leaver's devices, and the
first such commit wins (the rest find them gone). The leaving device deletes
the conversation once its message is stored.

## Replies, reactions, edits, deletions, receipts, voice (decision 49)

A message is named the same way by every member: the device that sent it and
that device's `sender_seq` (`MessageRef`, 40 bytes). Newer application
message kinds refer to one (version 2; clients that predate them drop them
silently, as they drop any kind they do not know):

| Kind | Body | Wakes devices |
|---|---|---|
| 6 `Reply` | ref, text | yes |
| 7 `React` | ref, emoji (≤ 32 bytes, no control characters; empty takes it back) | yes; taking back, no |
| 8 `Edit` | ref, new text | no |
| 9 `Delete` | ref (delete for everyone) | yes |
| 10 `Receipt` | 1–64 refs, one per sender device: the newest read | no |
| 11 `Voice` | file reference, length (≤ 15 min), 64-byte waveform; audio/webm or audio/mp4, ≤ 8 MiB, no preview | yes |

A submit can be **quiet**: a flags byte after the creation field, present
only when set. The mailbox stores a quiet message and pushes it to open
sockets but wakes no device, so receipts and edits make no notification. The
flag is the one plaintext hint of what a message is.

Edits and deletions are checked by each receiving device against the stored
message: only its sender's identity may change it, within 24 hours by both
messages' sender clocks (so every device decides alike), and an edit never
changes when a message disappears. One that arrives before its message waits
up to 30 days for it (`parked`). A deleted message keeps only its place:
"This message was deleted"; its file is dropped. Read receipts are kept as
watermarks per reader, sent in one-to-one chats and groups of up to eight,
at most every two seconds, never to message requests; at most one waits to be
sent per conversation (a newer one replaces it). Voice messages are scrubbed
before they leave the device: WebM in place (`krypt_core::scrub::scrub_webm`:
the recorder's and browser's names, a title, the date and track names zeroed;
tags, chapters and attachments made padding), MP4 like videos.

## Group admins (decision 51)

A group's rules live in its context, in extension `0xF0D2` (required of
members once set): a version, who may add people (`everyone`/`admins`), who
may rename the group or change its timer, the admins (sorted identities),
and, optionally, the invite link's secret. A new group's creator is its admin
and everyone may add and rename, as before. A group from before admins has
no rules (everyone may do everything) until its first rules, which must make
every member an admin. The admins in effect are the rules' admins who are
members, or, if none is, the member at the lowest leaf; every member computes
the same.

The mailbox cannot see who committed, so **every member checks every commit
before merging it** (`check_commit`): only Add, Remove and group context
proposals; the committer's update path keeps its certificate and signature
key; device ids stay unique; adds by a non-admin where only admins may add
are refused, except of the committer's own devices; changes to the name or
timer by a non-admin where only admins may; any change to the rules by a
non-admin, and the rules removed or damaged; extensions other than these and
`RequiredCapabilities`, which may change only to add `0xF0D2` with a group's
first rules; **the removal of an admin's devices by anyone but an admin**
(one's own devices excepted); and **any commit that leaves a group which had
an admin without one**. A commit that fails stops the conversation for that
member (`Desync`, reason `rules: …`); since every honest member fails it
alike, it stops for all of them. Each device also checks its own changes
before committing them, against the rules (`Refused`) and with
`check_commit` itself, so it never sends a commit the others would refuse.

An admin who leaves first commits a step down (`Intent::StepDown`, worked
out when the commit is made): off the admins, and, if no other admin would
be left, the member at the lowest leaf among those not themselves leaving
becomes one. Then the `Leave` goes out (messages wait for pending commits),
and whoever removes the leaver may. A non-admin's device never tries to
remove an admin. Removals say who made them (`MembersRemoved { by }`);
someone who sent `Leave` "left".

## Invite links (decision 52)

An admin turns a group's link on by putting a random 32-byte secret in the
group's rules (so every member's device has it, and any admin can approve).
From the secret *and the group's id* (`krypt_core::join`; the same secret in
another group is another link):

- An Ed25519 admin key. The requests log's route is
  `H("krypt join log v2" ‖ its public key)`; the mailbox checks it, so only
  that key opens the log (`OpenRequests`) or replaces its header (the public
  key below, and the group's name sealed under a key from `join`), even
  after the log lapses.
- `join` (16 bytes): the token a request must show, and the name key, come
  from it.
- An X-Wing key pair: requests are HPKE-sealed to its public key.
- The link: `https://krypt.chat/#join=` + base32(route ‖ `join` ‖
  BLAKE3(public key)[..16]), 77 characters. The fragment never reaches a
  server.

Each admin device follows the log of every group it is an admin of that has
a link, re-opening it at each start and whenever the group is renamed (which
also keeps it from going idle). Requests are kept 30 days, at most 512 per
log, and pushed to open sockets only: nobody is woken.

To ask, a device fetches the header (`JoinHeader` → `Header`), checks the key
against the hash in the link, shows the group's name, and sends a
`JoinRequest`: the token, and, sealed to the key, its card, the name it
gives, a **one-time key package that is never published**, the time, and its
device's signature over all of it and the link. It remembers the request
(30 days); when that lapses, the key package is deleted too.

An admin's device opens each request and drops it unless its key package is
valid, its certificate is signed by the identity the card names (with the
card's inbox) for a device id new to the group, the signature is that
device's, and it was made in the last 30 days (and not over a day ahead).
Requests from blocked people or members are dropped too. Each device keeps
how far it has read the log, so no request is shown twice, and reads on
until it has read it all. Approving adds exactly that key package (no claim
from the requester's inbox). Declining is local to the device.

The requester's device accepts the resulting Welcome without a message
request only if the group's rules carry a link that, in *that* group, is the
one it asked through, and its own leaf is the key package it sent
(`Joined { via_link }`). Another group adding it is a message request as
usual. Turning the link off or resetting it (a new secret) stops the old
link; members are told (`Rules { link }`). Removing someone resets it.

**What the mailbox sees:** that a requests log exists and when it is opened;
requesters' addresses and timing; from sockets and addresses, which devices
read the log (admins) and so probably which conversation it belongs to; the
Welcome's forward to the requester's inbox. It never sees names, cards or
who asked. Anyone with the link can fetch the log and see how many requests
there are and when, but cannot read them. Members can read them: they have
the secret. A flood of requests fills the log until an admin resets the link.

## Mute, archive, search (decision 50)

Muting is per device and withdraws the conversation's push registration
(`Watch { enable: false }`, retried until the mailbox confirms it), so a
muted conversation wakes nothing; it registers again when the mute runs out
or is lifted. Mutes are kept in the core (`0x00 'M'` records) so they survive
restarts and a new push address. Archiving and search are app data only:
archived chats leave the main list until unarchived, or until a message
arrives (unless muted); search reads the device's own decrypted history and
never leaves it.

## Typing and online (decision 47)

A **signal** says a device is typing, stopped (`idle`), online, offline, or
online and asking who else is (`hello`). It is never stored: the device sends
a `Signal` frame over the conversation's open socket, the mailbox checks it
and relays it as a `Signaled` frame to every socket open on that log, and
nothing is written. A device that is not connected never sees it.

- **Sealed** with ChaCha20-Poly1305 under a key exported from the epoch
  (`krypt signal v1`), which the mailbox does not have, with the route and
  epoch as associated data. Inside: the sender's leaf index, the kind, the
  sender's clock, and an Ed25519 signature by the sender's MLS signature key
  over all of them plus the route and epoch. Receivers check the signature
  against the leaf it names, so no member can speak for another.
- **Authorized** like a TURN request: a tag over the sealed bytes keyed by the
  current epoch's write key. A non-member, or a member on a stale epoch, is
  refused and nothing is relayed.
- **Dropped** when it is the receiver's own, from a blocked identity, more
  than two minutes from the receiver's clock, or not newer than the last
  signal from that device. Nothing is retried.

The web client sends `typing` at most every 3 s while a draft changes, and
`idle` when the draft is sent, cleared, paused for 5 s, or the chat is left.
While krypt is open and on screen it sends `hello` to its 32 most recent
accepted conversations, then `online` every 45 s, and `offline` when it goes
to the background or closes. A device online answers a `hello` with `online`
(at most every 10 s per conversation). Shown states lapse on their own
(typing after 7 s, online after 100 s), since a closed tab may say nothing.
Message requests get no signals and show none.

## Disappearing messages (decision 32)

The timer is part of the MLS group state: a group context extension
(`0xF0D1`, seconds as u32 little-endian, at most four weeks) that every
group requires its members to support. Setting it is a commit, like a key
update, so all members see the same value at the same point in the log,
and a member who joins later gets it in the welcome. Each message carries
the timer it was sent under (`expires_after_s`); every device deletes the
message that long after it was first shown.

A device upgrading from before timers republishes its key packages and
updates its leaf in each conversation, so its groups can turn timers on.
In a group with a member who has not upgraded, setting the timer fails
cleanly (`TimerRefused`).

## Requests and blocking (decisions 33 and 56)

- **Requests.** When a device joins a conversation someone else started and
  none of the other members is someone it knows (named, verified, or met in
  another accepted conversation), the conversation is a request: listed
  apart, unable to ring (calls show as missed), and its disappearing
  messages do not start their clocks. Accepting makes its members known.
  Nothing tells the sender whether a request was seen.
- **Deleting** a conversation (`Client::forget`) drops its MLS state, its
  unsent messages and its push registration (an unwatch is sent while the
  keys still exist). Nobody is told; the device stops reading the log. A
  tombstone keeps the next sender number, so if the device is invited back
  its numbering carries on and other members' duplicate windows accept its
  messages. The same holds for a device removed by others and invited back.
- **Blocking** (`Client::block`) is kept by the core: a welcome into a group
  with a blocked member is refused before joining, and a blocked identity's
  messages and calls in shared groups are dropped. A one-to-one conversation
  with the blocked person is deleted.
- **No reports** (decision 56): no message ever leaves a device
  unencrypted. Blocking is how someone stops another person reaching them.

## Linked devices, handles and backups (decisions 37 and 38)

**Linking.** Every device of an identity has its own MLS leaf, certificate
and inbox; members are identities, each with one or more devices.
1. The new device makes a secret `s` (16 bytes) and an X-Wing key pair,
   puts the 1216-byte public key at the key drop, and only then shows
   `krypt-link2:` and 32 bytes: `s` and a hash of the key. Every drop's id
   is a hash of `s` with its own label (key, payload, reply), so `s` itself
   never reaches the server.
2. An existing device scans the code, takes the key from the key drop,
   checks it against the hash, and seals to it (HPKE with X-Wing, `s` and
   the key hash in the info) the identity's root key, its devices' cards and
   the app's own data (names, accepted chats). ChaCha20-Poly1305 seals the
   payload under keys derived with BLAKE3 from the exported secret, `s`, the
   key hash and the KEM output, one key per direction; it goes to
   `PUT /v1/drop/<payload drop>` (`krypt_core::link`).
3. The new device takes it (`GET`, which empties the drop), shows the
   fingerprint of the identity inside and waits until the person confirms
   it is the one their other device shows (whoever saw the code could have
   sealed their own first), then becomes a device of the identity and
   answers with its card at the reply drop.

Each code works once: its key drop is emptied when read, and a second use is
refused ("used already"). Codes from the first version (`krypt-link:`, X25519)
are refused with a request to update krypt.
4. The existing device records it as a sibling. Every device adds its
   siblings to each conversation it is in, so they all see the same chats;
   messages from a sibling arrive like anyone's, attributed to the identity.

Drops hold one sealed payload of at most 256 KiB, are written once and read
once (a drop that was read stays closed), and are gone after 10 minutes. The
code travels by camera (or by hand), so nobody in between can substitute the
key. Unlinking a device removes its leaves from every conversation; every
other device of the identity, seeing a commit of its own identity remove a
sibling, forgets it and never adds it back. It still holds the root key.

**Handles.** `GET /v1/handle/<name>` gives the card a handle names. A
handle is 3 to 24 of `a-z 0-9 _`, a few names are reserved, and every
handle request counts against 30 a minute per address.
- Claiming takes a challenge from the handle's object, a new ES256 passkey
  (clientDataJSON and authenticatorData checked for type, challenge, origin,
  relying party and user verification) and the identity's signature over
  the handle, the card and the challenge.
- Releasing, and reading the backup, take an assertion with that passkey
  (its counter must move forward, unless it is a synced passkey reporting
  zero).
- A device of the same identity may point the handle at its own card with
  an identity signature over a fresh challenge.

**Backups.** The passkey's PRF output (salt `krypt backup prf v1`) seals the
identity's root key, its contacts' cards and the app's data. The device
keeps the PRF output and a token; it replaces the backup with the token
(`PUT …/backup`) a few seconds after people or chats change. Restoring
takes the passkey: the backup is opened on the new device, which becomes a
new device of the identity with no siblings (lost devices are not trusted
again), knows its contacts, and repoints the handle.

## Expiry

| What | When it goes |
|---|---|
| A log entry | 30 days after it was appended |
| A whole log (and its object's storage) | after 90 days with no reads or writes |
| A push registration | 30 days after it was last renewed (devices renew weekly) |
| Key packages | when they expire, or are claimed |
| A log over 4,096 entries or 64 MiB | its oldest entries, down to 15/16 of the limit |

## Mailbox deployment

- **Storage:** the mailbox's rules run over a per-log `Store` trait.
  - Tests and the simulator use `MemoryStore`.
  - Production is a Cloudflare Worker (`services/edge`) routing each frame to
    a Durable Object named by the frame's route: one object, with its own
    SQLite database, per conversation log or inbox.
- **Tables:** `entries(seq, at, hash, total, data)`, `commits(epoch, hash,
  seq)`, `blobs(id, value)` (meta, key packages, watchers, write keys) and
  `pending(id, route, entry)`. There are no secondary indexes, since each
  would add a row written per message. `total` is the running byte count, so
  the log's size comes from two rows.
- **Cost per message:** one row written. A commit writes four. Expiry runs
  from an alarm at most once a day per log, and the alarm is rewritten only
  when its time changes.
- **Strangers leave nothing:** tables are created by the first write, so
  reading a route nobody has written creates no storage.
- **Welcomes:** when a commit adds members, the welcomes become forwards.
  - They are written to the `pending` table in the same synchronous block as
    the commit.
  - The alarm delivers them to the inbox objects, retrying with backoff.
  - Delivery is idempotent, so retries are harmless.
- **API:**
  - `POST https://api.krypt.chat/v1/frame` with a request frame. The response
    body is the response frame (204 if none).
  - `GET /v1/ws/<route hex>` to subscribe (404 if the log does not exist).
- **Abuse limits:**
  - 1,200 requests per minute per IP address at the Worker, per Cloudflare
    location. The address is a counter key only and is never stored.
  - 20 requests per second per log (burst 200), across all its sockets.
  - 512 sockets per log.
  - 200 ms of CPU per invocation.
- **No request logs** (decision 20), so no IP addresses are kept.
- **Kill switch:** `just edge-kill` refuses all traffic within seconds, open
  sockets included; `just edge-unkill` restores it. Cloudflare budgets alert
  but never stop spending; this does.

## Web client

- **Where:** https://krypt.chat, served as static assets by the same Worker
  as the mailbox. App and API share one origin, so there is no CORS and the
  Content-Security-Policy allows connections only to that origin.
- **Core:** the same Rust device core, compiled to WebAssembly
  (`crates/krypt-wasm`, about 560 KB with brotli).
- **Durability:** each step's core records and the chat history it produced
  commit in one IndexedDB transaction with strict durability, before any
  request is sent or anything is shown. If storage fails, the device stops.
- **One tab:** a Web Lock keeps the device in one tab; others wait. Two tabs
  running one device could reuse encryption keys.
- **Contact links:** `https://krypt.chat/#add=krypt:…`. The card travels in
  the URL fragment, which browsers never send to any server. The card sheet
  shows the link as a QR code, so a phone's camera opens it; where the
  browser can detect barcodes, the app scans codes itself.
- **Other websites** are refused by the Worker (Origin check), since
  WebSockets ignore CORS.

## Frames

Every frame is a fixed **64-byte header** plus a bounded body. Kinds: client
to mailbox `Submit` 1, `Fetch` 2, `PublishKeyPackages` 3, `ClaimKeyPackage` 4,
`Watch` 5, `AuthorizeFile` 6, `AuthorizeTurn` 7, `Signal` 8, `OpenRequests` 9,
`JoinRequest` 10, `JoinHeader` 11; mailbox to client `Accepted` 16, `Rejected`
17, `Entries` 18, `KeyPackage` 19, `Notify` 20, `Signaled` 21, `Header` 22.


| Bytes | Field |
|---|---|
| 0–15 | BLAKE3 of the rest of the header (truncated) |
| 16–31 | BLAKE3 of the body (truncated) |
| 32–33 | magic `KR` |
| 34 | version |
| 35 | kind |
| 36–39 | body length |
| 40–47 | request id |
| 48–63 | route |

The checksums catch corruption; authenticity comes from MLS and the transport.
Bodies use a little-endian, length-prefixed codec in which every read states
its maximum. Limits are in `crates/krypt-wire/src/limits.rs`.

## Verified properties (`krypt-sim`)

| Property | Meaning |
|---|---|
| Exactly once | No device ever receives the same message twice |
| Integrity | Delivered content (text, or a file's key, name and preview) equals what was sent, attributed to the real sender |
| Agreement | Members at the same epoch have identical epoch authenticators (no forks) |
| Confinement | Message plaintext, file names and previews included, never appears in any frame or anywhere in mailbox storage |
| File access | Members up to date with the log may always store file parts; Mallory, guessing proofs at the log's real epoch, never may |
| Relay access | Members up to date with the log always get relay credentials within the allowance; Mallory never does |
| Timer agreement | Once healed, every member of a conversation has the same disappearing-message timer |
| Blocking | Nothing from a blocked identity reaches the device that blocked it |
| Rejoining | A device that deleted a conversation, or was removed, and is invited back is heard again: its numbering carries on |
| No desync | Honest devices never lose track of a conversation or fail to join |
| Eventual delivery | Once faults stop: every outbox drains, every intent commits, every member reaches the log's epoch, and every message reaches every recipient it was sealed for who is still a member |
| Hostile client | All of the above hold while "Mallory", who knows every route and sees every submission on the wire, tampers with real submissions (keeping their epoch and tag), replays them, drains inboxes' key packages and registers unproven watches |

All of these hold under 5% loss, 2% duplication, reordering, 1–5 s delays,
partitions, crashes and mid-step crashes. Runs cover 2–8 devices and chaos
phases of 30 s to 5 min.

With the membership checks disabled, Mallory breaks 126 of 500 seeds
(conversations desync or stall), which shows the simulator would catch a
regression.

## Open items (later phases)

- **Native push senders.** APNs needs the Apple Developer Program, and FCM a
  Firebase project.
- **Reading is unauthenticated.** Anyone who knows a route can fetch or
  subscribe to its ciphertext and see when it changes. Routes are random
  128-bit values shared only with members.
- **One socket per log** is cheapest per message (requests over a socket cost
  a twentieth of an HTTP request, and pushes are free), but a device with many
  conversations holds many sockets. If that becomes a problem, a per-device
  object can multiplex them.
- **Rotating mailbox ids derived from the MLS exporter,** for metadata
  privacy.
- **Post-quantum signatures** (ML-DSA), when a quantum computer able to
  forge Ed25519 in real time looks near.
