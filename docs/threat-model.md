# Threat model

What krypt protects, from whom, and where it stops. Every claim below points
at the mechanism that enforces it and the test that checks it; where there is
no mechanism, it says so. Read with [protocol.md](protocol.md) and
[decisions.md](decisions.md).

## What is protected

| Asset | Protection |
|---|---|
| Message text, files, call media | End to end: MLS (post-quantum X-Wing for key exchange, Ed25519 signatures) for messages and file keys; ChaCha20-Poly1305 per file part; DTLS-SRTP for calls, keyed through fingerprints delivered inside MLS |
| Who is talking to whom | Partly. The mailbox sees which routes (random 128-bit ids) a device reads and writes, from which address, and when. It never sees identities, names or cards |
| A person's identity | An Ed25519 root key that stays on the person's devices, leaving only sealed: to a device being linked (X-Wing + ChaCha20-Poly1305 through one-time drops, keyed in part by a secret that travels only in the link code) or in a passkey-sealed backup |
| Photo and video metadata | Removed on the sender's device before encryption; media that cannot be cleaned is refused |
| IP addresses | Messages never go device to device. Calls are direct by default (each side learns the other's address); "Always relay calls" hides it behind Cloudflare TURN. A message request cannot ring, so a stranger cannot learn an address by calling |

## Adversaries

### The network (anyone on the path)
Sees TLS to Cloudflare, and for calls, DTLS-SRTP between devices or to the
relay. Learns timing and sizes; message lengths are padded to 32 bytes. Cannot
read, alter or inject anything: MLS authenticates every message, and calls are
keyed through MLS.

### Cloudflare, or someone controlling the mailbox
The mailbox is the one piece of shared infrastructure, so it is the strongest
adversary that is always present.
- **Serves the web app.** The same Worker serves krypt.chat's code. Releases
  are built in public, signed with a key on a YubiKey, and pinned in the
  browser by a service worker that runs only signed releases and warns when
  served anything else; an hourly monitor checks what krypt.chat serves
  ([releases.md](releases.md)). What remains: the first visit trusts the
  server, and the server can replace the service worker itself (browsers
  fetch it again daily); a pinned device then warns, but the replacement is
  installed. So whoever controls Cloudflare, the account or the deploy token
  can still target someone with a modified app, but not change it for
  everyone unnoticed. Everything below is about the protocol, against a
  mailbox that serves the genuine app.
- **Cannot** read messages, file contents, file names, previews, call
  signaling or call media; cannot forge or alter messages; cannot add a member
  to a group (commits are signed by members, and every leaf carries a device
  certificate signed by its identity, checked on every add).
- **Can** see routes, sizes, timing and client addresses; drop, delay or
  reorder traffic (devices detect gaps and retry; the simulator checks
  exactly-once, in-order delivery after faults); refuse service; keep
  ciphertext past its retention. With no past epochs kept on devices, keys
  for old messages are gone, so stored ciphertext stays unreadable.
- **Directory:** maps handles to cards. It could hand out a wrong card for a
  handle. A safety-number check catches that: the fingerprint and safety
  numbers are computed from the identity key, not from anything the directory
  says. Handles are a convenience, not a root of trust.
- **Reports** are the one place plaintext reaches the server, and only what a
  reporter chose to send about someone else's messages.
- **Quiet messages:** read receipts, edits and reactions taken back are
  marked quiet in plaintext (so they wake nobody). With their size and
  timing, the mailbox can tell roughly when someone reads.
- **Invite links:** it sees that a group has a requests log, who asks (by
  address) and when, and, from sockets and addresses, which devices read it
  (the admins). It never sees the link, names, cards, or the group's name.
- **Can drop one message** without anyone noticing: devices detect gaps in
  the log, not a missing number in one sender's sequence, and a later read
  receipt (a watermark) then covers it as read.
- **Typing and online signals** are relayed, never stored, and sealed with a
  key it does not have. It sees that a signal was sent on a route, and when,
  as it already sees a device's socket activity. It could withhold or delay
  them; it cannot forge, alter or (beyond two minutes) replay one.

Checked by: `krypt-sim` (confinement: no plaintext, file name or preview
marker ever appears in any frame or in mailbox storage; agreement; eventual
delivery under faults), the mailbox's membership checks (`Mailbox::submit`,
`current_member`), and the browser test checking stored photos have no
metadata.

### A malicious member (or a removed one, "Mallory")
A member can read the conversation; that is what membership means. Mallory
in the simulator knows every route, sees every submission on the wire,
replays and tampers with real submissions (keeping epoch and tag), drains key
packages, registers unproven watches, and asks for file storage and relay
credentials without proof. None of it gets her a write, a file stored, a relay
credential or a desynced honest member. With the checks disabled she breaks
about a quarter of seeds, so the simulator would notice a regression.

Mallory as a *member* (holding the group's keys) is stronger: she can stop a
group for everyone, by committing something honest members refuse (a bogus
key for the mailbox, a commit that does not process, or one against the
group's rules). That is a denial of service only; she cannot read or forge
anything beyond what membership gives her. Groups have admins (decision 51):
every member checks every commit against the rules before merging it, and a
commit that breaks them (an add by a non-admin where only admins may add, a
rename or rules change by a non-admin, an admin removed by a non-admin, a
group left without an admin) stops the group for every honest member, so
whoever was added against the rules never reads a message, and nobody takes
a group over by removing its admins. An admin who leaves steps down first,
handing the role on if nobody else has it. Every commit is also checked to
keep each member's certificate and key (nobody becomes someone else by
updating) and every device id unique in the group; a device checks its own
commits the same way before sending them.

A member can commit a malformed timer (read as off). Who may add people, and
rename the group or change its timer, is up to its admins; only admins
remove admins, and removals of others are admin-only in the app; others see
who joined, who left, and who removed whom. Every member has the invite
link's secret: a member, or one removed later, can read who asks to join and
disturb the requests log, so removing someone resets the link. A member also learns when the others are typing and when
they have krypt open on screen (decision 47), unless they turn that off in
Settings → Privacy; a member cannot claim another's typing or presence, since
each signal is signed by the device it names. Message requests never get
these signals, so a stranger cannot watch when someone is active. A member can spend the conversation's daily file allowance
(1 GiB) or relay allowance (64 credentials).

### A stranger
Can start a conversation with anyone whose card or handle they know. It
arrives as a message request: listed apart, unable to ring, and nothing tells
the stranger it was seen. A group is a request unless whoever added this
device is someone it knows (adding a contact of theirs alongside changes
nothing). Blocking drops the conversation and every future invitation and
message from that identity, silently. Past 1,024 conversations nobody here
answered, invitations from strangers are dropped, so a flood of them cannot
crowd out real ones.

With a group's invite link, a stranger can read the group's name and ask to
join; an admin decides. They cannot ask in someone else's name (requests are
signed by the asking device), read other requests (sealed to the group's
key), or take over the requests log (it belongs to a key derived from the
link's secret, which they do not have, and the mailbox checks the log's
route is that key's), or have a request approved into another group with the
same secret (a link belongs to one group). Requests carry a signed time and
are never shown twice. They can fill the log (512 requests) until an admin
resets the link; junk hides no later request.

### A thief with an unlocked device, or malware on it
Has everything that device has: keys, history, the identity's root key.
Defences are limited to what the platform offers:
- The data sits in the browser profile like any site's data (krypt is a
  web app only).
- "Burn this identity" destroys everything on the device.
- From another device, the stolen one can be unlinked (removed from every
  conversation; every other device of the identity learns of it from the
  commit and never adds it back). It still holds the root key: it can start
  new conversations as the identity until the identity is burned and
  replaced. There is no revocation of a root key short of that.
- Burning also removes the browser's push subscription and service worker,
  so a later identity in the same browser shares no push endpoint with it.

Not done: wrapping the local database in a key from a platform keystore. In
a browser such a key would sit in the same profile as the data, so it would
not help. Decision 41.

### Someone who obtains a passkey
A synced passkey (iCloud Keychain, Google Password Manager) is as strong as
the account it syncs with. Whoever can use it can read the backup (the
identity's root key and contacts) and release the handle. They cannot read
past messages: a backup holds no conversation keys or history.

### A quantum computer, later
Key exchange is hybrid post-quantum (X-Wing: ML-KEM-768 + X25519), so traffic
recorded today stays protected. Signatures are Ed25519: forging one needs a
quantum computer at the time, not afterwards. File keys travel inside MLS.
Link seals use X-Wing too (decision 48), and backups a passkey's PRF output
(symmetric), so neither can be opened later by a quantum computer.

Linking also holds against the server: the drops' addresses come from a
secret that is only in the link code (a QR code or pasted text), so the
server cannot seal a payload of its own to the new device's key, and the code
carries a hash of that key, so the server cannot swap it either. Someone who
photographs the code and races the existing device could seal *their* own
identity to it: the new device shows the fingerprint of the identity it is
joining, to be checked against the other device's, before it joins. Each
drop is written once and read once.

## Abuse and cost

Everything that costs money has a per-address and a per-conversation bound,
and a kill switch (`just edge-kill`) stops all traffic, queued deliveries
included, within seconds. An address is an IPv4 address or an IPv6 /64.

| Resource | Bound |
|---|---|
| Requests | 1,200 a minute per address, through the Worker and over sockets alike; 20 a second per log (burst 200) |
| New logs | 20 a minute per address (a conversation's first commit, a requests log opened) |
| Sockets | 512 per log, 16 of them from one address |
| Invitations | 8 an hour from one conversation to one inbox, 512 inboxes an hour |
| File storage | 32 parts a minute per address; 1 GiB per conversation per day; deleted after 30 days |
| TURN relay | 10 credentials a minute per address; 64 per conversation per day; 1-hour credentials |
| Handles | 30 requests a minute per address |
| Drops | 60 a minute per address; one payload, read once, 10 minutes |
| Reports | 4 a minute per address; JSON objects only; kept 90 days |

Anyone can make a conversation log (it needs no account), so the
per-conversation bounds limit a member, not a stranger with many logs: the
per-address limits are what hold those. A relay credential lets its holder
relay any traffic, billed by the gigabyte, until it expires. A Cloudflare
billing alert is the backstop; there is no global daily budget that trips
the kill switch by itself.

## Supply chain

Crates come only from crates.io, at exact versions, checked by `cargo deny`
(licenses, bans, sources in `nix flake check`; advisories in `just audit`)
and `cargo vet`. Vetting covers little that matters yet: 82 small crates are
audited (by Mozilla, Google, the Bytecode Alliance, ZCash, ISRG or Embark);
the 298 exempted include every security-critical one (OpenMLS, the HPKE and
libcrux crates, X-Wing, ML-KEM, the dalek crates, ChaCha20-Poly1305, BLAKE3,
wasm-bindgen, the Worker runtime, serde). The web client pins exact npm
versions and installs with a frozen lockfile; `just audit` covers all of
them, build tools included. One advisory is accepted with reasoning
(RUSTSEC-2026-0387, see `deny.toml`).

Builds run from a pinned Nix flake, with one gap: building the Worker,
worker-build downloads esbuild from npm (wasm-bindgen and wasm-opt come from
the flake). A deploy builds everything first, with no secrets in reach, then
decrypts the token only to upload; it refuses an uncommitted tree and tags
the Worker version with the commit. The deploy token can still change the
code every browser runs (see the Cloudflare section).

## Testing the claims

- **Deterministic simulation** (`krypt-sim`): crashes (including mid-step),
  torn writes, loss, duplication, reordering, partitions and Mallory; 10,000
  seeds per run, each replayable.
- **Fuzzing** (`just fuzz`): every wire decoder (and that it re-encodes to
  its input), the metadata scrubber, the mailbox fed request scripts, and a
  device fed hostile frames and damaged storage. The first runs found three
  crashes on damaged storage, now fixed with regression tests.
- **Browser end to end** (`apps/web/e2e/chat.mjs`), locally and against
  krypt.chat: messaging, files and their metadata, calls, requests, blocking,
  reports, disappearing messages, linked devices, handles and passkey restore.

## Before going public

- An external audit of the protocol and the core (an internal one was done
  on 2026-11-07; see decision 53).
- Audits (or imported ones) for the critical crates `cargo vet` exempts.
- The open items in [protocol.md](protocol.md): rotating mailbox ids,
  post-quantum signatures.
- A license (AGPL-3.0 recommended).
