//! A deterministic simulator for krypt, in the spirit of TigerBeetle's VOPR.
//!
//! One seed fixes everything the simulator decides: the workload, network
//! latency, drops, duplicates and partitions, and when devices crash. Clients
//! and the mailbox are the real state machines from `krypt-core`; only the
//! network, the disk and the clock are simulated. Invariants are checked as
//! the run goes and again once the faults stop and the system heals.
//!
//! MLS ciphertext bytes vary between runs (OpenMLS draws HPKE randomness from
//! the OS), but no decision depends on them, so a seed always replays the
//! same trace. [`Report::trace`] fingerprints that trace to prove it.

use std::collections::{BTreeMap, BTreeSet, BinaryHeap, VecDeque};

use krypt_core::client::{
    Call, Client, Config as ClientConfig, Content, Effect, Event, Policy, SharedFile, Step, Who,
};
use krypt_core::identity::{ContactCard, DeviceId, IdentityKey};
use krypt_core::mailbox::{Forward, LocalMailbox};
use krypt_core::provider::Rand;
use krypt_wire::Route;
use krypt_wire::frame::{self, Kind};
use krypt_wire::msg::{
    CallEnd, CallKind, FilePart, MessageRef, Platform, PushTarget, Reject, Rejected, SignalKind,
    Submit, TurnGrant, Watch,
};
use rand_chacha::ChaCha8Rng;
use rand_core::{RngCore, SeedableRng};

/// Simulation clock granularity.
const TICK_MS: u64 = 10;
/// How often each client's `tick` runs (plus jitter).
const CLIENT_TICK_MS: u64 = 50;
/// Every message text contains this; it must never appear on the wire.
const LEAK_MARKER: &[u8] = b"KRYPTLEAK";
const CONVERSATIONS_MAX: usize = 6;

#[derive(Clone, Copy, Debug)]
pub struct Options {
    pub clients: usize,
    /// Length of the phase with workload and faults.
    pub chaos_ms: u64,
    /// Longest the system may take to converge once faults stop.
    pub heal_ms: u64,
    pub network_faults: bool,
    pub crashes: bool,
    /// How often clients poll. Push (`Notify`) normally makes polling a
    /// safety net; long intervals check that missed pushes are recovered.
    pub poll_ms: u64,
    /// Run Mallory: a hostile client that forges, replays and drains.
    pub attacker: bool,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            clients: 4,
            chaos_ms: 30_000,
            heal_ms: 120_000,
            network_faults: true,
            crashes: true,
            poll_ms: 250,
            attacker: true,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub sim_ms: u64,
    pub messages_sent: u64,
    pub deliveries: u64,
    pub conversations: usize,
    pub max_epoch: u64,
    pub crashes: u64,
    pub crashes_mid_step: u64,
    pub partitions: u64,
    pub frames: u64,
    pub frames_dropped: u64,
    /// Push wakeups the mailbox asked for (after coalescing).
    pub wakeups: u64,
    /// Mallory's requests, and how many the mailbox refused as forbidden.
    pub attacks: u64,
    pub attacks_forbidden: u64,
    /// File parts honest members were allowed to store.
    pub files_authorized: u64,
    /// Call relay credentials honest members were allowed.
    pub turn_grants: u64,
    /// Signals (typing, online) sent, and shown to another member.
    pub signals_sent: u64,
    pub signals_shown: u64,
    /// Disappearing-message timer changes committed.
    pub timer_changes: u64,
    /// Changes to a group's rules seen, and changes a device did not make
    /// because the rules forbid them.
    pub rule_changes: u64,
    pub refusals: u64,
    /// Conversations a device deleted, and identities blocked.
    pub forgotten: u64,
    pub blocks: u64,
    /// BLAKE3 of the logical event trace. Equal for equal seeds.
    pub trace: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Violation {
    pub seed: u64,
    pub at_ms: u64,
    pub what: String,
}

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "seed {} at {} ms: {}", self.seed, self.at_ms, self.what)
    }
}

/// A device's disk: whatever was durably written, nothing more.
#[derive(Default)]
struct Disk {
    kv: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl Disk {
    fn apply(&mut self, writes: Vec<(Vec<u8>, Option<Vec<u8>>)>) {
        for (key, value) in writes {
            match value {
                Some(value) => self.kv.insert(key, value),
                None => self.kv.remove(&key),
            };
        }
    }
}

struct Node {
    client: Option<Client>,
    disk: Disk,
    device: DeviceId,
    identity: IdentityKey,
    contact: ContactCard,
    /// While crashed: when the device comes back.
    down_until: Option<u64>,
    partitioned_until: u64,
    next_tick: u64,
    restarts: u64,
    /// Conversations this device deleted (nobody invites it back to them).
    /// A device removed by others may be invited back, and rejoins.
    removed: BTreeSet<Route>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Target {
    Mailbox {
        from: usize,
    },
    /// A welcome the mailbox forwards to another log (the frame is the entry).
    Forward {
        route: Route,
    },
    /// A request from Mallory; responses are only counted.
    Attacker,
    Node {
        to: usize,
    },
}

#[derive(PartialEq, Eq)]
struct InFlight {
    at: u64,
    order: u64,
    target: Target,
    frame: Vec<u8>,
}

impl Ord for InFlight {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Min-heap on (at, order).
        (other.at, other.order).cmp(&(self.at, self.order))
    }
}

impl PartialOrd for InFlight {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

type MessageId = (Route, DeviceId, u64);

#[derive(Default)]
struct Oracle {
    sent: BTreeMap<MessageId, (usize, Content)>,
    /// Members each message must reach: the intersection over every time it
    /// was sealed (it is re-sealed if it had to be re-encrypted), and the
    /// epoch of the last sealing, the copy the log keeps.
    sealed: BTreeMap<MessageId, (BTreeSet<IdentityKey>, u64)>,
    /// The epoch each device's membership of a conversation began at. A
    /// device can join a conversation only once.
    joined: BTreeMap<(usize, Route), u64>,
    delivered: BTreeSet<(usize, MessageId)>,
    /// Messages the mailbox acknowledged storing.
    stored: BTreeSet<MessageId>,
    /// Who blocked whom: nothing from a blocked identity may reach them.
    blocked: BTreeSet<(usize, IdentityKey)>,
    /// Signals sent: by conversation, sending device and kind.
    signals: BTreeSet<(Route, DeviceId, SignalKind)>,
    epochs: BTreeMap<(Route, u64), Vec<u8>>,
    undecryptable: Vec<(usize, Route, u64, String)>,
}

struct Sim {
    seed: u64,
    options: Options,
    rng: ChaCha8Rng,
    now: u64,
    mailbox: LocalMailbox,
    nodes: Vec<Node>,
    network: BinaryHeap<InFlight>,
    next_order: u64,
    oracle: Oracle,
    trace: blake3::Hasher,
    report: Report,
    violation: Option<Violation>,
    text_counter: u64,
    /// Submissions Mallory has seen on the wire, to tamper with and replay.
    captured: VecDeque<Vec<u8>>,
}

/// How many observed submissions Mallory remembers.
const CAPTURED_MAX: usize = 512;

/// A push endpoint for node `i`.
fn push_address(i: usize) -> Vec<u8> {
    format!("https://fcm.googleapis.com/fcm/send/node-{i}").into_bytes()
}

fn client_config(options: &Options) -> ClientConfig {
    ClientConfig {
        request_timeout_ms: 1_000,
        poll_interval_ms: options.poll_ms,
        key_packages: 4,
        break_rules: false,
    }
}

fn node_seed(seed: u64, node: usize, incarnation: u64) -> u64 {
    let hash = blake3::Hasher::new()
        .update(&seed.to_le_bytes())
        .update(&(node as u64).to_le_bytes())
        .update(&incarnation.to_le_bytes())
        .finalize();
    u64::from_le_bytes(hash.as_bytes()[..8].try_into().expect("8 bytes"))
}

/// Runs one seed to completion.
pub fn run(seed: u64, options: Options) -> Result<Report, Violation> {
    assert!(options.clients >= 2, "a conversation needs two devices");
    let mut sim = Sim {
        seed,
        options,
        rng: ChaCha8Rng::seed_from_u64(seed),
        now: 0,
        mailbox: LocalMailbox::new(),
        nodes: Vec::new(),
        network: BinaryHeap::new(),
        next_order: 0,
        oracle: Oracle::default(),
        trace: blake3::Hasher::new(),
        report: Report::default(),
        violation: None,
        text_counter: 0,
        captured: VecDeque::new(),
    };
    sim.setup();
    sim.run_phases();
    match sim.violation {
        Some(violation) => Err(violation),
        None => {
            sim.report.sim_ms = sim.now;
            sim.report.trace = *sim.trace.finalize().as_bytes();
            Ok(sim.report)
        }
    }
}

impl Sim {
    fn chance(&mut self, p: f64) -> bool {
        (self.rng.next_u64() >> 11) as f64 / (1u64 << 53) as f64 <= p
    }

    fn below(&mut self, n: u64) -> u64 {
        assert!(n > 0);
        self.rng.next_u64() % n
    }

    fn between(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.below(hi - lo + 1)
    }

    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        let i = self.below(items.len() as u64);
        items[usize::try_from(i).expect("index fits")]
    }

    fn fail(&mut self, what: String) {
        if self.violation.is_none() {
            self.violation = Some(Violation {
                seed: self.seed,
                at_ms: self.now,
                what,
            });
        }
    }

    fn trace(&mut self, node: usize, what: &str) {
        if std::env::var_os("KRYPT_SIM_VERBOSE").is_some() {
            eprintln!("{:>7} n{node} {what}", self.now);
        }
        self.trace.update(&self.now.to_le_bytes());
        self.trace.update(&(node as u64).to_le_bytes());
        self.trace.update(what.as_bytes());
    }

    fn chaos(&self) -> bool {
        self.now < self.options.chaos_ms
    }

    fn setup(&mut self) {
        for i in 0..self.options.clients {
            let rand = Rand::seeded(node_seed(self.seed, i, 0));
            let (client, step) = Client::create(client_config(&self.options), rand, self.now);
            let contact = client.contact_card();
            let next_tick = self.now + self.below(CLIENT_TICK_MS);
            self.nodes.push(Node {
                identity: client.identity(),
                device: client.device(),
                contact,
                client: Some(client),
                disk: Disk::default(),
                down_until: None,
                partitioned_until: 0,
                next_tick,
                restarts: 0,
                removed: BTreeSet::new(),
            });
            self.apply(i, step, None);
            // Half the devices want waking when they are not connected.
            if i % 2 == 0 {
                let address = push_address(i);
                let target = PushTarget {
                    platform: Platform::WebPush,
                    address: &address,
                };
                let now = self.now;
                let client = self.nodes[i].client.as_mut().expect("just created");
                let step = client.set_push_target(now, Some(target));
                self.apply(i, step, None);
            }
        }
        // Everyone starts in one conversation together.
        let contact = self.nodes[1].contact;
        let client = self.nodes[0].client.as_mut().expect("just created");
        let (id, step) = client
            .start_conversation(self.now, contact)
            .expect("first conversation");
        self.apply(0, step, None);
        for other in 2..self.options.clients {
            let contact = self.nodes[other].contact;
            let client = self.nodes[0].client.as_mut().expect("up");
            let step = client.invite(self.now, id, contact).expect("invite");
            self.apply(0, step, None);
        }
    }

    fn run_phases(&mut self) {
        let end = self.options.chaos_ms + self.options.heal_ms;
        while self.now < end && self.violation.is_none() {
            self.deliver_due();
            self.restart_due();
            self.tick_clients();
            if self.chaos() {
                self.workload();
                self.inject_faults();
                if self.options.attacker && self.chance(0.05) {
                    self.attack();
                }
            } else if self.now == self.options.chaos_ms {
                self.heal();
            }
            self.check_agreement();
            if !self.chaos() && self.now.is_multiple_of(1_000) && self.converged().is_ok() {
                break;
            }
            self.now += TICK_MS;
        }
        if self.violation.is_none() {
            if let Err(what) = self.converged() {
                self.fail(format!(
                    "did not converge within {} ms of healing: {what}",
                    self.options.heal_ms
                ));
            }
            self.check_mailbox_for_leaks();
        }
        self.report.max_epoch = self
            .oracle
            .epochs
            .keys()
            .map(|(_, epoch)| *epoch)
            .max()
            .unwrap_or(0);
        self.report.conversations = self
            .oracle
            .epochs
            .keys()
            .map(|(conv, _)| *conv)
            .collect::<BTreeSet<_>>()
            .len();
    }

    // ---- Network ---------------------------------------------------------

    fn latency(&mut self) -> u64 {
        if !self.chaos() || !self.options.network_faults {
            return self.between(1, 30);
        }
        if self.chance(0.02) {
            self.between(1_000, 5_000)
        } else {
            self.between(1, 150)
        }
    }

    fn partitioned(&self, node: usize) -> bool {
        self.nodes[node].partitioned_until > self.now
    }

    fn send(&mut self, from: Option<usize>, target: Target, frame: Vec<u8>) {
        self.report.frames += 1;
        if matches!(target, Target::Mailbox { .. })
            && frame::decode(&frame).is_ok_and(|f| f.kind == Kind::Submit)
        {
            if self.captured.len() == CAPTURED_MAX {
                self.captured.pop_front();
            }
            self.captured.push_back(frame.clone());
        }
        if frame.windows(LEAK_MARKER.len()).any(|w| w == LEAK_MARKER) {
            self.fail(format!("plaintext on the wire from {from:?}"));
            return;
        }
        let to = match target {
            Target::Mailbox { .. } | Target::Forward { .. } | Target::Attacker => None,
            Target::Node { to, .. } => Some(to),
        };
        let cut =
            from.is_some_and(|n| self.partitioned(n)) || to.is_some_and(|n| self.partitioned(n));
        let faulty = self.chaos() && self.options.network_faults;
        if cut || (faulty && self.chance(0.05)) {
            self.report.frames_dropped += 1;
            return;
        }
        let copies = if faulty && self.chance(0.02) { 2 } else { 1 };
        for _ in 0..copies {
            let at = self.now + self.latency();
            let order = self.next_order;
            self.next_order += 1;
            self.network.push(InFlight {
                at,
                order,
                target,
                frame: frame.clone(),
            });
        }
    }

    /// Schedules a forwarded welcome. In production it crosses from one
    /// Durable Object to another and is retried until it lands, so it is
    /// delayed, sometimes duplicated, but never lost.
    fn forward(&mut self, forward: Forward) {
        let copies = if self.chaos() && self.options.network_faults && self.chance(0.05) {
            2
        } else {
            1
        };
        for _ in 0..copies {
            let at = self.now + self.latency();
            let order = self.next_order;
            self.next_order += 1;
            self.network.push(InFlight {
                at,
                order,
                target: Target::Forward {
                    route: forward.route,
                },
                frame: forward.entry.clone(),
            });
        }
    }

    /// Mallory knows every route and has every submission seen on the wire
    /// (a removed member, or anyone who learned addresses). She tampers with
    /// real submissions while keeping their epoch and tag, replays them,
    /// drains inboxes' key packages and registers watches she cannot prove.
    fn attack(&mut self) {
        self.report.attacks += 1;
        let roll = self.below(100);
        let request = if roll < 70 && !self.captured.is_empty() {
            let i = usize::try_from(self.below(self.captured.len() as u64)).expect("fits");
            let original = self.captured[i].clone();
            if roll < 50 {
                Self::tamper(&original, self.rng.next_u64())
            } else {
                Some(original)
            }
        } else if roll < 80 {
            let victim = self.pick(&(0..self.nodes.len()).collect::<Vec<_>>());
            let inbox = self.nodes[victim].contact.inbox;
            Some(frame::encode_vec(
                Kind::ClaimKeyPackage,
                self.rng.next_u64(),
                inbox,
                &[],
            ))
        } else if roll < 85 && !self.captured.is_empty() {
            // Relay credentials without proof, at the log's real epoch.
            let i = usize::try_from(self.below(self.captured.len() as u64)).expect("fits");
            let route = frame::decode(&self.captured[i])
                .expect("captured frames decode")
                .route;
            let grant = TurnGrant {
                epoch: self.mailbox.epoch(&route).unwrap_or(0),
                auth: self
                    .rng
                    .next_u64()
                    .to_le_bytes()
                    .repeat(2)
                    .try_into()
                    .expect("16"),
            };
            Some(frame::encode_vec(
                Kind::AuthorizeTurn,
                self.rng.next_u64(),
                route,
                &grant.encode(),
            ))
        } else if roll < 90 && !self.captured.is_empty() {
            // Storing files without proof, at the log's real epoch.
            let i = usize::try_from(self.below(self.captured.len() as u64)).expect("fits");
            let route = frame::decode(&self.captured[i])
                .expect("captured frames decode")
                .route;
            let epoch = self.mailbox.epoch(&route).unwrap_or(0);
            let part = FilePart {
                file: self
                    .rng
                    .next_u64()
                    .to_le_bytes()
                    .repeat(2)
                    .try_into()
                    .expect("16"),
                part: 0,
                len: 1024,
                epoch,
                auth: self
                    .rng
                    .next_u64()
                    .to_le_bytes()
                    .repeat(2)
                    .try_into()
                    .expect("16"),
            };
            Some(frame::encode_vec(
                Kind::AuthorizeFile,
                self.rng.next_u64(),
                route,
                &part.encode(),
            ))
        } else if !self.captured.is_empty() {
            let i = usize::try_from(self.below(self.captured.len() as u64)).expect("fits");
            let route = frame::decode(&self.captured[i])
                .expect("captured frames decode")
                .route;
            let target = PushTarget {
                platform: Platform::WebPush,
                address: b"https://mallory.example/",
            };
            let watch = Watch {
                enable: true,
                target,
                proof: &[0xEE; 16],
            }
            .encode();
            Some(frame::encode_vec(
                Kind::Watch,
                self.rng.next_u64(),
                route,
                &watch,
            ))
        } else {
            None
        };
        if let Some(request) = request {
            self.send(None, Target::Attacker, request);
        }
    }

    /// The same submission with one byte of its MLS ciphertext changed: same
    /// route, same epoch header, same welcomes and tag.
    fn tamper(original: &[u8], noise: u64) -> Option<Vec<u8>> {
        let frame = frame::decode(original).ok()?;
        let submit = Submit::decode(frame.body).ok()?;
        let mut message = submit.message.to_vec();
        let at = message.len() - 1 - usize::try_from(noise % 16).expect("small");
        message[at] ^= 0x5A;
        let forged = Submit {
            message: &message,
            welcomes: submit.welcomes,
            auth: submit.auth,
            next_key: submit.next_key,
            creation: submit.creation,
            quiet: submit.quiet,
        };
        Some(frame::encode_vec(
            Kind::Submit,
            noise,
            frame.route,
            &forged.encode(),
        ))
    }

    /// Pushes a `Notify` to every device following the route, as the
    /// mailbox does over WebSockets. Pushes travel the same faulty network.
    fn notify(&mut self, route: Route, frame: Vec<u8>) {
        for to in 0..self.nodes.len() {
            let follows = self.nodes[to]
                .client
                .as_ref()
                .is_some_and(|c| c.routes().contains(&route));
            if follows {
                self.send(None, Target::Node { to }, frame.clone());
            }
        }
    }

    fn deliver_due(&mut self) {
        while self.network.peek().is_some_and(|f| f.at <= self.now) && self.violation.is_none() {
            let InFlight { target, frame, .. } = self.network.pop().expect("peeked");
            match target {
                Target::Mailbox { from } => {
                    let Some((route, handled)) = self.mailbox.handle_request(self.now, &frame)
                    else {
                        continue;
                    };
                    self.report.wakeups += handled.wakeups.len() as u64;
                    if let Some(notify) = handled.notify {
                        self.notify(route, notify);
                    }
                    if let Some(response) = handled.response {
                        self.send(None, Target::Node { to: from }, response);
                    }
                    for forward in handled.forwards {
                        self.forward(forward);
                    }
                }
                Target::Attacker => {
                    let Some((_, handled)) = self.mailbox.handle_request(self.now, &frame) else {
                        continue;
                    };
                    let kind = frame::decode(&frame).expect("decoded").kind;
                    let accepted = handled
                        .response
                        .as_deref()
                        .and_then(|r| frame::decode(r).ok())
                        .is_some_and(|f| f.kind == Kind::Accepted);
                    if kind == Kind::AuthorizeFile && accepted {
                        self.fail("the mailbox let a non-member store a file".to_owned());
                    }
                    if kind == Kind::AuthorizeTurn && accepted {
                        self.fail("the mailbox gave a non-member relay credentials".to_owned());
                    }
                    let refused = handled
                        .response
                        .as_deref()
                        .and_then(|r| frame::decode(r).ok())
                        .is_some_and(|f| {
                            f.kind == Kind::Rejected
                                && Rejected::decode(f.body)
                                    .is_ok_and(|r| r.reason == Reject::Forbidden)
                        });
                    self.report.attacks_forbidden += u64::from(refused);
                    // Anything Mallory gets accepted still pushes to members.
                    self.report.wakeups += handled.wakeups.len() as u64;
                    if let Some((route, notify)) = handled
                        .notify
                        .map(|n| (frame::decode(&frame).expect("decoded").route, n))
                    {
                        self.notify(route, notify);
                    }
                }
                Target::Forward { route } => {
                    let forward = Forward {
                        route,
                        entry: frame,
                    };
                    let delivered = self.mailbox.deliver(self.now, &forward);
                    self.report.wakeups += delivered.wakeups.len() as u64;
                    if let Some(notify) = delivered.notify {
                        self.notify(route, notify);
                    }
                }
                Target::Node { to } => {
                    if self.partitioned(to) {
                        self.report.frames_dropped += 1;
                        continue;
                    }
                    let now = self.now;
                    let Some(client) = self.nodes[to].client.as_mut() else {
                        self.report.frames_dropped += 1;
                        continue;
                    };
                    let step = client.receive(now, &frame);
                    self.apply(to, step, None);
                }
            }
        }
    }

    // ---- Steps -----------------------------------------------------------

    /// Persists a step, then performs its effects. A crash in between loses
    /// both, exactly as a real device would.
    fn apply(&mut self, node: usize, step: Step, sent: Option<(Route, u64, Content)>) {
        // Setup (time zero) is not part of the chaos.
        if self.now > 0 && self.chaos() && self.options.crashes && self.chance(0.001) {
            self.report.crashes_mid_step += 1;
            self.crash(node);
            return;
        }
        self.nodes[node].disk.apply(step.writes);
        if let Some((conversation, seq, content)) = sent {
            self.report.messages_sent += 1;
            let id = (conversation, self.nodes[node].device, seq);
            if self.oracle.sent.insert(id, (node, content)).is_some() {
                self.fail(format!("node {node} reused sender_seq {seq}"));
            }
        }
        for effect in step.effects {
            match effect {
                Effect::Mailbox(frame) => {
                    self.send(Some(node), Target::Mailbox { from: node }, frame)
                }
                Effect::Event(event) => self.observe(node, event),
            }
        }
    }

    fn observe(&mut self, node: usize, event: Event) {
        self.trace(node, &format!("{event:?}"));
        match event {
            Event::Message {
                conversation,
                from,
                device,
                sender_seq,
                content,
                ..
            } => {
                self.report.deliveries += 1;
                let id = (conversation, device, sender_seq);
                match self.oracle.sent.get(&id) {
                    None => self.fail(format!(
                        "node {node} received a message nobody sent: {id:?}"
                    )),
                    Some((sender, sent)) => {
                        if self.oracle.blocked.contains(&(node, from)) {
                            self.fail(format!(
                                "node {node} received {id:?} from someone it blocked"
                            ));
                        } else if *sent != content {
                            self.fail(format!("node {node} received altered content for {id:?}"));
                        } else if self.nodes[*sender].identity != from || *sender == node {
                            self.fail(format!(
                                "node {node} received {id:?} attributed to the wrong sender"
                            ));
                        }
                    }
                }
                if !self.oracle.delivered.insert((node, id)) {
                    self.fail(format!("node {node} received {id:?} twice"));
                }
            }
            Event::Sealed {
                conversation,
                sender_seq,
                recipients,
                epoch,
            } => {
                let id = (conversation, self.nodes[node].device, sender_seq);
                let recipients: BTreeSet<_> = recipients.into_iter().collect();
                self.oracle
                    .sealed
                    .entry(id)
                    .and_modify(|(r, last)| {
                        r.retain(|identity| recipients.contains(identity));
                        *last = epoch;
                    })
                    .or_insert((recipients, epoch));
            }
            Event::Started { conversation } => {
                self.oracle.joined.insert((node, conversation), 0);
            }
            // Signals may be lost, but one shown must be one its member sent,
            // to someone else, who has not blocked them.
            Event::Signal {
                conversation,
                from,
                device,
                kind,
            } => {
                self.report.signals_shown += 1;
                let sender = self.nodes.iter().position(|n| n.device == device);
                if !self.oracle.signals.contains(&(conversation, device, kind)) {
                    self.fail(format!(
                        "node {node} was shown a signal nobody sent: {kind:?}"
                    ));
                } else if sender == Some(node)
                    || sender.is_none_or(|s| self.nodes[s].identity != from)
                {
                    self.fail(format!(
                        "node {node} was shown a signal from the wrong sender"
                    ));
                } else if self.oracle.blocked.contains(&(node, from)) {
                    self.fail(format!(
                        "node {node} was shown a signal from someone it blocked"
                    ));
                }
            }
            Event::Joined {
                conversation,
                epoch,
                ..
            } => {
                if self
                    .oracle
                    .joined
                    .insert((node, conversation), epoch)
                    .is_some()
                {
                    self.fail(format!("node {node} joined {conversation:02x?} twice"));
                }
            }
            Event::Undecryptable {
                conversation,
                reason,
            } => {
                if reason.starts_with("welcome") {
                    self.fail(format!(
                        "node {node} could not join {conversation:02x?}: {reason}"
                    ));
                }
                self.oracle
                    .undecryptable
                    .push((node, conversation, self.now, reason));
            }
            Event::Removed { conversation } => {
                // Invited back, it joins again as a new member.
                self.oracle.joined.remove(&(node, conversation));
                self.drop_unsent(node, conversation);
            }
            Event::Desync {
                conversation,
                reason,
            } => {
                self.fail(format!(
                    "node {node} desynced from {conversation:02x?}: {reason}"
                ));
            }
            Event::InviteFailed { .. } => {
                self.fail(format!("node {node}: invite failed with an honest mailbox"))
            }
            Event::Timer { .. } | Event::Renamed { .. } => self.report.timer_changes += 1,
            Event::Rules { .. } => self.report.rule_changes += 1,
            // No invite links in the simulation (they are tested in
            // tests/join_links.rs).
            Event::JoinRequest { .. } => {
                self.fail(format!("node {node}: a join request with no link"))
            }
            // Members try changes whether they may or not; a device refuses
            // what its group's rules forbid.
            Event::Refused { .. } => self.report.refusals += 1,
            Event::TimerRefused {
                conversation,
                reason,
            } => self.fail(format!(
                "node {node}: timer refused in {conversation:02x?}, every node is current: {reason}"
            )),
            Event::Sent {
                conversation,
                sender_seq,
            } => {
                self.oracle
                    .stored
                    .insert((conversation, self.nodes[node].device, sender_seq));
            }
            Event::MembersAdded { .. } | Event::MembersRemoved { .. } => {}
        }
    }

    // ---- Clients ---------------------------------------------------------

    fn tick_clients(&mut self) {
        for i in 0..self.nodes.len() {
            if self.nodes[i].client.is_none() || self.now < self.nodes[i].next_tick {
                continue;
            }
            let jitter = self.below(10);
            self.nodes[i].next_tick = self.now + CLIENT_TICK_MS + jitter;
            let now = self.now;
            let step = self.nodes[i].client.as_mut().expect("checked").tick(now);
            self.apply(i, step, None);
        }
    }

    fn workload(&mut self) {
        for i in 0..self.nodes.len() {
            if self.nodes[i].client.is_none() || !self.chance(0.02) {
                continue;
            }
            let now = self.now;
            let active: Vec<Route> = {
                let client = self.nodes[i].client.as_ref().expect("checked");
                client
                    .conversations()
                    .filter(|c| client.is_active(c))
                    .collect()
            };
            let roll = self.below(100);
            if active.is_empty() {
                continue;
            }
            let conversation = self.pick(&active);
            let members = self.nodes[i]
                .client
                .as_ref()
                .expect("up")
                .members(&conversation);
            if (66..68).contains(&roll) {
                self.refer(i, conversation);
            } else if (68..70).contains(&roll) {
                self.signal(i, conversation);
            } else if (70..73).contains(&roll) {
                self.signal_call(i, conversation);
            } else if (73..75).contains(&roll) {
                const TIMERS: [u32; 4] = [0, 300, 86_400, 604_800];
                const NAMES: [&str; 3] = ["", "KRYPTLEAK team", "KRYPTLEAK ✦ friends"];
                let pick = usize::try_from(self.below(4)).expect("fits");
                let what = self.below(3);
                let other =
                    members[usize::try_from(self.below(members.len() as u64)).expect("fits")];
                let client = self.nodes[i].client.as_mut().expect("up");
                // Group names are settings like the timer, and secret like
                // messages: they carry the leak marker. Rules change too,
                // tried by members whether they may or not.
                let step = match what {
                    0 => client.rename(now, conversation, NAMES[pick % 3]),
                    1 => client.set_timer(now, conversation, TIMERS[pick]),
                    _ => {
                        let mut policy = client
                            .policy(&conversation)
                            .unwrap_or_else(|| Policy::new(client.identity()));
                        match pick {
                            0 => {
                                policy.add = if policy.add == Who::Admins {
                                    Who::Everyone
                                } else {
                                    Who::Admins
                                }
                            }
                            1 => {
                                policy.edit = if policy.edit == Who::Admins {
                                    Who::Everyone
                                } else {
                                    Who::Admins
                                }
                            }
                            2 => policy.admins.push(other),
                            _ => policy.admins.retain(|a| *a != other),
                        }
                        client.set_policy(now, conversation, policy)
                    }
                };
                if let Ok(step) = step {
                    self.apply(i, step, None);
                }
            } else if (75..78).contains(&roll) {
                self.share_file(i, conversation);
            } else if (78..80).contains(&roll) {
                self.request_turn(i, conversation);
            } else if roll < 80 {
                self.text_counter += 1;
                let text = format!(
                    "{}-{i}-{}-{:016x}",
                    "KRYPTLEAK",
                    self.text_counter,
                    self.rng.next_u64()
                );
                let client = self.nodes[i].client.as_mut().expect("up");
                if let Ok((seq, step)) = client.send(now, conversation, &text) {
                    self.apply(i, step, Some((conversation, seq, Content::Text(text))));
                }
            } else if roll < 87 {
                let client = self.nodes[i].client.as_mut().expect("up");
                if let Ok(step) = client.update_keys(now, conversation) {
                    self.apply(i, step, None);
                }
            } else if roll < 93 {
                let candidates: Vec<usize> = (0..self.nodes.len())
                    .filter(|&n| !members.contains(&self.nodes[n].identity))
                    .filter(|&n| !self.nodes[n].removed.contains(&conversation))
                    .collect();
                if candidates.is_empty() {
                    continue;
                }
                let invitee = self.pick(&candidates);
                let contact = self.nodes[invitee].contact;
                let client = self.nodes[i].client.as_mut().expect("up");
                if let Ok(step) = client.invite(now, conversation, contact) {
                    self.apply(i, step, None);
                }
            } else if roll < 97 {
                // Keep at least two members so conversations stay alive.
                let me = self.nodes[i].identity;
                let others: Vec<IdentityKey> =
                    members.iter().filter(|m| **m != me).copied().collect();
                if members.len() <= 2 || others.is_empty() {
                    continue;
                }
                let target = self.pick(&others);
                let client = self.nodes[i].client.as_mut().expect("up");
                if let Ok(step) = client.remove(now, conversation, target) {
                    self.apply(i, step, None);
                }
            } else if roll == 97 && self.chance(0.2) {
                // Rarely, someone deletes a conversation or blocks someone.
                let forget = self.chance(0.5);
                let client = self.nodes[i].client.as_mut().expect("up");
                if forget {
                    if let Ok(step) = client.forget(now, conversation) {
                        self.apply(i, step, None);
                        if self.nodes[i].client.is_some() {
                            self.report.forgotten += 1;
                            // An invitation already on its way may bring the
                            // device back, as a new member; nobody invites it
                            // again after that.
                            self.oracle.joined.remove(&(i, conversation));
                            self.drop_unsent(i, conversation);
                            self.nodes[i].removed.insert(conversation);
                        }
                    }
                } else {
                    let me = self.nodes[i].identity;
                    let others: Vec<IdentityKey> =
                        members.iter().filter(|m| **m != me).copied().collect();
                    if others.is_empty() {
                        continue;
                    }
                    let target = self.pick(&others);
                    let client = self.nodes[i].client.as_mut().expect("up");
                    if let Ok(step) = client.block(target) {
                        self.apply(i, step, None);
                        // A crash before the step was persisted undoes it.
                        if self.nodes[i].client.is_some() {
                            self.oracle.blocked.insert((i, target));
                            self.report.blocks += 1;
                        }
                    }
                }
            } else {
                let total: BTreeSet<Route> = self
                    .nodes
                    .iter()
                    .filter_map(|n| n.client.as_ref())
                    .flat_map(Client::conversations)
                    .collect();
                if total.len() >= CONVERSATIONS_MAX {
                    continue;
                }
                let others: Vec<usize> = (0..self.nodes.len()).filter(|&n| n != i).collect();
                let other = self.pick(&others);
                let contact = self.nodes[other].contact;
                let client = self.nodes[i].client.as_mut().expect("up");
                if let Ok((_, step)) = client.start_conversation(now, contact) {
                    self.apply(i, step, None);
                }
            }
        }
    }

    // ---- Faults ----------------------------------------------------------

    fn inject_faults(&mut self) {
        for i in 0..self.nodes.len() {
            if self.options.crashes && self.nodes[i].client.is_some() && self.chance(0.0003) {
                self.crash(i);
            }
            if self.options.network_faults
                && self.nodes[i].partitioned_until <= self.now
                && self.chance(0.0003)
            {
                self.report.partitions += 1;
                let until = self.now + self.between(1_000, 15_000);
                self.nodes[i].partitioned_until = until;
                self.trace(i, "partitioned");
            }
        }
    }

    fn crash(&mut self, node: usize) {
        if self.nodes[node].client.take().is_none() {
            return;
        }
        self.report.crashes += 1;
        let until = self.now + self.between(200, 10_000);
        self.nodes[node].down_until = Some(until);
        self.trace(node, "crashed");
    }

    fn restart_due(&mut self) {
        for i in 0..self.nodes.len() {
            if self.nodes[i]
                .down_until
                .is_some_and(|until| until <= self.now)
            {
                self.restart(i);
            }
        }
    }

    fn restart(&mut self, node: usize) {
        let n = &mut self.nodes[node];
        n.down_until = None;
        n.restarts += 1;
        let rand = Rand::seeded(node_seed(self.seed, node, n.restarts));
        let entries: Vec<_> = n
            .disk
            .kv
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        match Client::restore(client_config(&self.options), rand, entries, self.now) {
            Ok((client, step)) => {
                self.nodes[node].client = Some(client);
                self.nodes[node].next_tick = self.now + CLIENT_TICK_MS;
                self.trace(node, "restarted");
                self.apply(node, step, None);
            }
            Err(e) => self.fail(format!("node {node} failed to restore: {e}")),
        }
    }

    fn heal(&mut self) {
        for i in 0..self.nodes.len() {
            self.nodes[i].partitioned_until = 0;
            if self.nodes[i].down_until.is_some() {
                self.restart(i);
            }
        }
        self.trace(usize::MAX, "healed");
    }

    // ---- Invariants ------------------------------------------------------

    /// Members that reach the same epoch must agree on all of its state.
    fn check_agreement(&mut self) {
        for i in 0..self.nodes.len() {
            let Some(client) = self.nodes[i].client.as_ref() else {
                continue;
            };
            for conversation in client.conversations().collect::<Vec<_>>() {
                if !client.is_active(&conversation) {
                    continue;
                }
                let (epoch, authenticator) = client.epoch(&conversation).expect("listed");
                let agreed = self
                    .oracle
                    .epochs
                    .entry((conversation, epoch))
                    .or_insert_with(|| authenticator.clone());
                if *agreed != authenticator {
                    let what = format!(
                        "node {i} forked conversation {conversation:02x?} at epoch {epoch}"
                    );
                    self.fail(what);
                    return;
                }
            }
        }
    }

    /// Once healed: every device is idle, every member is at the log's
    /// epoch, and every message reached everyone it was sealed for who is
    /// still in the conversation.
    fn converged(&self) -> Result<(), String> {
        let mut active: BTreeMap<Route, Vec<usize>> = BTreeMap::new();
        for (i, node) in self.nodes.iter().enumerate() {
            let client = node.client.as_ref().ok_or(format!("node {i} is down"))?;
            // Every device that asked to be woken is registered wherever it
            // follows (registrations survive crashes and restarts).
            if i % 2 == 0 {
                let target = PushTarget {
                    platform: Platform::WebPush,
                    address: &push_address(i),
                }
                .encode();
                for route in client.routes() {
                    if !self.mailbox.watchers(&route).contains(&target) {
                        return Err(format!(
                            "node {i} is not registered for wakeups at {route:02x?}"
                        ));
                    }
                }
            }
            for conversation in client.conversations() {
                if !client.is_active(&conversation) {
                    continue;
                }
                let log_epoch = self.mailbox.epoch(&conversation);
                if client.outbox_len(&conversation) > 0 {
                    let state = client.describe(&conversation);
                    return Err(format!(
                        "node {i} still has unsent messages (log epoch {log_epoch:?}): {state}"
                    ));
                }
                if client.intents_len(&conversation) > 0 {
                    let state = client.describe(&conversation);
                    return Err(format!(
                        "node {i} has uncommitted membership changes (log epoch {log_epoch:?}): {state}"
                    ));
                }
                active.entry(conversation).or_default().push(i);
            }
        }
        for (conversation, members) in &active {
            let settings: BTreeSet<_> = members
                .iter()
                .map(|&i| {
                    let client = self.nodes[i].client.as_ref().expect("up");
                    (
                        client.timer(conversation),
                        client.group_name(conversation),
                        client.policy(conversation),
                        client.admins(conversation),
                    )
                })
                .collect();
            if settings.len() > 1 {
                return Err(format!(
                    "members of {conversation:02x?} disagree on its settings: {settings:?}"
                ));
            }
            let log_epoch = self.mailbox.epoch(conversation);
            for &i in members {
                let (epoch, _) = self.nodes[i]
                    .client
                    .as_ref()
                    .expect("up")
                    .epoch(conversation)
                    .expect("member");
                if log_epoch.is_some_and(|log| log != epoch) {
                    return Err(format!(
                        "node {i} is at epoch {epoch}, the log at {log_epoch:?}"
                    ));
                }
            }
        }
        for (id, (recipients, epoch)) in &self.oracle.sealed {
            let (conversation, _, _) = id;
            let Some((sender, content)) = self.oracle.sent.get(id) else {
                continue;
            };
            // Reactions, edits, deletions and receipts name a device; a
            // receiver drops one naming a device not in the group (any of
            // these, as generated here, may; membership also changes while
            // they travel), so their delivery is not owed.
            if matches!(
                content,
                Content::React { .. }
                    | Content::Edit { .. }
                    | Content::Delete { .. }
                    | Content::Receipt(_)
            ) {
                continue;
            }
            if !active.get(conversation).is_some_and(|m| m.contains(sender)) {
                continue;
            }
            for (i, node) in self.nodes.iter().enumerate() {
                let still_member = active.get(conversation).is_some_and(|m| m.contains(&i));
                // Only the membership a message was encrypted to can read it:
                // a device that was removed before it ever came online and
                // invited again joins later, under new keys.
                let member_at_epoch = self
                    .oracle
                    .joined
                    .get(&(i, *conversation))
                    .is_some_and(|joined| joined <= epoch);
                let sender_identity = self.nodes[*sender].identity;
                if recipients.contains(&node.identity)
                    && still_member
                    && member_at_epoch
                    && !self.oracle.blocked.contains(&(i, sender_identity))
                    && !self.oracle.delivered.contains(&(i, *id))
                {
                    let skipped: Vec<String> = self
                        .oracle
                        .undecryptable
                        .iter()
                        .filter(|(n, c, _, _)| *n == i && c == conversation)
                        .map(|(_, _, at, reason)| format!("@{at}: {reason}"))
                        .collect();
                    let joined = self.oracle.joined.get(&(i, *conversation));
                    let (_, device, _) = id;
                    let got: Vec<u64> = self
                        .oracle
                        .delivered
                        .iter()
                        .filter(|(n, (c, d, _))| *n == i && c == conversation && d == device)
                        .map(|(_, (_, _, seq))| *seq)
                        .collect();
                    let sender = self.oracle.sent.get(id).map(|(s, _)| *s);
                    return Err(format!(
                        "node {i} (joined at epoch {joined:?}) never received {id:02x?} (seq {}) from node {sender:?} sealed at epoch {epoch}; got {got:?} from that device; undecryptable here: {skipped:?}",
                        id.2
                    ));
                }
            }
        }
        Ok(())
    }

    /// A member shares a file: it uploads the parts (the edge asks the
    /// mailbox, one request per part, as here), then sends the message. The
    /// name and preview carry the leak marker, so neither may reach the
    /// mailbox unencrypted. File contents are stored elsewhere (R2), sealed
    /// by `krypt_core::file`, so they are not simulated.
    fn share_file(&mut self, i: usize, conversation: Route) {
        let now = self.now;
        let log_epoch = self.mailbox.epoch(&conversation);
        let client = self.nodes[i].client.as_mut().expect("up");
        let (id, key) = client.new_file();
        let Ok(part) = client.file_auth(conversation, id, 0, 1024) else {
            return;
        };
        let request = frame::encode_vec(Kind::AuthorizeFile, 1, conversation, &part.encode());
        let Some((_, handled)) = self.mailbox.handle_request(now, &request) else {
            self.fail("the mailbox dropped a file authorization".to_owned());
            return;
        };
        let response = handled.response.expect("a response");
        let response = frame::decode(&response).expect("decodes");
        if response.kind == Kind::Accepted {
            self.report.files_authorized += 1;
        } else {
            let rejected = Rejected::decode(response.body).expect("decodes");
            // A member up to date with the log is always allowed.
            if Some(part.epoch) == log_epoch {
                self.fail(format!("a member was refused a file part: {rejected:?}"));
            }
            return;
        }
        self.text_counter += 1;
        let file = SharedFile {
            id,
            key,
            size: 1024,
            name: format!("KRYPTLEAK-{i}-{}.jpg", self.text_counter),
            media_type: "image/jpeg".to_owned(),
            width: 640,
            height: 480,
            thumbnail: LEAK_MARKER.to_vec(),
        };
        let client = self.nodes[i].client.as_mut().expect("up");
        if let Ok((seq, step)) = client.send_file(now, conversation, file.clone()) {
            self.apply(
                i,
                step,
                Some((conversation, seq, Content::File(Box::new(file)))),
            );
        }
    }

    /// A device's membership ended (removed, or it forgot the conversation):
    /// messages it had not yet sent went with it.
    fn drop_unsent(&mut self, node: usize, conversation: Route) {
        let device = self.nodes[node].device;
        let stored = &self.oracle.stored;
        self.oracle.sealed.retain(|id, _| {
            let (c, d, _) = id;
            *c != conversation || *d != device || stored.contains(id)
        });
    }

    /// A member sends a call signal. Session descriptions carry addresses
    /// and keys, so they carry the leak marker too.
    fn signal_call(&mut self, i: usize, conversation: Route) {
        let now = self.now;
        self.text_counter += 1;
        let roll = self.below(4);
        let peer = usize::try_from(self.below(self.nodes.len() as u64)).expect("fits");
        let call = Call {
            call: self
                .rng
                .next_u64()
                .to_le_bytes()
                .repeat(2)
                .try_into()
                .expect("16"),
            to: if roll == 0 {
                [0; 32]
            } else {
                self.nodes[peer].device
            },
            kind: match roll {
                0 => CallKind::Offer,
                1 => CallKind::Answer,
                2 => CallKind::Candidates,
                _ => CallKind::End(CallEnd::Hangup),
            },
            video: roll == 0,
            sdp: if roll == 3 {
                String::new()
            } else {
                format!("v=0 KRYPTLEAK-{i}-{}", self.text_counter)
            },
        };
        let client = self.nodes[i].client.as_mut().expect("up");
        if let Ok((seq, step)) = client.send_call(now, conversation, call.clone()) {
            self.apply(
                i,
                step,
                Some((conversation, seq, Content::Call(Box::new(call)))),
            );
        }
    }

    /// A member sends something that refers to a message: a reply, a
    /// reaction, an edit, a deletion, a read receipt. Replies and edits carry
    /// the leak marker like any text.
    fn refer(&mut self, i: usize, conversation: Route) {
        let now = self.now;
        let nodes = u64::try_from(self.nodes.len()).expect("fits");
        let author = usize::try_from(self.below(nodes)).expect("fits");
        let to = MessageRef {
            device: self.nodes[author].device,
            seq: 1 + self.below(8),
        };
        self.text_counter += 1;
        let text = format!("KRYPTLEAK-ref-{i}-{}", self.text_counter);
        let content = match self.below(5) {
            0 => Content::Reply { to, text },
            1 => Content::React {
                to,
                emoji: if self.chance(0.5) {
                    "👍".into()
                } else {
                    String::new()
                },
            },
            2 => Content::Edit { to, text },
            3 => Content::Delete { to },
            _ => Content::Receipt(vec![to]),
        };
        let device = self.nodes[i].device;
        let client = self.nodes[i].client.as_mut().expect("up");
        if let Ok((seq, step)) = client.send_content(now, conversation, content.clone()) {
            let id = (conversation, device, seq);
            let replaced = matches!(content, Content::Receipt(_))
                && matches!(self.oracle.sent.get(&id), Some((_, Content::Receipt(_))));
            if replaced {
                // A newer receipt took the place of one not yet sent.
                self.oracle.sent.insert(id, (i, content));
                self.apply(i, step, None);
            } else {
                self.apply(i, step, Some((conversation, seq, content)));
            }
        }
    }

    /// A member says it is typing, stopped, online or offline.
    fn signal(&mut self, i: usize, conversation: Route) {
        const KINDS: [SignalKind; 5] = [
            SignalKind::Typing,
            SignalKind::Idle,
            SignalKind::Online,
            SignalKind::Offline,
            SignalKind::Hello,
        ];
        let kind = KINDS[usize::try_from(self.below(5)).expect("fits")];
        let now = self.now;
        let device = self.nodes[i].device;
        let client = self.nodes[i].client.as_mut().expect("up");
        if let Ok(step) = client.signal(now, conversation, kind) {
            self.report.signals_sent += 1;
            self.oracle.signals.insert((conversation, device, kind));
            self.apply(i, step, None);
        }
    }

    /// A member asks for call relay credentials (the edge asks the mailbox,
    /// as here). One up to date with the log is allowed within the day's
    /// allowance.
    fn request_turn(&mut self, i: usize, conversation: Route) {
        let now = self.now;
        let log_epoch = self.mailbox.epoch(&conversation);
        let client = self.nodes[i].client.as_mut().expect("up");
        let Ok(grant) = client.turn_auth(conversation) else {
            return;
        };
        let request = frame::encode_vec(Kind::AuthorizeTurn, 1, conversation, &grant.encode());
        let Some((_, handled)) = self.mailbox.handle_request(now, &request) else {
            self.fail("the mailbox dropped a relay authorization".to_owned());
            return;
        };
        let response = handled.response.expect("a response");
        let response = frame::decode(&response).expect("decodes");
        if response.kind == Kind::Accepted {
            self.report.turn_grants += 1;
            return;
        }
        let rejected = Rejected::decode(response.body).expect("decodes");
        if Some(grant.epoch) == log_epoch && rejected.reason != Reject::OverQuota {
            self.fail(format!(
                "a member was refused relay credentials: {rejected:?}"
            ));
        }
    }

    fn check_mailbox_for_leaks(&mut self) {
        let leaked = self
            .mailbox
            .values()
            .any(|bytes| bytes.windows(LEAK_MARKER.len()).any(|w| w == LEAK_MARKER));
        if leaked {
            self.fail("plaintext stored at the mailbox".to_owned());
        }
    }
}
