//! Hot-path benchmarks: sending and receiving one chat message.
//!
//! Budget (docs/STYLE.md): encrypt + frame a message in under 20 µs.

#![allow(clippy::unwrap_used)]

use std::collections::{BTreeMap, VecDeque};

use krypt_core::client::{Client, Config, Effect, Step};
use krypt_core::mailbox::LocalMailbox;
use krypt_core::provider::Rand;
use krypt_wire::{Kind, Route, frame};

fn main() {
    divan::main();
}

/// Two devices that share a conversation, wired through a mailbox with no
/// network in between.
struct Pair {
    alice: Client,
    bob: Client,
    mailbox: LocalMailbox,
    conversation: Route,
    now: u64,
}

impl Pair {
    fn new() -> Pair {
        let (alice, _) = Client::create(Config::default(), Rand::seeded(1), 0);
        let (bob, _) = Client::create(Config::default(), Rand::seeded(2), 0);
        let mut pair = Pair {
            alice,
            bob,
            mailbox: LocalMailbox::new(),
            conversation: [0; 16],
            now: 0,
        };
        // Let both publish key packages, then start the conversation.
        pair.settle();
        let contact = pair.bob.contact_card();
        let (conversation, step) = pair.alice.start_conversation(pair.now, contact).unwrap();
        pair.conversation = conversation;
        pair.drive(0, step, false);
        pair.settle();
        assert!(pair.bob.is_active(&conversation), "bob never joined");
        pair
    }

    fn client(&mut self, node: usize) -> &mut Client {
        if node == 0 {
            &mut self.alice
        } else {
            &mut self.bob
        }
    }

    /// Runs requests through the mailbox until nothing is left in flight,
    /// pushing each log's new entries to the devices that follow it. With
    /// `hold`, pushes to Bob are returned instead of delivered.
    fn drive(&mut self, from: usize, step: Step, hold: bool) -> Vec<Vec<u8>> {
        let mut held = Vec::new();
        let mut queue = VecDeque::from([(from, step)]);
        while let Some((node, step)) = queue.pop_front() {
            for effect in step.effects {
                let Effect::Mailbox(request) = effect else {
                    continue;
                };
                if let Some(response) = self.mailbox.handle(self.now, &request) {
                    let now = self.now;
                    queue.push_back((node, self.client(node).receive(now, &response)));
                }
                drop(self.mailbox.take_wakeups());
                for (route, notify) in self.mailbox.take_notifications() {
                    for to in [0, 1] {
                        if !self.client(to).routes().contains(&route) {
                            continue;
                        }
                        if hold && to == 1 {
                            held.push(notify.clone());
                            continue;
                        }
                        let now = self.now;
                        queue.push_back((to, self.client(to).receive(now, &notify)));
                    }
                }
            }
        }
        held
    }

    fn settle(&mut self) {
        for _ in 0..20 {
            self.now += 1_000;
            let step = self.alice.tick(self.now);
            self.drive(0, step, false);
            let step = self.bob.tick(self.now);
            self.drive(1, step, false);
        }
    }
}

/// Alice queues a message: MLS encryption, framing, and the storage writes.
#[divan::bench(sample_count = 2000)]
fn send_message(bencher: divan::Bencher) {
    let mut pair = Pair::new();
    bencher.bench_local(|| {
        let (now, conversation) = (pair.now, pair.conversation);
        let (_, step) = pair
            .alice
            .send(now, conversation, "hello, this is a typical chat message")
            .unwrap();
        // Acknowledge it so the outbox (bounded) never fills. Bob's copy is
        // held back: decrypting it is `receive_pushed`, not sending.
        pair.drive(0, step, true)
    });
}

/// Bob receives a message the mailbox pushed to him: decode, decrypt,
/// verify, deliver.
#[divan::bench(sample_count = 2000)]
fn receive_pushed(bencher: divan::Bencher) {
    let pair = std::cell::RefCell::new(Pair::new());
    bencher
        .with_inputs(|| {
            let mut pair = pair.borrow_mut();
            let (now, conversation) = (pair.now, pair.conversation);
            let (_, step) = pair
                .alice
                .send(now, conversation, "hello, this is a typical chat message")
                .unwrap();
            pair.drive(0, step, true)
        })
        .bench_local_values(|pushed| {
            let mut pair = pair.borrow_mut();
            let now = pair.now;
            assert!(!pushed.is_empty(), "nothing was pushed");
            pushed
                .iter()
                .map(|notify| pair.bob.receive(now, notify))
                .collect::<Vec<_>>()
        });
}

/// A conversation of `n` devices, everyone's keys rotated once so that every
/// node of the ratchet tree is filled (the largest state a group of that
/// size stores), with each device's disk.
struct Group {
    clients: Vec<Client>,
    disks: Vec<BTreeMap<Vec<u8>, Vec<u8>>>,
    /// Bytes each device has written (keys and values).
    written: Vec<usize>,
    mailbox: LocalMailbox,
    conversation: Route,
    now: u64,
}

impl Group {
    fn new(n: usize) -> Group {
        let mut group = Group {
            clients: Vec::new(),
            disks: Vec::new(),
            written: Vec::new(),
            mailbox: LocalMailbox::new(),
            conversation: [0; 16],
            now: 0,
        };
        for seed in 0..n as u64 {
            let (client, step) = Client::create(Config::default(), Rand::seeded(seed), 0);
            group.clients.push(client);
            group.disks.push(BTreeMap::new());
            group.written.push(0);
            group.drive(group.clients.len() - 1, step);
        }
        let card = group.clients[1].contact_card();
        let (conversation, step) = group.clients[0].start_conversation(0, card).unwrap();
        group.conversation = conversation;
        group.drive(0, step);
        group.settle();
        for i in 2..n {
            let card = group.clients[i].contact_card();
            let step = group.clients[0]
                .invite(group.now, conversation, card)
                .unwrap();
            group.drive(0, step);
            group.settle();
        }
        for i in 0..n {
            let step = group.clients[i]
                .update_keys(group.now, conversation)
                .unwrap();
            group.drive(i, step);
            group.settle();
        }
        let epochs: Vec<_> = group
            .clients
            .iter()
            .map(|c| c.epoch(&conversation))
            .collect();
        assert!(
            epochs.iter().all(|e| e.is_some() && *e == epochs[0]),
            "every member is in the same epoch"
        );
        group
    }

    /// Persists each step, then runs its requests through the mailbox and
    /// pushes new entries to every device following the log.
    fn drive(&mut self, from: usize, step: Step) {
        let mut queue = VecDeque::from([(from, step)]);
        while let Some((node, step)) = queue.pop_front() {
            for (key, value) in step.writes {
                self.written[node] += key.len() + value.as_ref().map_or(0, Vec::len);
                match value {
                    Some(value) => self.disks[node].insert(key, value),
                    None => self.disks[node].remove(&key),
                };
            }
            for effect in step.effects {
                let Effect::Mailbox(request) = effect else {
                    continue;
                };
                if let Some(response) = self.mailbox.handle(self.now, &request) {
                    queue.push_back((node, self.clients[node].receive(self.now, &response)));
                }
                drop(self.mailbox.take_wakeups());
                for (route, notify) in self.mailbox.take_notifications() {
                    for to in 0..self.clients.len() {
                        if self.clients[to].routes().contains(&route) {
                            queue.push_back((to, self.clients[to].receive(self.now, &notify)));
                        }
                    }
                }
            }
        }
    }

    fn settle(&mut self) {
        for _ in 0..4 {
            self.now += 1_000;
            for i in 0..self.clients.len() {
                let step = self.clients[i].tick(self.now);
                self.drive(i, step);
            }
        }
    }

    /// Bytes device `node` writes while `f` runs.
    fn written_by(&mut self, node: usize, f: impl FnOnce(&mut Group)) -> usize {
        let before = self.written[node];
        f(self);
        self.written[node] - before
    }
}

/// Restarting a device in a group of `members`. Also prints what the
/// device writes sending one message (until the mailbox has it) and
/// processing another member's commit (the whole ratchet tree, among
/// others), and what it stores.
#[divan::bench(args = [2, 33], sample_count = 100)]
fn restore(bencher: divan::Bencher, members: usize) {
    let mut group = Group::new(members);
    let conversation = group.conversation;
    let message = group.written_by(1, |group| {
        let (_, step) = group.clients[1]
            .send(
                group.now,
                conversation,
                "hello, this is a typical chat message",
            )
            .unwrap();
        group.drive(1, step);
        group.settle();
    });
    let commit = group.written_by(1, |group| {
        let step = group.clients[0]
            .update_keys(group.now, conversation)
            .unwrap();
        group.drive(0, step);
        group.settle();
    });
    let stored: usize = group.disks[1].iter().map(|(k, v)| k.len() + v.len()).sum();
    eprintln!(
        "{members} members, bytes written: {message} sending a message, {commit} processing a commit; {stored} stored"
    );
    let disk = group.disks[1].clone();
    let now = group.now;
    bencher
        .with_inputs(|| disk.clone())
        .bench_local_values(|disk| {
            Client::restore(Config::default(), Rand::seeded(9), disk, now).unwrap()
        });
}

#[divan::bench(args = [64, 1024, 16 * 1024])]
fn frame_encode(bencher: divan::Bencher, size: usize) {
    let body = vec![7u8; size];
    bencher
        .counter(divan::counter::BytesCount::new(size))
        .bench(|| frame::encode_vec(Kind::Submit, 1, [3; 16], &body));
}

#[divan::bench(args = [64, 1024, 16 * 1024])]
fn frame_decode(bencher: divan::Bencher, size: usize) {
    let bytes = frame::encode_vec(Kind::Submit, 1, [3; 16], &vec![7u8; size]);
    bencher
        .counter(divan::counter::BytesCount::new(size))
        .bench(|| frame::decode(divan::black_box(&bytes)).unwrap().body.len());
}

/// Sealing one full file part (4 MiB): what a phone spends per part before
/// uploading it.
#[divan::bench(sample_count = 50)]
fn seal_file_part(bencher: divan::Bencher) {
    use krypt_wire::limits::FILE_PART_SIZE;
    let size = u64::from(FILE_PART_SIZE) * 2;
    bencher
        .counter(divan::counter::BytesCount::new(FILE_PART_SIZE as usize))
        .with_inputs(|| vec![7u8; FILE_PART_SIZE as usize])
        .bench_local_values(|mut part| {
            krypt_core::file::seal(&[1; 32], size, 0, &mut part);
            part
        });
}
