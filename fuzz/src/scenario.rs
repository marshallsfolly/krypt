//! The conversation the fixture and the seeds come from: Alice, Bob, Carol
//! and Dave on one mailbox. Bob goes offline midway, with a message queued
//! and an invitation pending, while the others carry on; he is the
//! fixture's device.

use std::collections::BTreeMap;

use krypt_core::client::{Client, Config, Effect, SharedFile, Step};
use krypt_core::mailbox::LocalMailbox;
use krypt_core::provider::Rand;
use krypt_wire::frame::{self, Kind, Route};
use krypt_wire::limits::FETCH_ENTRIES_MAX;
use krypt_wire::msg::{Entries, Fetch};

use crate::fixture::{Fixture, Stashed};
use crate::mailbox::START_MS;

pub struct Node {
    pub client: Client,
    pub disk: BTreeMap<Vec<u8>, Vec<u8>>,
    pub online: bool,
}

/// Devices on one mailbox, which keeps every request it handled and every
/// frame it sent back.
pub struct World {
    pub mailbox: LocalMailbox,
    pub nodes: Vec<Node>,
    pub now: u64,
    pub requests: Vec<(u64, Vec<u8>)>,
    pub frames: Vec<Vec<u8>>,
}

impl World {
    fn new() -> World {
        World {
            mailbox: LocalMailbox::new(),
            nodes: Vec::new(),
            now: START_MS,
            requests: Vec::new(),
            frames: Vec::new(),
        }
    }

    fn add(&mut self, seed: u64) -> usize {
        let (client, step) = Client::create(Config::default(), Rand::seeded(seed), self.now);
        self.nodes.push(Node {
            client,
            disk: BTreeMap::new(),
            online: true,
        });
        let node = self.nodes.len() - 1;
        self.drive(node, step);
        node
    }

    /// Persists each step; an online device's requests then reach the
    /// mailbox, and pushes reach every online device following the log.
    pub fn drive(&mut self, from: usize, step: Step) {
        let mut queue = vec![(from, step)];
        while let Some((node, step)) = queue.pop() {
            for (key, value) in step.writes {
                match value {
                    Some(value) => self.nodes[node].disk.insert(key, value),
                    None => self.nodes[node].disk.remove(&key),
                };
            }
            if !self.nodes[node].online {
                continue;
            }
            for effect in step.effects {
                let Effect::Mailbox(request) = effect else {
                    continue;
                };
                self.requests.push((self.now, request.clone()));
                if let Some(response) = self.mailbox.handle(self.now, &request) {
                    self.frames.push(response.clone());
                    queue.push((node, self.nodes[node].client.receive(self.now, &response)));
                }
                drop(self.mailbox.take_wakeups());
                for (route, notify) in self.mailbox.take_notifications() {
                    self.frames.push(notify.clone());
                    for to in 0..self.nodes.len() {
                        let follows = self.nodes[to].client.routes().contains(&route);
                        if self.nodes[to].online && follows {
                            let step = self.nodes[to].client.receive(self.now, &notify);
                            queue.push((to, step));
                        }
                    }
                }
            }
        }
    }

    fn settle(&mut self) {
        for _ in 0..5 {
            self.now += 1_000;
            for node in 0..self.nodes.len() {
                if self.nodes[node].online {
                    let step = self.nodes[node].client.tick(self.now);
                    self.drive(node, step);
                }
            }
        }
    }

    /// Every entry of a log, read straight from the mailbox.
    fn log(&mut self, route: Route) -> Vec<Stashed> {
        let mut out = Vec::new();
        let mut after = 0;
        loop {
            let fetch = Fetch {
                after,
                max: FETCH_ENTRIES_MAX,
            };
            let request = frame::encode_vec(Kind::Fetch, 0, route, &fetch.encode());
            let response = self.mailbox.handle(self.now, &request).expect("answered");
            let response = frame::decode(&response).expect("a frame");
            let entries = Entries::decode(response.body).expect("entries");
            for entry in &entries.entries {
                out.push(Stashed {
                    route,
                    seq: entry.seq,
                    data: entry.data.to_vec(),
                });
                after = entry.seq;
            }
            if entries.next <= after + 1 {
                return out;
            }
        }
    }

    fn send(&mut self, node: usize, conversation: Route, text: &str) {
        let (_, step) = self.nodes[node]
            .client
            .send(self.now, conversation, text)
            .expect("sends");
        self.drive(node, step);
    }
}

/// What the scenario leaves: the fixture, and everything the mailbox saw.
pub struct Scenario {
    pub fixture: Fixture,
    pub world: World,
}

pub fn run() -> Scenario {
    let mut world = World::new();
    let alice = world.add(1);
    let bob = world.add(2);
    let carol = world.add(3);
    let dave = world.add(4);
    world.settle();

    let card = world.nodes[bob].client.contact_card();
    let (first, step) = world.nodes[alice]
        .client
        .start_conversation(world.now, card)
        .expect("starts");
    world.drive(alice, step);
    world.settle();
    world.send(alice, first, "hello bob");
    world.send(bob, first, "hi alice");
    world.settle();
    assert!(world.nodes[bob].client.is_active(&first), "bob joined");

    // Bob goes offline. Alice adds Carol, they talk, share a file, and
    // Alice rotates her keys; then she starts a second conversation with
    // Bob.
    world.nodes[bob].online = false;
    world.send(alice, first, "while you were away");
    let card = world.nodes[carol].client.contact_card();
    let step = world.nodes[alice]
        .client
        .invite(world.now, first, card)
        .expect("invites");
    world.drive(alice, step);
    world.settle();
    assert!(world.nodes[carol].client.is_active(&first), "carol joined");
    world.send(carol, first, "hi everyone");
    let (id, key) = world.nodes[alice].client.new_file();
    let file = SharedFile {
        id,
        key,
        size: 3_000_000,
        name: "IMG_0001.jpg".to_owned(),
        media_type: "image/jpeg".to_owned(),
        width: 4032,
        height: 3024,
        thumbnail: vec![0xFF, 0xD8, 0xFF, 0xD9],
    };
    let (_, step) = world.nodes[alice]
        .client
        .send_file(world.now, first, file)
        .expect("shares");
    world.drive(alice, step);
    let step = world.nodes[alice]
        .client
        .update_keys(world.now, first)
        .expect("updates");
    world.drive(alice, step);
    world.settle();
    let card = world.nodes[bob].client.contact_card();
    let (second, step) = world.nodes[alice]
        .client
        .start_conversation(world.now, card)
        .expect("starts");
    world.drive(alice, step);
    world.settle();
    world.send(alice, second, "a second conversation");
    world.settle();

    // Offline, Bob writes a message and asks to add Dave; both are
    // persisted, and nothing reaches the mailbox.
    world.send(bob, first, "written offline");
    let card = world.nodes[dave].client.contact_card();
    let step = world.nodes[bob]
        .client
        .invite(world.now, first, card)
        .expect("invites");
    world.drive(bob, step);

    let inbox = world.nodes[bob].client.contact_card().inbox;
    let mut stash = world.log(inbox);
    stash.extend(world.log(first));
    stash.extend(world.log(second));
    let claim = frame::encode_vec(Kind::ClaimKeyPackage, 0, card.inbox, &[]);
    let key_package = world.mailbox.handle(world.now, &claim).expect("answered");
    let key_package = frame::decode(&key_package).expect("a frame");
    assert_eq!(key_package.kind, Kind::KeyPackage);

    let fixture = Fixture {
        now: world.now,
        records: world.nodes[bob].disk.clone().into_iter().collect(),
        inbox,
        conversations: vec![first, second],
        stash,
        peer: world.nodes[alice].client.identity(),
        contact: card,
        key_package: key_package.body.to_vec(),
    };
    Scenario { fixture, world }
}
