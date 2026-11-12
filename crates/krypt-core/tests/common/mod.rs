//! A device driven against a local mailbox, for the integration tests.
// Each test binary uses only part of this.
#![allow(dead_code)]

use std::collections::BTreeMap;

use krypt_core::client::{Client, Config, Effect, Event, Step};
use krypt_core::mailbox::LocalMailbox;
use krypt_core::provider::Rand;
use krypt_wire::frame::{self, Kind, Route};
use krypt_wire::msg::{Reject, Rejected};

pub struct Device {
    pub client: Client,
    pub disk: BTreeMap<Vec<u8>, Vec<u8>>,
    pub events: Vec<Event>,
}

impl Device {
    pub fn new(seed: u64, mailbox: &mut LocalMailbox) -> Device {
        Device::with_config(seed, mailbox, Config::default())
    }

    pub fn with_config(seed: u64, mailbox: &mut LocalMailbox, config: Config) -> Device {
        let (client, step) = Client::create(config, Rand::seeded(seed), 0);
        let mut device = Device {
            client,
            disk: BTreeMap::new(),
            events: Vec::new(),
        };
        device.apply(mailbox, 0, step);
        device
    }

    /// Persists a step and runs its requests through the mailbox.
    pub fn apply(&mut self, mailbox: &mut LocalMailbox, now: u64, step: Step) {
        let mut queue = vec![step];
        let mut rounds = 0;
        while let Some(step) = queue.pop() {
            rounds += 1;
            assert!(
                rounds < 10_000,
                "requests never settle: {:?}",
                step.effects
                    .iter()
                    .map(|e| match e {
                        Effect::Mailbox(frame) =>
                            format!("{:?}", krypt_wire::frame::decode(frame).map(|f| f.kind)),
                        Effect::Event(event) => format!("{event:?}").chars().take(80).collect(),
                    })
                    .collect::<Vec<_>>()
            );
            for (key, value) in step.writes {
                match value {
                    Some(value) => self.disk.insert(key, value),
                    None => self.disk.remove(&key),
                };
            }
            for effect in step.effects {
                match effect {
                    Effect::Mailbox(request) => {
                        if let Some(response) = mailbox.handle(now, &request) {
                            queue.push(self.client.receive(now, &response));
                        }
                    }
                    Effect::Event(event) => self.events.push(event),
                }
            }
        }
    }

    /// Persists a step's writes without performing its effects: a crash
    /// right after.
    pub fn persist_only(&mut self, step: Step) {
        for (key, value) in step.writes {
            match value {
                Some(value) => self.disk.insert(key, value),
                None => self.disk.remove(&key),
            };
        }
    }

    /// Restarts from what is on disk.
    pub fn restart(&mut self, mailbox: &mut LocalMailbox, seed: u64, now: u64) {
        let records = self.disk.clone().into_iter();
        let (client, step) =
            Client::restore(Config::default(), Rand::seeded(seed), records, now).expect("restores");
        self.client = client;
        self.apply(mailbox, now, step);
    }
}

/// Lets both devices run until the mailbox has nothing more to push.
pub fn settle(devices: &mut [&mut Device], mailbox: &mut LocalMailbox, now: &mut u64) {
    for _ in 0..50 {
        *now += 1_000;
        for device in devices.iter_mut() {
            let step = device.client.tick(*now);
            device.apply(mailbox, *now, step);
        }
        for (_, notify) in mailbox.take_notifications() {
            for device in devices.iter_mut() {
                let step = device.client.receive(*now, &notify);
                device.apply(mailbox, *now, step);
            }
        }
    }
}

/// Sends an authorization request (as the edge does) straight to the mailbox.
pub fn authorize(
    mailbox: &mut LocalMailbox,
    kind: Kind,
    conversation: Route,
    body: &[u8],
) -> Result<(), Reject> {
    let request = frame::encode_vec(kind, 1, conversation, body);
    let response = mailbox.handle(0, &request).expect("a response");
    let response = frame::decode(&response).expect("decodes");
    match response.kind {
        Kind::Accepted => Ok(()),
        _ => Err(Rejected::decode(response.body).expect("decodes").reason),
    }
}
