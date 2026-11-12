//! Push registrations: made once per log and renewed weekly, not on every
//! start. A browser reloads constantly; re-registering every conversation
//! each time would cost a request and a row written per log per reload.

use std::collections::BTreeMap;

use krypt_core::client::{Client, Config, Effect, Step};
use krypt_core::mailbox::LocalMailbox;
use krypt_core::provider::Rand;
use krypt_wire::msg::{Platform, PushTarget};
use krypt_wire::{Kind, frame};

const DAY_MS: u64 = 24 * 60 * 60 * 1000;

/// A device and its disk, wired to a mailbox.
struct Device {
    client: Client,
    disk: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Watch requests the device has sent.
    watches: usize,
}

impl Device {
    fn apply(&mut self, mailbox: &mut LocalMailbox, now: u64, step: Step) {
        let mut queue = vec![step];
        while let Some(step) = queue.pop() {
            for (key, value) in step.writes {
                match value {
                    Some(value) => self.disk.insert(key, value),
                    None => self.disk.remove(&key),
                };
            }
            for effect in step.effects {
                let Effect::Mailbox(request) = effect else {
                    continue;
                };
                if frame::decode(&request).is_ok_and(|f| f.kind == Kind::Watch) {
                    self.watches += 1;
                }
                if let Some(response) = mailbox.handle(now, &request) {
                    queue.push(self.client.receive(now, &response));
                }
            }
        }
    }

    fn settle(&mut self, mailbox: &mut LocalMailbox, now: u64) {
        for i in 0..5 {
            let step = self.client.tick(now + i * 1_000);
            self.apply(mailbox, now + i * 1_000, step);
        }
    }
}

#[test]
fn registrations_survive_restarts_and_renew_weekly() {
    let mut mailbox = LocalMailbox::new();
    let (client, step) = Client::create(Config::default(), Rand::seeded(7), 0);
    let mut device = Device {
        client,
        disk: BTreeMap::new(),
        watches: 0,
    };
    device.apply(&mut mailbox, 0, step);
    let target = PushTarget {
        platform: Platform::WebPush,
        address: b"https://fcm.googleapis.com/fcm/send/abc",
    };
    let step = device.client.set_push_target(0, Some(target));
    device.apply(&mut mailbox, 0, step);
    device.settle(&mut mailbox, 1_000);
    let inbox = device.client.routes()[0];
    assert!(mailbox.watchers(&inbox).contains(&target.encode()));
    assert_eq!(
        device.watches, 1,
        "one registration for the one log followed"
    );

    // Restart from disk, many times: nothing is registered again.
    for restart in 1..=5 {
        let now = restart * 60_000;
        let records = device.disk.clone().into_iter();
        let (client, step) =
            Client::restore(Config::default(), Rand::seeded(restart), records, now).unwrap();
        device.client = client;
        device.apply(&mut mailbox, now, step);
        device.settle(&mut mailbox, now);
    }
    assert_eq!(device.watches, 1, "restarts must not re-register");

    // A week on, the registration is renewed once.
    device.settle(&mut mailbox, 8 * DAY_MS);
    assert_eq!(device.watches, 2);
}

#[test]
fn a_new_device_registers_its_inbox_at_the_first_attempt() {
    let mut mailbox = LocalMailbox::new();
    let (mut client, created) = Client::create(Config::default(), Rand::seeded(9), 0);
    // Turned on before the first publish is answered: the two requests race,
    // and here the registration reaches the mailbox first.
    let target = PushTarget {
        platform: Platform::WebPush,
        address: b"https://fcm.googleapis.com/fcm/send/new",
    };
    let step = client.set_push_target(0, Some(target));
    let mut device = Device {
        client,
        disk: BTreeMap::new(),
        watches: 0,
    };
    device.apply(&mut mailbox, 0, step);
    device.apply(&mut mailbox, 0, created);
    device.settle(&mut mailbox, 1_000);
    let inbox = device.client.routes()[0];
    assert!(mailbox.watchers(&inbox).contains(&target.encode()));
    assert_eq!(device.watches, 1, "registered once, not refused first");
}
