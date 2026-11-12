//! Devices in the wild hold OpenMLS state written as JSON, the encoding the
//! vendored store used until 2026-11-06. Later builds write a compact binary
//! encoding and must go on reading the old one, including stores that mix
//! the two once a device has written again.
//!
//! The fixture holds two devices' records exactly as a JSON-era build
//! (commit e99c043) left them, and every request their mailbox saw, so the
//! mailbox can be rebuilt exactly. `regenerate_fixture` wrote it, at that
//! commit (with this file copied in); later builds refuse to.

use std::collections::BTreeMap;
use std::path::PathBuf;

use krypt_core::client::{Client, Config, Content, Effect, Event, Step};
use krypt_core::mailbox::LocalMailbox;
use krypt_core::provider::Rand;
use krypt_wire::Route;
use krypt_wire::codec::{Reader, Writer};

/// Binary OpenMLS values start with this byte, which no JSON text can.
const BINARY: u8 = 0x01;
const FIXTURE_MAGIC: &[u8; 8] = b"krypt-m1";
/// The fixture is small: one regular key package per device, plus the
/// last-resort one.
const CONFIG: Config = Config {
    request_timeout_ms: 2_000,
    poll_interval_ms: 15_000,
    key_packages: 1,
    break_rules: false,
};

type Disk = BTreeMap<Vec<u8>, Vec<u8>>;

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/json-era-records.bin")
}

/// Every request a mailbox handled, in order, so it can be rebuilt.
struct Net {
    mailbox: LocalMailbox,
    requests: Vec<(u64, Vec<u8>)>,
}

struct Device {
    client: Client,
    disk: Disk,
    events: Vec<Event>,
}

impl Device {
    fn restore(disk: Disk, seed: u64, now: u64, net: &mut Net) -> Device {
        let (client, step) =
            Client::restore(CONFIG, Rand::seeded(seed), disk.clone(), now).expect("restores");
        let mut device = Device {
            client,
            disk,
            events: Vec::new(),
        };
        device.apply(net, now, step);
        device
    }

    /// Persists a step, then runs its requests through the mailbox.
    fn apply(&mut self, net: &mut Net, now: u64, step: Step) {
        let mut queue = vec![step];
        while let Some(step) = queue.pop() {
            for (key, value) in step.writes {
                match value {
                    Some(value) => self.disk.insert(key, value),
                    None => self.disk.remove(&key),
                };
            }
            for effect in step.effects {
                match effect {
                    Effect::Mailbox(request) => {
                        net.requests.push((now, request.clone()));
                        if let Some(response) = net.mailbox.handle(now, &request) {
                            queue.push(self.client.receive(now, &response));
                        }
                    }
                    Effect::Event(event) => self.events.push(event),
                }
            }
        }
    }
}

/// Runs both devices until the mailbox has nothing more to push.
fn settle(devices: &mut [&mut Device], net: &mut Net, now: &mut u64) {
    for _ in 0..30 {
        *now += 1_000;
        for device in devices.iter_mut() {
            let step = device.client.tick(*now);
            device.apply(net, *now, step);
        }
        drop(net.mailbox.take_wakeups());
        for (route, notify) in net.mailbox.take_notifications() {
            for device in devices.iter_mut() {
                if device.client.routes().contains(&route) {
                    let step = device.client.receive(*now, &notify);
                    device.apply(net, *now, step);
                }
            }
        }
    }
}

fn texts(device: &Device, conversation: Route) -> Vec<String> {
    device
        .events
        .iter()
        .filter_map(|e| match e {
            Event::Message {
                conversation: c,
                content: Content::Text(text),
                ..
            } if *c == conversation => Some(text.clone()),
            _ => None,
        })
        .collect()
}

/// OpenMLS's records: everything but the application's, whose keys start
/// with a zero byte.
fn mls_values(disk: &Disk) -> impl Iterator<Item = (&Vec<u8>, &Vec<u8>)> {
    disk.iter().filter(|(key, _)| key.first() != Some(&0))
}

fn encode_disk(w: &mut Writer, disk: &Disk) {
    w.count(disk.len());
    for (key, value) in disk {
        w.bytes(key).bytes(value);
    }
}

fn decode_disk(r: &mut Reader<'_>) -> Disk {
    let n = r.count(1 << 16).expect("a record count");
    (0..n)
        .map(|_| {
            let key = r.bytes(1 << 16).expect("a key").to_vec();
            let value = r.bytes(1 << 24).expect("a value").to_vec();
            (key, value)
        })
        .collect()
}

struct Fixture {
    alice: Disk,
    bob: Disk,
    requests: Vec<(u64, Vec<u8>)>,
    now: u64,
}

fn load_fixture() -> Fixture {
    let bytes = std::fs::read(fixture_path()).expect("the fixture is committed");
    let mut r = Reader::new(&bytes);
    assert_eq!(&r.array::<8>().expect("magic"), FIXTURE_MAGIC);
    let now = r.u64().expect("time");
    let alice = decode_disk(&mut r);
    let bob = decode_disk(&mut r);
    let n = r.count(1 << 16).expect("a request count");
    let requests = (0..n)
        .map(|_| {
            let at = r.u64().expect("time");
            (at, r.bytes(1 << 24).expect("a frame").to_vec())
        })
        .collect();
    r.finish().expect("nothing after the requests");
    Fixture {
        alice,
        bob,
        requests,
        now,
    }
}

/// Writes the fixture: Alice and Bob talk, Alice rotates her keys, and Bob
/// queues a message he never sends.
#[test]
#[ignore = "writes the committed fixture; run at e99c043 for JSON-era records"]
fn regenerate_fixture() {
    let mut net = Net {
        mailbox: LocalMailbox::new(),
        requests: Vec::new(),
    };
    let mut now = 1_793_000_000_000;
    let new_device = |seed: u64, net: &mut Net| {
        let (client, step) = Client::create(CONFIG, Rand::seeded(seed), now);
        let mut device = Device {
            client,
            disk: Disk::new(),
            events: Vec::new(),
        };
        device.apply(net, now, step);
        device
    };
    let mut alice = new_device(1, &mut net);
    let mut bob = new_device(2, &mut net);
    settle(&mut [&mut alice, &mut bob], &mut net, &mut now);

    let card = bob.client.contact_card();
    let (conversation, step) = alice.client.start_conversation(now, card).expect("starts");
    alice.apply(&mut net, now, step);
    settle(&mut [&mut alice, &mut bob], &mut net, &mut now);
    let (_, step) = alice
        .client
        .send(now, conversation, "before the upgrade")
        .expect("sends");
    alice.apply(&mut net, now, step);
    settle(&mut [&mut alice, &mut bob], &mut net, &mut now);
    let (_, step) = bob
        .client
        .send(now, conversation, "a reply")
        .expect("sends");
    bob.apply(&mut net, now, step);
    let step = alice
        .client
        .update_keys(now, conversation)
        .expect("updates");
    alice.apply(&mut net, now, step);
    settle(&mut [&mut alice, &mut bob], &mut net, &mut now);
    assert_eq!(texts(&bob, conversation), ["before the upgrade"]);
    assert_eq!(texts(&alice, conversation), ["a reply"]);
    assert_eq!(
        alice.client.epoch(&conversation),
        bob.client.epoch(&conversation)
    );
    // Queued, persisted, never sent.
    let (_, step) = bob
        .client
        .send(now, conversation, "queued before the upgrade")
        .expect("queues");
    for (key, value) in step.writes {
        match value {
            Some(value) => bob.disk.insert(key, value),
            None => bob.disk.remove(&key),
        };
    }
    // The fixture exists to hold JSON; this build may not write it any more.
    for disk in [&alice.disk, &bob.disk] {
        assert!(
            mls_values(disk).all(|(_, value)| value.first() != Some(&BINARY)),
            "this build writes binary records: regenerate at e99c043"
        );
    }

    let mut w = Writer::new();
    w.array(FIXTURE_MAGIC).u64(now);
    encode_disk(&mut w, &alice.disk);
    encode_disk(&mut w, &bob.disk);
    w.count(net.requests.len());
    for (at, request) in &net.requests {
        w.u64(*at).bytes(request);
    }
    let path = fixture_path();
    std::fs::create_dir_all(path.parent().expect("a directory")).expect("creates");
    std::fs::write(&path, w.finish()).expect("writes the fixture");
}

#[test]
fn devices_restore_from_json_era_records() {
    let fixture = load_fixture();
    for disk in [&fixture.alice, &fixture.bob] {
        assert!(
            mls_values(disk).count() > 10,
            "the fixture holds OpenMLS state"
        );
        assert!(
            mls_values(disk).all(|(_, value)| value.first() != Some(&BINARY)),
            "the fixture is JSON-era"
        );
    }

    // The mailbox is a deterministic function of the requests it saw.
    let mut net = Net {
        mailbox: LocalMailbox::new(),
        requests: Vec::new(),
    };
    for (at, request) in &fixture.requests {
        drop(net.mailbox.handle(*at, request));
    }
    drop(net.mailbox.take_notifications());
    drop(net.mailbox.take_wakeups());

    let mut now = fixture.now + 60_000;
    let mut alice = Device::restore(fixture.alice, 11, now, &mut net);
    let mut bob = Device::restore(fixture.bob, 12, now, &mut net);
    let conversation = alice.client.conversations().next().expect("a conversation");
    assert!(alice.client.is_active(&conversation) && bob.client.is_active(&conversation));
    settle(&mut [&mut alice, &mut bob], &mut net, &mut now);
    assert_eq!(
        texts(&alice, conversation),
        ["queued before the upgrade"],
        "bob's queued message went out after the upgrade"
    );

    let (_, step) = alice
        .client
        .send(now, conversation, "after the upgrade")
        .expect("sends");
    alice.apply(&mut net, now, step);
    let step = bob.client.update_keys(now, conversation).expect("updates");
    bob.apply(&mut net, now, step);
    settle(&mut [&mut alice, &mut bob], &mut net, &mut now);
    assert_eq!(texts(&bob, conversation), ["after the upgrade"]);
    let (epoch, authenticator) = alice.client.epoch(&conversation).expect("a member");
    assert_eq!(
        bob.client.epoch(&conversation),
        Some((epoch, authenticator)),
        "both agree on the group after Bob's commit"
    );

    // What they wrote since is binary; the rest is still JSON. Both restart
    // from that mix.
    for device in [&alice, &bob] {
        assert!(mls_values(&device.disk).any(|(_, v)| v.first() == Some(&BINARY)));
        assert!(mls_values(&device.disk).any(|(_, v)| v.first() != Some(&BINARY)));
    }
    let mut alice = Device::restore(alice.disk, 21, now, &mut net);
    let mut bob = Device::restore(bob.disk, 22, now, &mut net);
    let (_, step) = bob
        .client
        .send(now, conversation, "after a second restart")
        .expect("sends");
    bob.apply(&mut net, now, step);
    let step = alice
        .client
        .update_keys(now, conversation)
        .expect("updates");
    alice.apply(&mut net, now, step);
    settle(&mut [&mut alice, &mut bob], &mut net, &mut now);
    assert_eq!(texts(&alice, conversation), ["after a second restart"]);
    assert_eq!(
        alice.client.epoch(&conversation),
        bob.client.epoch(&conversation)
    );
    assert!(alice.client.epoch(&conversation).expect("a member").0 > epoch);
}
