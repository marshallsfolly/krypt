//! Scripts against the fixture's device: what the mailbox (or anyone
//! pretending to be it) sends, and what the device's user does.

use std::collections::BTreeMap;

use krypt_core::client::{Client, Config, Effect, Error, SharedFile, Step};
use krypt_core::provider::Rand;
use krypt_wire::frame::{self, Kind, Route};
use krypt_wire::limits::{FETCH_ENTRIES_MAX, FRAME_BODY_MAX};
use krypt_wire::msg::{Entries, Entry, Platform, PushTarget};

use crate::check::{self, Sent};
use crate::fixture::Fixture;
use crate::input::Input;

/// Every run restores the device with this seed, so request ids replay.
pub const SEED: u64 = 7;
/// Operations per script; enough to catch up, join, commit and send.
pub const OPS_MAX: usize = 64;
/// Recent requests a script can answer, newest first.
const SENT_MAX: usize = 256;

pub type Disk = BTreeMap<Vec<u8>, Vec<u8>>;

/// A device and its disk. Every step's writes are persisted, and every
/// request it emits is checked and remembered so a script can answer it.
#[derive(Debug)]
pub struct Device {
    pub client: Client,
    pub disk: Disk,
    pub sent: Vec<Sent>,
    pub now: u64,
    pub events: usize,
}

impl Device {
    pub fn restore(disk: Disk, now: u64) -> Result<Device, Error> {
        let (client, step) =
            Client::restore(Config::default(), Rand::seeded(SEED), disk.clone(), now)?;
        let mut device = Device {
            client,
            disk,
            sent: Vec::new(),
            now,
            events: 0,
        };
        device.absorb(step);
        Ok(device)
    }

    /// The fixture's device, restarted.
    pub fn from_fixture(fixture: &Fixture) -> Device {
        Device::restore(fixture.records.iter().cloned().collect(), fixture.now)
            .expect("the fixture restores")
    }

    pub fn absorb(&mut self, step: Step) {
        for (key, value) in step.writes {
            match value {
                Some(value) => self.disk.insert(key, value),
                None => self.disk.remove(&key),
            };
        }
        for effect in step.effects {
            match effect {
                Effect::Mailbox(request) => {
                    if self.sent.len() == SENT_MAX {
                        self.sent.remove(0);
                    }
                    self.sent.push(check::request(&request));
                }
                Effect::Event(_) => self.events += 1,
            }
        }
    }

    pub fn receive(&mut self, bytes: &[u8]) {
        let step = self.client.receive(self.now, bytes);
        self.absorb(step);
    }

    /// The `index`th most recent request, if any.
    pub fn request(&self, index: u8) -> Option<Sent> {
        let n = self.sent.len();
        (n > 0).then(|| self.sent[n - 1 - usize::from(index) % n])
    }

    /// Answers a recent request with a response of any kind.
    pub fn respond(&mut self, index: u8, kind: Kind, body: &[u8]) {
        if let Some(sent) = self.request(index) {
            self.receive(&frame::encode_vec(kind, sent.seq, sent.route, body));
        }
    }

    pub fn tick(&mut self, by_ms: u64) {
        self.now += by_ms;
        let step = self.client.tick(self.now);
        self.absorb(step);
    }

    /// Whatever the device was fed, it can restart from what it persisted.
    pub fn check_restart(&self) {
        let restarted = Device::restore(self.disk.clone(), self.now);
        if let Err(e) = restarted {
            panic!("the device cannot restart from what it persisted: {e}");
        }
    }

    /// Where a recent request went, by its kind.
    pub fn find(&self, kind: Kind, route: Option<Route>) -> Option<u8> {
        let n = self.sent.len();
        (0..n.min(256))
            .find(|&i| {
                let sent = self.sent[n - 1 - i];
                sent.kind == kind && route.is_none_or(|r| r == sent.route)
            })
            .map(|i| u8::try_from(i).expect("below 256"))
    }
}

/// The operations of a `client_receive` script, by their first byte
/// (modulo 8).
pub mod op {
    /// `index, kind, body`: a response to a recent request.
    pub const RESPOND: u8 = 0;
    /// `index, extra, count, picks`: entries from the stash, in answer to a
    /// recent request (a fetch, usually).
    pub const RESPOND_STASH: u8 = 1;
    /// `route, body`: a push.
    pub const NOTIFY: u8 = 2;
    /// `route, extra, count, picks`: a push of stash entries.
    pub const NOTIFY_STASH: u8 = 3;
    /// `count, unit`: time passes, `count` (a `u16`) tenths of a second,
    /// seconds, minutes or hours.
    pub const TICK: u8 = 4;
    /// `bytes`: a frame as is, checksums and all.
    pub const RAW: u8 = 5;
    /// `call, conversation`: the user does something.
    pub const API: u8 = 6;
    /// `index`: the contact's key package, in answer to a recent request.
    pub const RESPOND_KEY_PACKAGE: u8 = 7;
}

/// Response kinds, by their selector byte (modulo 4).
pub const RESPONSES: [Kind; 4] = [
    Kind::Accepted,
    Kind::Rejected,
    Kind::Entries,
    Kind::KeyPackage,
];

/// API calls, by their selector byte (modulo 8).
pub mod api {
    pub const SEND: u8 = 0;
    pub const UPDATE: u8 = 1;
    pub const INVITE: u8 = 2;
    pub const REMOVE: u8 = 3;
    pub const POLL: u8 = 4;
    pub const PUSH_TARGET: u8 = 5;
    pub const FILE_AUTH: u8 = 6;
    pub const SEND_FILE: u8 = 7;
}

/// Routes by selector byte (modulo 4): the inbox, the two conversations, or
/// 16 bytes from the script.
fn route(fixture: &Fixture, sel: u8, input: &mut Input) -> Route {
    match sel % 4 {
        0 => fixture.inbox,
        1 => fixture.conversations[0],
        2 => fixture.conversations[1],
        _ => input.array(),
    }
}

/// An `Entries` body of the picked stash entries: deduplicated, in order,
/// within a frame. `next` is one past the last, plus `extra`.
pub fn stash_entries(fixture: &Fixture, picks: &[u8], extra: u8) -> Vec<u8> {
    let mut picked: Vec<_> = picks
        .iter()
        .map(|&i| &fixture.stash[usize::from(i) % fixture.stash.len()])
        .collect();
    picked.sort_by_key(|e| e.seq);
    picked.dedup_by_key(|e| e.seq);
    picked.truncate(FETCH_ENTRIES_MAX as usize);
    let mut size = Entries::EMPTY_SIZE;
    let mut entries = Vec::new();
    for e in picked {
        size += Entries::entry_size(e.data.len());
        if size > FRAME_BODY_MAX as usize {
            break;
        }
        entries.push(Entry {
            seq: e.seq,
            data: &e.data,
        });
    }
    let next = entries.last().map_or(1, |e| e.seq + 1) + u64::from(extra);
    Entries { next, entries }.encode()
}

fn stash_picks<'a>(input: &mut Input<'a>) -> (u8, &'a [u8]) {
    let extra = input.u8();
    let count = input.u8() % (FETCH_ENTRIES_MAX as u8 + 1);
    (extra, input.bytes(usize::from(count)))
}

fn api(fixture: &Fixture, device: &mut Device, call: u8, sel: u8) {
    let conversation = fixture.conversations[usize::from(sel) % fixture.conversations.len()];
    let now = device.now;
    let client = &mut device.client;
    let step = match call % 8 {
        api::SEND => client.send(now, conversation, "fuzz").map(|(_, step)| step),
        api::UPDATE => client.update_keys(now, conversation),
        api::INVITE => client.invite(now, conversation, fixture.contact),
        api::REMOVE => client.remove(now, conversation, fixture.peer),
        api::POLL => Ok(client.poll_now(now)),
        api::PUSH_TARGET => {
            let target = PushTarget {
                platform: Platform::WebPush,
                address: b"https://fcm.googleapis.com/fcm/send/fuzz",
            };
            Ok(client.set_push_target(now, sel.is_multiple_of(2).then_some(target)))
        }
        api::FILE_AUTH => {
            let (id, _) = client.new_file();
            drop(client.file_auth(conversation, id, u32::from(sel), 1 << 20));
            return;
        }
        _ => {
            let (id, key) = client.new_file();
            let file = SharedFile {
                id,
                key,
                size: 1 << 20,
                name: "fuzz.jpg".to_owned(),
                media_type: "image/jpeg".to_owned(),
                width: 1,
                height: 1,
                thumbnail: vec![sel; usize::from(sel)],
            };
            client
                .send_file(now, conversation, file)
                .map(|(_, step)| step)
        }
    };
    if let Ok(step) = step {
        device.absorb(step);
    }
}

/// Runs one `client_receive` script.
pub fn run(fixture: &Fixture, device: &mut Device, input: &mut Input) {
    for _ in 0..OPS_MAX {
        if input.is_empty() {
            break;
        }
        match input.u8() % 8 {
            op::RESPOND => {
                let index = input.u8();
                let kind = RESPONSES[usize::from(input.u8() % 4)];
                let body = input.chunk();
                device.respond(index, kind, body);
            }
            op::RESPOND_STASH => {
                let index = input.u8();
                let (extra, picks) = stash_picks(input);
                let body = stash_entries(fixture, picks, extra);
                device.respond(index, Kind::Entries, &body);
            }
            op::NOTIFY => {
                let sel = input.u8();
                let route = route(fixture, sel, input);
                let body = input.chunk();
                device.receive(&frame::encode_vec(Kind::Notify, 0, route, body));
            }
            op::NOTIFY_STASH => {
                let sel = input.u8();
                let route = route(fixture, sel, input);
                let (extra, picks) = stash_picks(input);
                let body = stash_entries(fixture, picks, extra);
                device.receive(&frame::encode_vec(Kind::Notify, 0, route, &body));
            }
            op::TICK => {
                let count = u64::from(input.u16());
                device.tick(count * [100, 1_000, 60_000, 3_600_000][usize::from(input.u8() % 4)]);
            }
            op::RAW => {
                let bytes = input.chunk();
                device.receive(bytes);
            }
            op::API => {
                let (call, sel) = (input.u8(), input.u8());
                api(fixture, device, call, sel);
            }
            _ => {
                let index = input.u8();
                device.respond(index, Kind::KeyPackage, &fixture.key_package);
            }
        }
    }
}

/// The operations of a `client_restore` script, by their first byte
/// (modulo 8). Each names a record by index (modulo the count).
pub mod edit {
    /// `record`
    pub const DELETE: u8 = 0;
    /// `record, value`
    pub const REPLACE: u8 = 1;
    /// `record, offset (u32), mask`
    pub const XOR: u8 = 2;
    /// `record, length (u32)`
    pub const TRUNCATE: u8 = 3;
    /// `key, value`
    pub const INSERT: u8 = 4;
    /// `record, key`
    pub const RENAME: u8 = 5;
    /// `record, from record`: one record's value in another.
    pub const COPY: u8 = 6;
    /// `record, offset (u32), u64`: a little-endian integer written over.
    pub const WRITE_U64: u8 = 7;
}

/// Edits the fixture's records as a `client_restore` script says.
pub fn edit(fixture: &Fixture, input: &mut Input) -> Disk {
    let mut records = fixture.records.clone();
    for _ in 0..OPS_MAX {
        if input.is_empty() {
            break;
        }
        let op = input.u8() % 8;
        if op == edit::INSERT {
            let key = input.chunk().to_vec();
            records.push((key, input.chunk().to_vec()));
            continue;
        }
        if records.is_empty() {
            break;
        }
        let i = usize::from(input.u8()) % records.len();
        let len = records[i].1.len();
        let at = |offset: u32| usize::try_from(offset).unwrap_or(0) % len.max(1);
        match op {
            edit::DELETE => {
                records.remove(i);
            }
            edit::REPLACE => records[i].1 = input.chunk().to_vec(),
            edit::XOR => {
                let (offset, mask) = (at(input.u32()), input.u8() | 1);
                if let Some(byte) = records[i].1.get_mut(offset) {
                    *byte ^= mask;
                }
            }
            edit::TRUNCATE => {
                let keep = at(input.u32());
                records[i].1.truncate(keep);
            }
            edit::RENAME => records[i].0 = input.chunk().to_vec(),
            edit::COPY => {
                let from = usize::from(input.u8()) % records.len();
                records[i].1 = records[from].1.clone();
            }
            _ => {
                let (offset, value) = (at(input.u32()), input.u64().to_le_bytes());
                let value = &value[..value.len().min(len - offset.min(len))];
                records[i].1[offset..offset + value.len()].copy_from_slice(value);
            }
        }
    }
    records.into_iter().collect()
}

/// Restarts a device from edited records. If it comes up, it reads every
/// log it follows from the stash and runs for a day, so whatever it loaded
/// is put to use.
pub fn restore_and_run(fixture: &Fixture, disk: Disk) {
    let Ok(mut device) = Device::restore(disk, fixture.now) else {
        return;
    };
    for conversation in &fixture.conversations {
        let _ = device.client.epoch(conversation);
        let _ = device.client.members(conversation);
        let _ = device.client.describe(conversation);
    }
    let fetches: Vec<_> = device
        .sent
        .iter()
        .filter(|s| s.kind == Kind::Fetch)
        .copied()
        .collect();
    for sent in fetches {
        let picks: Vec<u8> = fixture
            .log(&sent.route)
            .filter_map(|(i, _)| u8::try_from(i).ok())
            .collect();
        let body = stash_entries(fixture, &picks, 0);
        device.receive(&frame::encode_vec(
            Kind::Entries,
            sent.seq,
            sent.route,
            &body,
        ));
    }
    device.tick(krypt_wire::limits::DAY_MS);
}
