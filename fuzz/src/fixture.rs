//! The client fixture: a device in two real conversations, and the log
//! entries meant for it that it has not read yet.

use std::sync::OnceLock;

use krypt_core::identity::{ContactCard, IdentityKey};
use krypt_wire::Route;
use krypt_wire::codec::{DecodeError, Reader, Writer};

pub const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/client.bin");
const MAGIC: &[u8; 8] = b"krypt-f1";
const LIST_MAX: usize = 1 << 12;
const VALUE_MAX: usize = 1 << 24;

/// A log entry from one of the device's logs.
#[derive(Clone, Debug)]
pub struct Stashed {
    pub route: Route,
    pub seq: u64,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Fixture {
    /// When the device stopped; it restarts here.
    pub now: u64,
    /// Its disk, in key order.
    pub records: Vec<(Vec<u8>, Vec<u8>)>,
    pub inbox: Route,
    /// The conversation it is in, then the one it is invited to.
    pub conversations: Vec<Route>,
    /// Every entry of its inbox and both conversation logs.
    pub stash: Vec<Stashed>,
    /// A member of both conversations.
    pub peer: IdentityKey,
    /// Someone the device has asked to add, and a real key package of theirs.
    pub contact: ContactCard,
    pub key_package: Vec<u8>,
}

impl Fixture {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.array(MAGIC).u64(self.now).count(self.records.len());
        for (key, value) in &self.records {
            w.bytes(key).bytes(value);
        }
        w.array(&self.inbox).count(self.conversations.len());
        for route in &self.conversations {
            w.array(route);
        }
        w.count(self.stash.len());
        for entry in &self.stash {
            w.array(&entry.route).u64(entry.seq).bytes(&entry.data);
        }
        w.array(&self.peer)
            .bytes(&self.contact.encode())
            .bytes(&self.key_package);
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Fixture, DecodeError> {
        let mut r = Reader::new(bytes);
        if &r.array::<8>()? != MAGIC {
            return Err(DecodeError::BadValue);
        }
        let now = r.u64()?;
        let mut records = Vec::new();
        for _ in 0..r.count(LIST_MAX)? {
            records.push((r.bytes(VALUE_MAX)?.to_vec(), r.bytes(VALUE_MAX)?.to_vec()));
        }
        let inbox = r.array()?;
        let mut conversations = Vec::new();
        for _ in 0..r.count(LIST_MAX)? {
            conversations.push(r.array()?);
        }
        let mut stash = Vec::new();
        for _ in 0..r.count(LIST_MAX)? {
            stash.push(Stashed {
                route: r.array()?,
                seq: r.u64()?,
                data: r.bytes(VALUE_MAX)?.to_vec(),
            });
        }
        let peer = r.array()?;
        let contact = ContactCard::decode(r.bytes(VALUE_MAX)?)?;
        let key_package = r.bytes(VALUE_MAX)?.to_vec();
        r.finish()?;
        Ok(Fixture {
            now,
            records,
            inbox,
            conversations,
            stash,
            peer,
            contact,
            key_package,
        })
    }

    /// The committed fixture, read once per process.
    pub fn get() -> &'static Fixture {
        static FIXTURE: OnceLock<Fixture> = OnceLock::new();
        FIXTURE.get_or_init(|| {
            let bytes = std::fs::read(PATH)
                .unwrap_or_else(|e| panic!("{PATH}: {e} (write it with `just fuzz-fixture`)"));
            let fixture = Fixture::decode(&bytes).expect("the fixture decodes");
            assert!(fixture.conversations.len() == 2 && !fixture.stash.is_empty());
            fixture
        })
    }

    /// The stash entries of one log, in order.
    pub fn log(&self, route: &Route) -> impl Iterator<Item = (usize, &Stashed)> {
        self.stash
            .iter()
            .enumerate()
            .filter(move |(_, e)| e.route == *route)
    }
}
