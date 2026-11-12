//! Linking a new device to an identity, and encrypted backups.
//!
//! **Linking.** The new device makes a secret and a fresh X-Wing key pair
//! (ML-KEM-768 with X25519), leaves the public key at a drop, and shows a
//! code: the secret and a hash of the key. An existing device of the identity
//! scans it, fetches the key, checks it against the hash, seals what the new
//! device needs (the identity's root key, among other things) to that key,
//! and leaves it at a second drop. The new device opens it, becomes a device
//! of the identity, and answers through a third drop with its contact card,
//! sealed under the same shared secret, so the existing device can add it to
//! every conversation.
//!
//! The drops (on the edge) only ever hold ciphertext and the public key.
//! Their addresses are derived from the secret, which travels only by camera
//! (or by hand): the server sees the drops but cannot seal a payload of its
//! own, since that needs the secret, and cannot swap the key, since the code
//! carries its hash. Sealing is post-quantum, so a payload recorded today
//! stays sealed against a future quantum computer.
//!
//! **Backups** are sealed under a key derived from a secret only the user's
//! passkey can produce (its PRF output), so the server that keeps them
//! learns nothing.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use krypt_wire::codec::{DecodeError, Reader, Writer};
use openmls_rust_crypto::RustCrypto;
use openmls_traits::crypto::OpenMlsCrypto as _;
use openmls_traits::types::{HpkeAeadType, HpkeConfig, HpkeKdfType, HpkeKemType};

use crate::identity::ContactCard;
use crate::provider::Rand;

/// Largest sealed payload: the identity, its other devices and the app's
/// own data (names of people and the like).
pub const LINK_PAYLOAD_MAX: usize = 192 * 1024;
/// Most devices one identity links.
pub const DEVICES_MAX: usize = 8;
/// Most contacts a backup carries.
pub const BACKUP_CONTACTS_MAX: usize = 4096;
/// An X-Wing public key, as left at the key drop.
pub const LINK_KEY_LEN: usize = 1216;
/// The X-Wing ciphertext that opens a sealed payload.
const ENC_LEN: usize = 1120;

const CODE_PREFIX: &str = "krypt-link2:";
/// The first version's codes (X25519), recognised only to say they are too
/// old to use.
const OLD_PREFIX: &str = "krypt-link:";
const TAG: usize = 16;
const EXPORT_CONTEXT: &[u8] = b"krypt link keys v2";

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum LinkError {
    #[error("not a link code")]
    BadCode,
    #[error("this code is from an older krypt: update krypt on both devices")]
    OldCode,
    #[error("the key left for this code does not match it")]
    WrongKey,
    #[error("the sealed data is damaged, or not for this device")]
    Corrupt,
    #[error("the payload exceeds its limit")]
    TooLarge,
}

/// What the new device shows: a secret (where the drops are, and part of
/// every key) and a hash of the public key to seal to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkCode {
    pub secret: [u8; 16],
    pub key_hash: [u8; 16],
}

impl LinkCode {
    pub fn to_text(&self) -> String {
        let bytes = [self.secret, self.key_hash].concat();
        format!(
            "{CODE_PREFIX}{}",
            data_encoding::BASE32_NOPAD.encode(&bytes).to_lowercase()
        )
    }

    pub fn from_text(text: &str) -> Result<LinkCode, LinkError> {
        let text = text.trim();
        let prefixed = |prefix: &str| {
            text.get(..prefix.len())
                .filter(|p| p.eq_ignore_ascii_case(prefix))
                .map(|_| &text[prefix.len()..])
        };
        let Some(body) = prefixed(CODE_PREFIX) else {
            return Err(if prefixed(OLD_PREFIX).is_some() {
                LinkError::OldCode
            } else {
                LinkError::BadCode
            });
        };
        let bytes = data_encoding::BASE32_NOPAD
            .decode(body.to_uppercase().as_bytes())
            .map_err(|_| LinkError::BadCode)?;
        if bytes.len() != 32 {
            return Err(LinkError::BadCode);
        }
        Ok(LinkCode {
            secret: bytes[..16].try_into().expect("16 bytes"),
            key_hash: bytes[16..].try_into().expect("16 bytes"),
        })
    }

    fn drop_for(&self, label: &[u8]) -> [u8; 16] {
        crate::hash16(&[label, &self.secret].concat())
    }

    /// Where the new device leaves its public key.
    pub fn key_drop(&self) -> [u8; 16] {
        self.drop_for(b"krypt link key v2")
    }

    /// Where the existing device leaves the sealed payload.
    pub fn drop(&self) -> [u8; 16] {
        self.drop_for(b"krypt link payload v2")
    }

    /// Where the new device answers.
    pub fn reply_drop(&self) -> [u8; 16] {
        self.drop_for(b"krypt link reply v2")
    }

    fn info(&self) -> Vec<u8> {
        [b"krypt link v2".as_slice(), &self.secret, &self.key_hash].concat()
    }
}

fn key_hash(public: &[u8]) -> [u8; 16] {
    blake3::derive_key("krypt link key hash v2", public)[..16]
        .try_into()
        .expect("16 bytes")
}

/// X-Wing, the KEM of krypt's MLS ciphersuite, already in the build.
fn config() -> HpkeConfig {
    HpkeConfig(
        HpkeKemType::XWingKemDraft6,
        HpkeKdfType::HkdfSha256,
        HpkeAeadType::ChaCha20Poly1305,
    )
}

/// Keys for both directions, from one encapsulation. Each is used once.
fn keys(exported: &[u8], enc: &[u8], code: &LinkCode) -> ([u8; 32], [u8; 32]) {
    let material = [exported, &code.secret, &code.key_hash, enc].concat();
    (
        blake3::derive_key("krypt link request v2", &material),
        blake3::derive_key("krypt link reply v2", &material),
    )
}

fn seal_once(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    // The key is used for exactly one message, so a fixed nonce is safe.
    ChaCha20Poly1305::new(key.into())
        .encrypt(&Nonce::default(), plaintext)
        .expect("a payload is far below ChaCha20's length limit")
}

fn open_once(key: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>, LinkError> {
    ChaCha20Poly1305::new(key.into())
        .decrypt(&Nonce::default(), sealed)
        .map_err(|_| LinkError::Corrupt)
}

/// The new device's side.
pub struct LinkInvite {
    private: Vec<u8>,
    public: Vec<u8>,
    pub code: LinkCode,
    reply_key: Option<[u8; 32]>,
}

/// Secrets stay out of debug output.
impl std::fmt::Debug for LinkInvite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkInvite")
            .field("code", &self.code)
            .finish_non_exhaustive()
    }
}

impl LinkInvite {
    pub fn new(rand: &Rand) -> LinkInvite {
        let pair = RustCrypto::default()
            .derive_hpke_keypair(config(), &rand.bytes::<32>())
            .expect("X-Wing derives a key pair from any seed");
        assert_eq!(pair.public.len(), LINK_KEY_LEN);
        LinkInvite {
            code: LinkCode {
                secret: rand.bytes(),
                key_hash: key_hash(&pair.public),
            },
            private: pair.private.to_vec(),
            public: pair.public,
            reply_key: None,
        }
    }

    /// The public key, to leave at the key drop before the code is shown.
    pub fn public_key(&self) -> &[u8] {
        &self.public
    }

    /// Opens what the existing device left at the drop.
    pub fn open(&mut self, sealed: &[u8]) -> Result<Vec<u8>, LinkError> {
        if sealed.len() < ENC_LEN + TAG || sealed.len() > ENC_LEN + LINK_PAYLOAD_MAX + TAG {
            return Err(LinkError::Corrupt);
        }
        let (enc, sealed) = sealed.split_at(ENC_LEN);
        let exported = RustCrypto::default()
            .hpke_setup_receiver_and_export(
                config(),
                enc,
                &self.private,
                &self.code.info(),
                EXPORT_CONTEXT,
                32,
            )
            .map_err(|_| LinkError::Corrupt)?;
        let (request, reply) = keys(&exported, enc, &self.code);
        let payload = open_once(&request, sealed)?;
        self.reply_key = Some(reply);
        Ok(payload)
    }

    /// Seals this device's answer (its contact card); only after `open`.
    pub fn reply(&self, card: &ContactCard) -> Vec<u8> {
        let key = self.reply_key.expect("opened the payload first");
        seal_once(&key, &card.encode())
    }
}

/// The existing device's side.
pub struct LinkOffer {
    reply_key: [u8; 32],
    pub code: LinkCode,
}

impl std::fmt::Debug for LinkOffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkOffer")
            .field("code", &self.code)
            .finish_non_exhaustive()
    }
}

impl LinkOffer {
    /// Seals `payload` for the device showing `code`, to `public_key` from
    /// its key drop, which must be the key the code names.
    pub fn seal(
        code: LinkCode,
        public_key: &[u8],
        payload: &[u8],
    ) -> Result<(LinkOffer, Vec<u8>), LinkError> {
        if public_key.len() != LINK_KEY_LEN || key_hash(public_key) != code.key_hash {
            return Err(LinkError::WrongKey);
        }
        if payload.len() > LINK_PAYLOAD_MAX {
            return Err(LinkError::TooLarge);
        }
        let (enc, exported) = RustCrypto::default()
            .hpke_setup_sender_and_export(config(), public_key, &code.info(), EXPORT_CONTEXT, 32)
            .map_err(|_| LinkError::WrongKey)?;
        assert_eq!(enc.len(), ENC_LEN);
        let (request, reply_key) = keys(&exported, &enc, &code);
        let mut sealed = enc;
        sealed.extend_from_slice(&seal_once(&request, payload));
        Ok((LinkOffer { reply_key, code }, sealed))
    }

    /// Opens the new device's answer: its contact card.
    pub fn open_reply(&self, sealed: &[u8]) -> Result<ContactCard, LinkError> {
        let card = open_once(&self.reply_key, sealed)?;
        ContactCard::decode(&card).map_err(|_| LinkError::Corrupt)
    }
}

/// What a linked device receives: the identity's root key, the identity's
/// other devices, and the app's own data (opaque here).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkPayload {
    pub identity_seed: [u8; 32],
    pub devices: Vec<ContactCard>,
    pub app: Vec<u8>,
}

const PAYLOAD_VERSION: u8 = 1;

impl LinkPayload {
    pub fn encode(&self) -> Vec<u8> {
        assert!(self.devices.len() <= DEVICES_MAX);
        let mut w = Writer::new();
        w.u8(PAYLOAD_VERSION)
            .array(&self.identity_seed)
            .count(self.devices.len());
        for device in &self.devices {
            w.bytes(&device.encode());
        }
        w.bytes(&self.app);
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<LinkPayload, DecodeError> {
        let mut r = Reader::new(bytes);
        if r.u8()? != PAYLOAD_VERSION {
            return Err(DecodeError::BadValue);
        }
        let identity_seed = r.array()?;
        let n = r.count(DEVICES_MAX)?;
        let mut devices = Vec::with_capacity(n);
        for _ in 0..n {
            devices.push(ContactCard::decode(r.bytes(64)?)?);
        }
        let app = r.bytes(LINK_PAYLOAD_MAX)?.to_vec();
        r.finish()?;
        Ok(LinkPayload {
            identity_seed,
            devices,
            app,
        })
    }
}

/// What a backup holds: the identity's root key, the people it talks to
/// (so a restored device can reach them again), and the app's own data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Backup {
    pub identity_seed: [u8; 32],
    pub contacts: Vec<ContactCard>,
    pub app: Vec<u8>,
}

const BACKUP_VERSION: u8 = 1;

impl Backup {
    pub fn encode(&self) -> Vec<u8> {
        assert!(self.contacts.len() <= BACKUP_CONTACTS_MAX);
        let mut w = Writer::new();
        w.u8(BACKUP_VERSION)
            .array(&self.identity_seed)
            .count(self.contacts.len());
        for contact in &self.contacts {
            w.bytes(&contact.encode());
        }
        w.bytes(&self.app);
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Backup, DecodeError> {
        let mut r = Reader::new(bytes);
        if r.u8()? != BACKUP_VERSION {
            return Err(DecodeError::BadValue);
        }
        let identity_seed = r.array()?;
        let n = r.count(BACKUP_CONTACTS_MAX)?;
        let mut contacts = Vec::with_capacity(n);
        for _ in 0..n {
            contacts.push(ContactCard::decode(r.bytes(64)?)?);
        }
        let app = r.bytes(LINK_PAYLOAD_MAX)?.to_vec();
        r.finish()?;
        Ok(Backup {
            identity_seed,
            contacts,
            app,
        })
    }

    /// Seals the backup under a passkey's PRF output (a random nonce: the
    /// key seals every new version of the backup).
    pub fn seal(&self, rand: &Rand, prf: &[u8; 32]) -> Vec<u8> {
        let key = blake3::derive_key("krypt backup v1", prf);
        let nonce: [u8; 12] = rand.bytes();
        let mut out = nonce.to_vec();
        out.extend(
            ChaCha20Poly1305::new((&key).into())
                .encrypt(&Nonce::from(nonce), self.encode().as_slice())
                .expect("a backup is far below ChaCha20's length limit"),
        );
        out
    }

    pub fn open(sealed: &[u8], prf: &[u8; 32]) -> Result<Backup, LinkError> {
        if sealed.len() < 12 + TAG {
            return Err(LinkError::Corrupt);
        }
        let key = blake3::derive_key("krypt backup v1", prf);
        let plain = ChaCha20Poly1305::new((&key).into())
            .decrypt(Nonce::from_slice(&sealed[..12]), &sealed[12..])
            .map_err(|_| LinkError::Corrupt)?;
        Backup::decode(&plain).map_err(|_| LinkError::Corrupt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_link_round_trip_and_its_failures() {
        let rand = Rand::seeded(1);
        let mut invite = LinkInvite::new(&rand);
        let code = LinkCode::from_text(&invite.code.to_text().to_uppercase()).unwrap();
        assert_eq!(code, invite.code);
        assert_eq!(invite.code.to_text().len(), "krypt-link2:".len() + 52);
        let payload = LinkPayload {
            identity_seed: [7; 32],
            devices: vec![ContactCard {
                identity: [1; 32],
                inbox: [2; 16],
            }],
            app: b"{\"people\":[]}".to_vec(),
        };
        // A key that is not the one the code names (left by someone else at
        // the key drop) is refused.
        let impostor = LinkInvite::new(&Rand::seeded(2));
        assert_eq!(
            LinkOffer::seal(code, impostor.public_key(), &payload.encode()).unwrap_err(),
            LinkError::WrongKey
        );
        let (offer, sealed) =
            LinkOffer::seal(code, invite.public_key(), &payload.encode()).unwrap();
        // Another device's key cannot open it, and damage is caught.
        let mut stranger = LinkInvite::new(&Rand::seeded(3));
        assert_eq!(stranger.open(&sealed), Err(LinkError::Corrupt));
        let mut damaged = sealed.clone();
        *damaged.last_mut().unwrap() ^= 1;
        assert_eq!(invite.open(&damaged), Err(LinkError::Corrupt));
        // Without the code's secret, the right key is not enough: a payload
        // sealed for another secret does not open.
        let other = LinkCode {
            secret: [9; 16],
            ..code
        };
        let (_, forged) = LinkOffer::seal(other, invite.public_key(), &payload.encode()).unwrap();
        assert_eq!(invite.open(&forged), Err(LinkError::Corrupt));
        let opened = invite.open(&sealed).unwrap();
        assert_eq!(LinkPayload::decode(&opened).unwrap(), payload);

        let card = ContactCard {
            identity: [1; 32],
            inbox: [9; 16],
        };
        assert_eq!(offer.open_reply(&invite.reply(&card)).unwrap(), card);
        let drops = [code.key_drop(), code.drop(), code.reply_drop()];
        assert!(drops[0] != drops[1] && drops[1] != drops[2] && drops[0] != drops[2]);
        assert!(
            !drops.contains(&code.secret),
            "drops do not reveal the secret"
        );
        assert_eq!(LinkCode::from_text("krypt:abc"), Err(LinkError::BadCode));
        assert_eq!(
            LinkCode::from_text("krypt-link2:abc"),
            Err(LinkError::BadCode)
        );
        assert_eq!(
            LinkCode::from_text(
                "krypt-link:ge2dgnbvgy3tqojqgezdgnbvgy3tqojqgezdgnbvgy3tqojqgezdgnbvgy3tqojq"
            ),
            Err(LinkError::OldCode)
        );
    }

    #[test]
    fn a_backup_opens_only_with_its_passkey() {
        let rand = Rand::seeded(3);
        let backup = Backup {
            identity_seed: [5; 32],
            contacts: vec![ContactCard {
                identity: [6; 32],
                inbox: [7; 16],
            }],
            app: vec![1, 2, 3],
        };
        let sealed = backup.seal(&rand, &[9; 32]);
        assert_eq!(Backup::open(&sealed, &[9; 32]).unwrap(), backup);
        assert_eq!(Backup::open(&sealed, &[8; 32]), Err(LinkError::Corrupt));
        assert_ne!(
            backup.seal(&rand, &[9; 32]),
            sealed,
            "a fresh nonce each time"
        );
    }
}
