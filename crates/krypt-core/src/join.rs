//! Invite links (decision 52): anyone with a group's link may *ask* to join;
//! an admin approves each request.
//!
//! An admin makes a link seed (kept in the group's rules, so the group's
//! other members and admins have it). From the seed and the group's id (so
//! the same seed in another group is another link) come:
//!
//! - `join` (16 bytes), which the link carries: the token a request must
//!   show, and the key the group's name is sealed under, come from it.
//! - An X-Wing key pair: requests are sealed to its public key, so neither
//!   the server nor other people with the link can read them. The link
//!   carries a hash of it.
//! - An admin key (Ed25519). The requests log's route is a hash of its
//!   public key, which the mailbox checks: only that key opens the log and
//!   writes its header (the public key, and the group's name), so nobody
//!   else can take the log over, even once it has lapsed. The link carries
//!   the route.
//!
//! A request carries the person's card, their name, a one-time key package
//! (never published), when it was made, and a signature by that device's key
//! over all of it and the link, so nobody can ask in someone else's name or
//! replay an old request for long. An admin approves by adding exactly that
//! key package.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::Signer as _;
use krypt_wire::codec::{DecodeError, Reader, Writer};
use krypt_wire::frame::{self, Kind, Route};
use krypt_wire::limits::{JOIN_HEADER_MAX, JOIN_REQUEST_MAX};
use krypt_wire::msg::{JoinRequest, OpenRequests};
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls_rust_crypto::RustCrypto;
use openmls_traits::crypto::OpenMlsCrypto as _;
use openmls_traits::types::{HpkeAeadType, HpkeCiphertext, HpkeConfig, HpkeKdfType, HpkeKemType};

use crate::identity::ContactCard;
use crate::provider::Rand;

/// A name someone gives when asking to join.
pub const JOIN_NAME_MAX: usize = 64;
const KEY_LEN: usize = 1216;
const NONCE: usize = 12;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum JoinError {
    #[error("not an invite link")]
    BadLink,
    #[error("this invite link no longer works")]
    WrongKey,
    #[error("the request is damaged, or not for this group")]
    Corrupt,
}

fn config() -> HpkeConfig {
    HpkeConfig(
        HpkeKemType::XWingKemDraft6,
        HpkeKdfType::HkdfSha256,
        HpkeAeadType::ChaCha20Poly1305,
    )
}

/// Everything about a link comes from its seed and its group.
fn base_of(seed: &[u8; 32], group: &[u8]) -> [u8; 32] {
    blake3::derive_key("krypt join v2", &[seed.as_slice(), group].concat())
}

/// The `join` a link seed gives in a group (without deriving its keys).
pub fn join_of(seed: &[u8; 32], group: &[u8]) -> [u8; 16] {
    blake3::derive_key("krypt join v2 join", &base_of(seed, group))[..16]
        .try_into()
        .expect("16 bytes")
}

/// A requests log's route: from the key that owns it, so the mailbox can
/// check that whoever opens it holds that key.
pub fn requests_route(admin: &[u8; 32]) -> Route {
    crate::hash16(&[b"krypt join log v2".as_slice(), admin].concat())
}

fn key_hash(public: &[u8]) -> [u8; 16] {
    blake3::derive_key("krypt join key hash v1", public)[..16]
        .try_into()
        .expect("16 bytes")
}

/// What an invite link carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JoinCode {
    /// The requests log ([`requests_route`] of the admin key).
    pub route: Route,
    pub join: [u8; 16],
    pub key_hash: [u8; 16],
}

impl JoinCode {
    /// The link's code, as it follows `#join=` in a URL.
    pub fn to_text(&self) -> String {
        data_encoding::BASE32_NOPAD
            .encode(&[self.route, self.join, self.key_hash].concat())
            .to_lowercase()
    }

    pub fn from_text(text: &str) -> Result<JoinCode, JoinError> {
        let bytes = data_encoding::BASE32_NOPAD
            .decode(text.trim().to_uppercase().as_bytes())
            .map_err(|_| JoinError::BadLink)?;
        if bytes.len() != 48 {
            return Err(JoinError::BadLink);
        }
        Ok(JoinCode {
            route: bytes[..16].try_into().expect("16 bytes"),
            join: bytes[16..32].try_into().expect("16 bytes"),
            key_hash: bytes[32..].try_into().expect("16 bytes"),
        })
    }

    /// The requests log's route.
    pub fn route(&self) -> Route {
        self.route
    }

    /// What a request must show the mailbox.
    pub fn token(&self) -> [u8; 16] {
        blake3::derive_key("krypt join v2 token", &self.join)[..16]
            .try_into()
            .expect("16 bytes")
    }

    fn name_key(&self) -> [u8; 32] {
        blake3::derive_key("krypt join v2 name", &self.join)
    }

    fn info(&self) -> Vec<u8> {
        [
            b"krypt join v2".as_slice(),
            &self.route,
            &self.join,
            &self.key_hash,
        ]
        .concat()
    }

    /// The request that fetches the log's header.
    pub fn header_frame(&self) -> Vec<u8> {
        frame::encode_vec(Kind::JoinHeader, 1, self.route(), &[])
    }

    /// The header: the key requests are sealed to, which must be the one
    /// the link names, and the group's name.
    pub fn read_header(&self, header: &[u8]) -> Result<Header, JoinError> {
        let mut r = Reader::new(header);
        let public = r.bytes(KEY_LEN).map_err(|_| JoinError::Corrupt)?.to_vec();
        let sealed = r.bytes(JOIN_HEADER_MAX).map_err(|_| JoinError::Corrupt)?;
        r.finish().map_err(|_| JoinError::Corrupt)?;
        if public.len() != KEY_LEN || key_hash(&public) != self.key_hash {
            return Err(JoinError::WrongKey);
        }
        if sealed.len() < NONCE {
            return Err(JoinError::Corrupt);
        }
        let (nonce, ciphertext) = sealed.split_at(NONCE);
        let name = ChaCha20Poly1305::new(&self.name_key().into())
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .ok()
            .and_then(|name| String::from_utf8(name).ok())
            .ok_or(JoinError::Corrupt)?;
        Ok(Header { public, name })
    }

    /// A request to join (with its signature already made), sealed to the
    /// header's key, as the frame that leaves it at the requests log.
    pub fn request_frame(&self, header: &Header, request: &Request) -> Vec<u8> {
        let ciphertext = RustCrypto::default()
            .hpke_seal(
                config(),
                &header.public,
                &self.info(),
                &self.route(),
                &request.encode(),
            )
            .expect("X-Wing seals to a key the link names");
        let sealed = ciphertext
            .tls_serialize_detached()
            .expect("a ciphertext serializes");
        assert!(sealed.len() <= JOIN_REQUEST_MAX);
        let body = JoinRequest {
            token: self.token(),
            sealed: &sealed,
        }
        .encode();
        frame::encode_vec(Kind::JoinRequest, 1, self.route(), &body)
    }

    /// What a requester's device signs: everything in the request, and the
    /// link it is for.
    pub fn signed_bytes(
        &self,
        card: &ContactCard,
        name: &str,
        key_package: &[u8],
        at_ms: u64,
    ) -> Vec<u8> {
        let mut w = Writer::new();
        w.array(b"krypt join request v2")
            .array(&self.route)
            .array(&self.join)
            .array(&self.key_hash)
            .bytes(&card.encode())
            .bytes(name.as_bytes())
            .array(blake3::hash(key_package).as_bytes())
            .u64(at_ms);
        w.finish()
    }
}

/// A requests log's header, as read with the link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub public: Vec<u8>,
    /// The group's name (empty: none).
    pub name: String,
}

/// A request to join, as sealed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub card: ContactCard,
    pub name: String,
    /// A one-time key package of the requesting device, never published.
    pub key_package: Vec<u8>,
    /// When it was made (by the requester's clock): an old one is refused.
    pub at_ms: u64,
    /// By the device's MLS key, over [`JoinCode::signed_bytes`].
    pub signature: [u8; 64],
}

impl Request {
    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&self.card.encode())
            .bytes(self.name.as_bytes())
            .bytes(&self.key_package)
            .u64(self.at_ms)
            .array(&self.signature);
        w.finish()
    }

    fn decode(bytes: &[u8]) -> Result<Request, DecodeError> {
        let mut r = Reader::new(bytes);
        let card = ContactCard::decode(r.bytes(256)?)?;
        let name = String::from_utf8(r.bytes(JOIN_NAME_MAX)?.to_vec())
            .map_err(|_| DecodeError::BadValue)?;
        let key_package = r.bytes(JOIN_REQUEST_MAX)?.to_vec();
        let at_ms = r.u64()?;
        let signature = r.array()?;
        r.finish()?;
        Ok(Request {
            card,
            name,
            key_package,
            at_ms,
            signature,
        })
    }
}

/// An admin's side of a link: everything derived from its seed (in its
/// group).
pub struct LinkKeys {
    pub code: JoinCode,
    private: Vec<u8>,
    public: Vec<u8>,
    admin: ed25519_dalek::SigningKey,
}

impl std::fmt::Debug for LinkKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkKeys")
            .field("code", &self.code)
            .finish_non_exhaustive()
    }
}

impl LinkKeys {
    pub fn from_seed(seed: &[u8; 32], group: &[u8]) -> LinkKeys {
        let base = base_of(seed, group);
        let pair = RustCrypto::default()
            .derive_hpke_keypair(config(), &blake3::derive_key("krypt join v2 seal", &base))
            .expect("X-Wing derives a key pair from any seed");
        let admin = ed25519_dalek::SigningKey::from_bytes(&blake3::derive_key(
            "krypt join v2 admin",
            &base,
        ));
        LinkKeys {
            code: JoinCode {
                route: requests_route(&admin.verifying_key().to_bytes()),
                join: join_of(seed, group),
                key_hash: key_hash(&pair.public),
            },
            private: pair.private.to_vec(),
            public: pair.public,
            admin,
        }
    }

    /// The body of an `OpenRequests` (to the code's route) that opens, or
    /// keeps open, the requests log, with the group's name in its header.
    pub fn open_body(&self, rand: &Rand, group_name: &str) -> Vec<u8> {
        let nonce: [u8; NONCE] = rand.bytes();
        let sealed_name = ChaCha20Poly1305::new(&self.code.name_key().into())
            .encrypt(Nonce::from_slice(&nonce), group_name.as_bytes())
            .expect("a name is far below ChaCha20's length limit");
        let mut w = Writer::new();
        w.bytes(&self.public)
            .bytes(&[nonce.as_slice(), &sealed_name].concat());
        let header = w.finish();
        let route = self.code.route();
        let admin = self.admin.verifying_key().to_bytes();
        let token = self.code.token();
        let signature = self
            .admin
            .sign(&OpenRequests::signed_bytes(&route, &admin, &token, &header))
            .to_bytes();
        OpenRequests {
            admin,
            token,
            header: &header,
            signature,
        }
        .encode()
    }

    /// Opens a request left at the log. Who sent it is checked by the
    /// caller, against its key package.
    pub fn open(&self, sealed: &[u8]) -> Result<Request, JoinError> {
        let ciphertext =
            HpkeCiphertext::tls_deserialize_exact(sealed).map_err(|_| JoinError::Corrupt)?;
        let plain = RustCrypto::default()
            .hpke_open(
                config(),
                &ciphertext,
                &self.private,
                &self.code.info(),
                &self.code.route(),
            )
            .map_err(|_| JoinError::Corrupt)?;
        Request::decode(&plain).map_err(|_| JoinError::Corrupt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_reaches_only_the_links_admins() {
        let keys = LinkKeys::from_seed(&[4; 32], b"group");
        let code = JoinCode::from_text(&keys.code.to_text()).expect("parses");
        assert_eq!(code, keys.code);
        // The header, as the mailbox would hand it out.
        let open = keys.open_body(&Rand::seeded(1), "Climbing");
        let open = OpenRequests::decode(&open).expect("decodes");
        let header = code.read_header(open.header).expect("reads");
        assert_eq!(header.name, "Climbing");
        let request = Request {
            card: ContactCard {
                identity: [1; 32],
                inbox: [2; 16],
            },
            name: "Dana".into(),
            key_package: vec![9; 1500],
            at_ms: 7,
            signature: [3; 64],
        };
        let sent = code.request_frame(&header, &request);
        let sent = frame::decode(&sent).expect("a frame");
        let sent = JoinRequest::decode(sent.body).expect("decodes");
        assert_eq!(sent.token, code.token());
        assert_eq!(keys.open(sent.sealed), Ok(request));
        // Another link's keys cannot read it.
        assert!(
            LinkKeys::from_seed(&[5; 32], b"group")
                .open(sent.sealed)
                .is_err()
        );
        // A header with another key is refused: the link names its key.
        let other = LinkKeys::from_seed(&[6; 32], b"group").open_body(&Rand::seeded(2), "x");
        let other = OpenRequests::decode(&other).expect("decodes");
        assert_eq!(code.read_header(other.header), Err(JoinError::WrongKey));
        assert!(JoinCode::from_text("nonsense").is_err());
    }

    #[test]
    fn a_link_belongs_to_one_group_and_one_admin_key() {
        // The same seed in another group is another link altogether.
        let ours = LinkKeys::from_seed(&[4; 32], b"group");
        let lookalike = LinkKeys::from_seed(&[4; 32], b"other group");
        assert_ne!(ours.code.join, lookalike.code.join);
        assert_ne!(ours.code.route, lookalike.code.route);
        assert_eq!(join_of(&[4; 32], b"group"), ours.code.join);
        // The route is the admin key's, as the mailbox checks it.
        let open = ours.open_body(&Rand::seeded(1), "Climbing");
        let open = OpenRequests::decode(&open).expect("decodes");
        assert_eq!(requests_route(&open.admin), ours.code.route);
    }
}
