//! Identities, device certificates, contact cards, fingerprints and safety
//! numbers.
//!
//! An identity is a long-term Ed25519 root key that lives only on the user's
//! devices. Each device gets a certificate, signed by the root, binding the
//! device's MLS signature key, its device id and its inbox. The
//! certificate is the MLS credential, so every group member can check that a
//! leaf really belongs to the identity it claims.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use krypt_wire::Route;
use krypt_wire::codec::{DecodeError, Reader, Writer};

/// An identity's public root key.
pub type IdentityKey = [u8; 32];

/// A device's id: 32 random bytes chosen when the device is created.
pub type DeviceId = [u8; 32];

#[derive(Clone)]
pub struct Identity {
    root: SigningKey,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("public", &fingerprint(&self.public()))
            .finish()
    }
}

impl Identity {
    pub fn from_seed(seed: [u8; 32]) -> Identity {
        Identity {
            root: SigningKey::from_bytes(&seed),
        }
    }

    pub fn seed(&self) -> [u8; 32] {
        self.root.to_bytes()
    }

    pub fn public(&self) -> IdentityKey {
        self.root.verifying_key().to_bytes()
    }

    /// Signs on behalf of this identity (e.g. proving inbox ownership).
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.root.sign(message).to_bytes()
    }

    pub fn certify(
        &self,
        mls_signature_key: [u8; 32],
        device: DeviceId,
        inbox: Route,
    ) -> DeviceCert {
        let mut cert = DeviceCert {
            identity: self.public(),
            mls_signature_key,
            device,
            inbox,
            signature: [0; 64],
        };
        cert.signature = self.root.sign(&cert.signed_bytes()).to_bytes();
        cert
    }
}

/// Whether `signature` is `identity`'s over `message`.
pub fn verify(identity: &IdentityKey, message: &[u8], signature: &[u8; 64]) -> bool {
    VerifyingKey::from_bytes(identity).is_ok_and(|key| {
        key.verify_strict(message, &Signature::from_bytes(signature))
            .is_ok()
    })
}

/// Binds a device's MLS signature key, id and inbox to an identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceCert {
    pub identity: IdentityKey,
    pub mls_signature_key: [u8; 32],
    pub device: DeviceId,
    pub inbox: Route,
    pub signature: [u8; 64],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CertError {
    #[error("certificate is malformed")]
    Malformed,
    #[error("certificate signature is invalid")]
    BadSignature,
}

impl From<DecodeError> for CertError {
    fn from(_: DecodeError) -> CertError {
        CertError::Malformed
    }
}

const CERT_CONTEXT: &[u8] = b"krypt device certificate v1";
const CERT_VERSION: u8 = 1;
pub const CERT_SIZE: usize = 1 + 32 + 32 + 32 + 16 + 64;

impl DeviceCert {
    fn signed_bytes(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(CERT_CONTEXT.len() + 112);
        w.array(&self.identity)
            .array(&self.mls_signature_key)
            .array(&self.device)
            .array(&self.inbox);
        let mut out = CERT_CONTEXT.to_vec();
        out.extend_from_slice(&w.finish());
        out
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(CERT_SIZE);
        w.u8(CERT_VERSION)
            .array(&self.identity)
            .array(&self.mls_signature_key)
            .array(&self.device)
            .array(&self.inbox)
            .array(&self.signature);
        w.finish()
    }

    /// Decodes a certificate and verifies its signature.
    pub fn decode(bytes: &[u8]) -> Result<DeviceCert, CertError> {
        let mut r = Reader::new(bytes);
        if r.u8()? != CERT_VERSION {
            return Err(CertError::Malformed);
        }
        let cert = DeviceCert {
            identity: r.array()?,
            mls_signature_key: r.array()?,
            device: r.array()?,
            inbox: r.array()?,
            signature: r.array()?,
        };
        r.finish()?;
        let root = VerifyingKey::from_bytes(&cert.identity).map_err(|_| CertError::Malformed)?;
        root.verify_strict(
            &cert.signed_bytes(),
            &Signature::from_bytes(&cert.signature),
        )
        .map_err(|_| CertError::BadSignature)?;
        Ok(cert)
    }
}

/// What two people exchange out of band (a QR code or link) to start talking.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ContactCard {
    pub identity: IdentityKey,
    pub inbox: Route,
}

const CARD_VERSION: u8 = 1;

impl ContactCard {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(49);
        w.u8(CARD_VERSION).array(&self.identity).array(&self.inbox);
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<ContactCard, DecodeError> {
        let mut r = Reader::new(bytes);
        if r.u8()? != CARD_VERSION {
            return Err(DecodeError::BadValue);
        }
        let card = ContactCard {
            identity: r.array()?,
            inbox: r.array()?,
        };
        r.finish()?;
        Ok(card)
    }

    /// The card as text to paste or put in a link: `krypt:` and lowercase
    /// base32, which survives being read aloud, typed and URL-encoded.
    pub fn to_text(&self) -> String {
        format!(
            "{CARD_PREFIX}{}",
            data_encoding::BASE32_NOPAD
                .encode(&self.encode())
                .to_lowercase()
        )
    }

    /// Parses [`ContactCard::to_text`]'s output, ignoring surrounding space
    /// and case.
    pub fn from_text(text: &str) -> Option<ContactCard> {
        let text = text.trim();
        let body = text
            .get(..CARD_PREFIX.len())
            .filter(|prefix| prefix.eq_ignore_ascii_case(CARD_PREFIX))
            .map(|_| &text[CARD_PREFIX.len()..])?;
        let bytes = data_encoding::BASE32_NOPAD
            .decode(body.to_ascii_uppercase().as_bytes())
            .ok()?;
        ContactCard::decode(&bytes).ok()
    }
}

const CARD_PREFIX: &str = "krypt:";

/// Short human-readable identity fingerprint: four groups of four hex digits.
pub fn fingerprint(identity: &IdentityKey) -> String {
    let hash = blake3::hash(identity);
    let b = hash.as_bytes();
    format!(
        "{:02X}{:02X} {:02X}{:02X} {:02X}{:02X} {:02X}{:02X}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]
    )
}

/// Iterations make finding an identity key with a chosen safety number
/// expensive, as in Signal's numeric fingerprints.
const SAFETY_ITERATIONS: usize = 5200;

fn safety_half(identity: &IdentityKey) -> [u32; 6] {
    let mut hash = *blake3::Hasher::new()
        .update(b"krypt safety number v1")
        .update(identity)
        .finalize()
        .as_bytes();
    for _ in 0..SAFETY_ITERATIONS {
        hash = *blake3::Hasher::new()
            .update(&hash)
            .update(identity)
            .finalize()
            .as_bytes();
    }
    let mut groups = [0u32; 6];
    for (i, group) in groups.iter_mut().enumerate() {
        let chunk = &hash[i * 5..i * 5 + 5];
        let value = chunk
            .iter()
            .fold(0u64, |acc, &byte| (acc << 8) | u64::from(byte));
        *group = u32::try_from(value % 100_000).expect("below 100000");
    }
    groups
}

/// The 60-digit safety number two identities compare to rule out a
/// machine-in-the-middle. Both sides compute the same twelve groups.
pub fn safety_number(a: &IdentityKey, b: &IdentityKey) -> [u32; 12] {
    let (first, second) = if a <= b { (a, b) } else { (b, a) };
    let mut out = [0u32; 12];
    out[..6].copy_from_slice(&safety_half(first));
    out[6..].copy_from_slice(&safety_half(second));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificate_roundtrip_and_tamper_detection() {
        let identity = Identity::from_seed([1; 32]);
        let cert = identity.certify([2; 32], [3; 32], [4; 16]);
        let bytes = cert.encode();
        assert_eq!(bytes.len(), CERT_SIZE);
        assert_eq!(DeviceCert::decode(&bytes).unwrap(), cert);

        for i in 1..bytes.len() {
            let mut tampered = bytes.clone();
            tampered[i] ^= 0x01;
            assert!(
                DeviceCert::decode(&tampered).is_err(),
                "tamper at byte {i} accepted"
            );
        }
    }

    #[test]
    fn certificate_from_another_identity_is_rejected() {
        let alice = Identity::from_seed([1; 32]);
        let mallory = Identity::from_seed([9; 32]);
        let mut cert = mallory.certify([2; 32], [3; 32], [4; 16]);
        cert.identity = alice.public();
        assert_eq!(
            DeviceCert::decode(&cert.encode()),
            Err(CertError::BadSignature)
        );
    }

    #[test]
    fn safety_number_is_symmetric_and_distinct() {
        let a = Identity::from_seed([1; 32]).public();
        let b = Identity::from_seed([2; 32]).public();
        let c = Identity::from_seed([3; 32]).public();
        assert_eq!(safety_number(&a, &b), safety_number(&b, &a));
        assert_ne!(safety_number(&a, &b), safety_number(&a, &c));
        assert!(safety_number(&a, &b).iter().all(|&g| g < 100_000));
    }

    #[test]
    fn fingerprint_format() {
        let fp = fingerprint(&[0; 32]);
        assert_eq!(fp.len(), 19);
        assert_eq!(fp.matches(' ').count(), 3);
    }

    #[test]
    fn contact_card_text_roundtrip() {
        let card = ContactCard {
            identity: [3; 32],
            inbox: [4; 16],
        };
        let text = card.to_text();
        assert!(text.starts_with("krypt:"));
        assert_eq!(ContactCard::from_text(&text), Some(card));
        assert_eq!(
            ContactCard::from_text(&format!("  {}\n", text.to_uppercase())),
            Some(card)
        );
        assert_eq!(ContactCard::from_text("krypt:"), None);
        assert_eq!(ContactCard::from_text(&text[..text.len() - 2]), None);
        assert_eq!(ContactCard::from_text("hello"), None);
    }

    #[test]
    fn contact_card_roundtrip() {
        let card = ContactCard {
            identity: [5; 32],
            inbox: [6; 16],
        };
        assert_eq!(ContactCard::decode(&card.encode()).unwrap(), card);
    }
}
