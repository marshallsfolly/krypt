//! The little of WebAuthn the directory needs: checking that a passkey was
//! made, and later used, on krypt's own pages, for a challenge the directory
//! issued. Only ES256 (P-256) passkeys, which every platform authenticator
//! makes. Plain Rust, so it is tested natively.
//!
//! Registration takes the passkey's public key as the browser reports it
//! (`getPublicKey()`, SubjectPublicKeyInfo). Attestation is not checked:
//! whoever claims a handle may protect it with any key they hold, and the
//! claim is also signed by the identity the handle names.

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

/// The DER prefix of a P-256 SubjectPublicKeyInfo; the 65-byte uncompressed
/// point follows.
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];
const FLAG_USER_PRESENT: u8 = 0x01;
const FLAG_USER_VERIFIED: u8 = 0x04;
/// Largest clientDataJSON or authenticatorData accepted.
const PART_MAX: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WebAuthnError {
    Malformed,
    WrongType,
    WrongChallenge,
    WrongOrigin,
    WrongRelyingParty,
    NotVerified,
    BadSignature,
    Replayed,
}

/// Where krypt's pages are: the relying party id and the origins its
/// passkeys may be used from.
#[derive(Clone, Debug)]
pub struct RelyingParty {
    pub id: String,
    pub origins: Vec<String>,
}

#[derive(serde::Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    kind: String,
    challenge: String,
    origin: String,
}

/// Checks clientDataJSON and authenticatorData; returns the challenge used
/// and the authenticator's signature counter.
fn check(
    rp: &RelyingParty,
    kind: &str,
    client_data: &[u8],
    authenticator_data: &[u8],
) -> Result<([u8; 32], u32), WebAuthnError> {
    if client_data.len() > PART_MAX || authenticator_data.len() > PART_MAX {
        return Err(WebAuthnError::Malformed);
    }
    let data: ClientData =
        serde_json::from_slice(client_data).map_err(|_| WebAuthnError::Malformed)?;
    if data.kind != kind {
        return Err(WebAuthnError::WrongType);
    }
    if !rp.origins.contains(&data.origin) {
        return Err(WebAuthnError::WrongOrigin);
    }
    let challenge: [u8; 32] = data_encoding::BASE64URL_NOPAD
        .decode(data.challenge.as_bytes())
        .ok()
        .and_then(|c| c.try_into().ok())
        .ok_or(WebAuthnError::WrongChallenge)?;
    if authenticator_data.len() < 37 {
        return Err(WebAuthnError::Malformed);
    }
    if authenticator_data[..32] != *Sha256::digest(rp.id.as_bytes()) {
        return Err(WebAuthnError::WrongRelyingParty);
    }
    let flags = authenticator_data[32];
    if flags & FLAG_USER_PRESENT == 0 || flags & FLAG_USER_VERIFIED == 0 {
        return Err(WebAuthnError::NotVerified);
    }
    let counter = u32::from_be_bytes(authenticator_data[33..37].try_into().expect("4 bytes"));
    Ok((challenge, counter))
}

/// A passkey's public key from its SubjectPublicKeyInfo.
pub fn public_key(spki: &[u8]) -> Result<[u8; 65], WebAuthnError> {
    if spki.len() != P256_SPKI_PREFIX.len() + 65 || spki[..26] != P256_SPKI_PREFIX {
        return Err(WebAuthnError::Malformed);
    }
    let point: [u8; 65] = spki[26..].try_into().expect("65 bytes");
    VerifyingKey::from_sec1_bytes(&point).map_err(|_| WebAuthnError::Malformed)?;
    Ok(point)
}

/// A new passkey: returns the challenge it answered and its counter.
pub fn registration(
    rp: &RelyingParty,
    client_data: &[u8],
    authenticator_data: &[u8],
) -> Result<([u8; 32], u32), WebAuthnError> {
    check(rp, "webauthn.create", client_data, authenticator_data)
}

/// A passkey used: checks its signature with the key registered for it and
/// that its counter moved on (when it keeps one). Returns the challenge and
/// the new counter.
pub fn assertion(
    rp: &RelyingParty,
    key: &[u8; 65],
    counter: u32,
    client_data: &[u8],
    authenticator_data: &[u8],
    signature: &[u8],
) -> Result<([u8; 32], u32), WebAuthnError> {
    let (challenge, next) = check(rp, "webauthn.get", client_data, authenticator_data)?;
    let key = VerifyingKey::from_sec1_bytes(key).map_err(|_| WebAuthnError::Malformed)?;
    let signature = Signature::from_der(signature).map_err(|_| WebAuthnError::BadSignature)?;
    let signed = [authenticator_data, Sha256::digest(client_data).as_slice()].concat();
    key.verify(&signed, &signature)
        .map_err(|_| WebAuthnError::BadSignature)?;
    // Synced passkeys report zero; others must count up.
    if (next != 0 || counter != 0) && next <= counter {
        return Err(WebAuthnError::Replayed);
    }
    Ok((challenge, next))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::Signer;

    fn rp() -> RelyingParty {
        RelyingParty {
            id: "krypt.chat".to_owned(),
            origins: vec!["https://krypt.chat".to_owned()],
        }
    }

    fn client_data(kind: &str, challenge: &[u8; 32], origin: &str) -> Vec<u8> {
        format!(
            r#"{{"type":"{kind}","challenge":"{}","origin":"{origin}","crossOrigin":false}}"#,
            data_encoding::BASE64URL_NOPAD.encode(challenge)
        )
        .into_bytes()
    }

    fn authenticator_data(rp_id: &str, flags: u8, counter: u32) -> Vec<u8> {
        let mut data = Sha256::digest(rp_id.as_bytes()).to_vec();
        data.push(flags);
        data.extend_from_slice(&counter.to_be_bytes());
        data
    }

    #[test]
    fn a_passkey_is_registered_and_used() {
        let signing = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let point = signing.verifying_key().to_encoded_point(false);
        let spki = [P256_SPKI_PREFIX.as_slice(), point.as_bytes()].concat();
        let key = public_key(&spki).unwrap();
        assert!(public_key(&spki[1..]).is_err());

        let challenge = [3u8; 32];
        let created = client_data("webauthn.create", &challenge, "https://krypt.chat");
        let data = authenticator_data("krypt.chat", 0x45, 0);
        assert_eq!(registration(&rp(), &created, &data), Ok((challenge, 0)));
        // Made on another site, for another site, or without the user.
        let elsewhere = client_data("webauthn.create", &challenge, "https://evil.example");
        assert_eq!(
            registration(&rp(), &elsewhere, &data),
            Err(WebAuthnError::WrongOrigin)
        );
        let other_rp = authenticator_data("evil.example", 0x45, 0);
        assert_eq!(
            registration(&rp(), &created, &other_rp),
            Err(WebAuthnError::WrongRelyingParty)
        );
        let unverified = authenticator_data("krypt.chat", 0x01, 0);
        assert_eq!(
            registration(&rp(), &created, &unverified),
            Err(WebAuthnError::NotVerified)
        );

        let used = client_data("webauthn.get", &challenge, "https://krypt.chat");
        let data = authenticator_data("krypt.chat", 0x05, 8);
        let sign = |data: &[u8], client: &[u8]| -> Vec<u8> {
            let signed = [data, Sha256::digest(client).as_slice()].concat();
            let signature: Signature = signing.sign(&signed);
            signature.to_der().as_bytes().to_vec()
        };
        let signature = sign(&data, &used);
        assert_eq!(
            assertion(&rp(), &key, 7, &used, &data, &signature),
            Ok((challenge, 8))
        );
        // A replayed counter, another key, a creation presented as a use, or
        // a tampered challenge all fail.
        assert_eq!(
            assertion(&rp(), &key, 8, &used, &data, &signature),
            Err(WebAuthnError::Replayed)
        );
        let other = SigningKey::from_slice(&[8u8; 32]).unwrap();
        let other_key: [u8; 65] = other
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .try_into()
            .unwrap();
        assert_eq!(
            assertion(&rp(), &other_key, 0, &used, &data, &signature),
            Err(WebAuthnError::BadSignature)
        );
        assert_eq!(
            assertion(&rp(), &key, 0, &created, &data, &sign(&data, &created)),
            Err(WebAuthnError::WrongType)
        );
        let forged = client_data("webauthn.get", &[4u8; 32], "https://krypt.chat");
        assert_eq!(
            assertion(&rp(), &key, 0, &forged, &data, &signature),
            Err(WebAuthnError::BadSignature)
        );
        // Synced passkeys always report zero.
        let synced = authenticator_data("krypt.chat", 0x05, 0);
        assert_eq!(
            assertion(&rp(), &key, 0, &used, &synced, &sign(&synced, &used)),
            Ok((challenge, 0))
        );
    }
}
