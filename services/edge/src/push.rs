//! Web Push wakeups (RFC 8030), identified with VAPID (RFC 8292).
//!
//! A wakeup carries no payload: the device's service worker shows a
//! content-free notification and the app fetches when opened. So nothing
//! is encrypted here, and push services learn only that something happened.
//!
//! Endpoints must belong to a known browser push service: a member could
//! otherwise make the mailbox send requests to any URL it likes.

use data_encoding::BASE64URL_NOPAD;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

/// Whom push services may contact about this sender.
const SUBJECT: &str = "https://krypt.chat";
/// How long a token is valid; push services accept at most 24 hours.
pub const TOKEN_LIFETIME_S: u64 = 12 * 60 * 60;
/// How long a push service keeps an undelivered wakeup (a phone off for a
/// day still learns there is something new).
pub const TTL_S: u64 = 24 * 60 * 60;

/// Push service hosts, by suffix: Chrome and most Chromium browsers (FCM),
/// Firefox, Safari, and Edge (WNS).
const SERVICES: &[&str] = &[
    "fcm.googleapis.com",
    "push.services.mozilla.com",
    "push.apple.com",
    "notify.windows.com",
];

pub struct Vapid {
    key: SigningKey,
    /// The public key as sent in `k=`: the uncompressed point, base64url.
    public: String,
}

impl std::fmt::Debug for Vapid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vapid")
            .field("public", &self.public)
            .finish()
    }
}

impl Vapid {
    /// From the private scalar, base64url (the `VAPID_PRIVATE_KEY` secret).
    pub fn from_secret(secret: &str) -> Option<Vapid> {
        let bytes = BASE64URL_NOPAD.decode(secret.trim().as_bytes()).ok()?;
        let key = SigningKey::from_slice(&bytes).ok()?;
        let point = VerifyingKey::from(&key).to_encoded_point(false);
        Some(Vapid {
            key,
            public: BASE64URL_NOPAD.encode(point.as_bytes()),
        })
    }

    /// The `Authorization` header for pushes to `audience` (a push
    /// service's origin), valid until `expires_s` (Unix seconds).
    pub fn authorization(&self, audience: &str, expires_s: u64) -> String {
        let header = BASE64URL_NOPAD.encode(br#"{"typ":"JWT","alg":"ES256"}"#);
        let claims = serde_json::json!({ "aud": audience, "exp": expires_s, "sub": SUBJECT });
        let claims = BASE64URL_NOPAD.encode(claims.to_string().as_bytes());
        let signed = format!("{header}.{claims}");
        let signature: Signature = self.key.sign(signed.as_bytes());
        let signature = BASE64URL_NOPAD.encode(&signature.to_bytes());
        format!("vapid t={signed}.{signature}, k={}", self.public)
    }
}

/// A push endpoint we send to: the URL to send to and its origin (the
/// token's audience), or `None`. Parsed as `fetch` parses it (WHATWG), and
/// the parsed URL is what is sent to, so what is checked is what is
/// contacted. `local` also admits http://127.0.0.1 and localhost, for tests.
pub fn endpoint(endpoint: &str, local: bool) -> Option<(String, String)> {
    let url = url::Url::parse(endpoint).ok()?;
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return None;
    }
    let url::Host::Domain(host) = url.host()? else {
        // An address: only the local test one.
        return (local
            && url.scheme() == "http"
            && url.host() == Some(url::Host::Ipv4([127, 0, 0, 1].into())))
        .then(|| (url.to_string(), url.origin().ascii_serialization()));
    };
    let known = SERVICES
        .iter()
        .any(|s| host == *s || host.ends_with(&format!(".{s}")));
    let test = local && host == "localhost";
    let allowed = match url.scheme() {
        "https" => (known && url.port().is_none()) || test,
        "http" => test,
        _ => false,
    };
    allowed.then(|| (url.to_string(), url.origin().ascii_serialization()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier;

    #[test]
    fn only_push_services_are_contacted() {
        let audience = |e: &str, local: bool| endpoint(e, local).map(|(_, origin)| origin);
        let fcm = "https://fcm.googleapis.com/fcm/send/abc:def";
        assert_eq!(
            audience(fcm, false).as_deref(),
            Some("https://fcm.googleapis.com")
        );
        assert_eq!(
            endpoint(fcm, false).map(|(url, _)| url).as_deref(),
            Some(fcm)
        );
        let apple = "https://web.push.apple.com/QGx";
        assert_eq!(
            audience(apple, false).as_deref(),
            Some("https://web.push.apple.com")
        );
        let mozilla = "https://updates.push.services.mozilla.com/wpush/v2/x";
        assert_eq!(
            audience(mozilla, false).as_deref(),
            Some("https://updates.push.services.mozilla.com")
        );
        let windows = "https://wns2-par02p.notify.windows.com/w/?token=BQYAAA";
        assert_eq!(
            audience(windows, false).as_deref(),
            Some("https://wns2-par02p.notify.windows.com")
        );
        for bad in [
            // Each reads as a push service to a naive split, but `fetch`
            // goes to evil.example.
            "https://evil.example?.fcm.googleapis.com",
            "https://evil.example#.fcm.googleapis.com",
            "https://evil.example\\.fcm.googleapis.com/x",
            "https://fcm.googleapis.com@evil.example/x",
            "https://user:pw@fcm.googleapis.com/x",
            "https://fcm.googleapis.com/x#frag",
            "https://fcm.googleapis.com:8443/x",
            "https://evil.example/fcm.googleapis.com",
            "https://fcm.googleapis.com.evil.example/x",
            "https://evilfcm.googleapis.com.example/x",
            "http://fcm.googleapis.com/x",
            "http://127.0.0.1:9000/push",
            "ftp://fcm.googleapis.com/x",
            "fcm.googleapis.com",
        ] {
            assert_eq!(audience(bad, false), None, "{bad}");
        }
        assert_eq!(
            audience("http://127.0.0.1:9000/push", true).as_deref(),
            Some("http://127.0.0.1:9000")
        );
    }

    /// Checks the deployed key pair: `sops exec-env secrets/push.yaml
    /// 'cargo test -p krypt-edge -- --ignored'`.
    #[test]
    #[ignore = "needs the VAPID keys in the environment"]
    fn configured_keys_match() {
        let private = std::env::var("VAPID_PRIVATE_KEY").expect("VAPID_PRIVATE_KEY");
        let public = std::env::var("VAPID_PUBLIC_KEY").expect("VAPID_PUBLIC_KEY");
        let vapid = Vapid::from_secret(&private).expect("a P-256 private key");
        assert!(
            vapid.public == public,
            "the private key does not match the public key"
        );
    }

    #[test]
    fn tokens_verify_with_the_public_key() {
        let secret = BASE64URL_NOPAD.encode(&[7u8; 32]);
        let vapid = Vapid::from_secret(&secret).unwrap();
        let header = vapid.authorization("https://fcm.googleapis.com", 1_900_000_000);
        let (token, public) = header
            .strip_prefix("vapid t=")
            .and_then(|rest| rest.split_once(", k="))
            .unwrap();
        let (signed, signature) = token.rsplit_once('.').unwrap();
        let claims = BASE64URL_NOPAD
            .decode(signed.split('.').nth(1).unwrap().as_bytes())
            .unwrap();
        assert_eq!(
            std::str::from_utf8(&claims).unwrap(),
            r#"{"aud":"https://fcm.googleapis.com","exp":1900000000,"sub":"https://krypt.chat"}"#
        );
        let key =
            VerifyingKey::from_sec1_bytes(&BASE64URL_NOPAD.decode(public.as_bytes()).unwrap())
                .unwrap();
        let signature =
            Signature::from_slice(&BASE64URL_NOPAD.decode(signature.as_bytes()).unwrap()).unwrap();
        key.verify(signed.as_bytes(), &signature).unwrap();
    }
}
