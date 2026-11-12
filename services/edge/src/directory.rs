//! The directory: @handles and drops, one Durable Object each.
//!
//! A **handle** is a name pointing at a contact card, so people can start a
//! chat by typing `@name` instead of pasting a card. It is claimed with a
//! passkey (only its holder can change or release it) and a signature by
//! the identity the card names (nobody can point a handle at someone else).
//! It can also keep a backup sealed under a key only the passkey produces;
//! the backup is replaced with a token the device holds, and read back only
//! with the passkey.
//!
//! A **drop** is a one-time slot for linking a device: one sealed payload,
//! read once, gone after ten minutes. Drop ids are random and secret.
//!
//! Lookups are rate limited per address: handles can be guessed, so the
//! directory must not become a cheap way to list who uses krypt.

use std::cell::Cell;

use krypt_core::client::handle_signed_bytes;
use krypt_core::identity::{ContactCard, verify};
use krypt_core::provider::Rand;
use krypt_wire::codec::{Reader, Writer};
use worker::{
    DurableObject, Env, Method, Request, RequestInit, Response, Result, SqlStorageValue, State,
    durable_object,
};

use crate::webauthn::{self, RelyingParty};
use crate::{allowed, now_ms};

const BINDING: &str = "DIRECTORY";
const HANDLE_RATE_BINDING: &str = "HANDLES_PER_IP";
const DROP_RATE_BINDING: &str = "DROPS_PER_IP";
/// Where passkeys are used: the relying party id and its origins (comma
/// separated). Vars, so `wrangler dev` can use localhost.
const RP_ID_VAR: &str = "RP_ID";
const ORIGINS_VAR: &str = "ORIGINS";

pub const HANDLE_MIN: usize = 3;
pub const HANDLE_MAX: usize = 24;
/// Largest sealed backup.
const BACKUP_MAX: usize = 256 * 1024;
/// Largest drop.
const DROP_MAX: usize = 256 * 1024;
const DROP_TTL_MS: u64 = 10 * 60 * 1000;
/// How long a challenge lasts. Challenges are stateless (a nonce, its
/// expiry and a MAC), so asking for one writes nothing and nobody can crowd
/// out someone else's; used ones are remembered (after a passkey or identity
/// signature checked out) until they expire.
const CHALLENGE_TTL_MS: u64 = 5 * 60 * 1000;
const USED_CHALLENGES_MAX: usize = 16;
/// The challenge MAC key comes from this secret (with its own label).
const CHALLENGE_SECRET: &str = "VAPID_PRIVATE_KEY";
const CREDENTIAL_ID_MAX: usize = 1024;
const JSON_MAX: usize = 16 * 1024;

/// Names nobody may claim: they would let someone pose as krypt.
const RESERVED: [&str; 12] = [
    "admin",
    "administrator",
    "help",
    "krypt",
    "kryptchat",
    "moderator",
    "official",
    "root",
    "security",
    "staff",
    "support",
    "system",
];

/// A handle as stored: lowercase letters, digits and underscores, not
/// starting with an underscore. `None` if it cannot be one.
pub fn normalize(handle: &str) -> Option<String> {
    let handle = handle.trim().trim_start_matches('@').to_ascii_lowercase();
    let valid = (HANDLE_MIN..=HANDLE_MAX).contains(&handle.len())
        && handle
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        && !handle.starts_with('_')
        && !RESERVED.contains(&handle.as_str());
    valid.then_some(handle)
}

fn b64(bytes: &[u8]) -> String {
    data_encoding::BASE64URL_NOPAD.encode(bytes)
}

fn unb64(text: &str) -> Option<Vec<u8>> {
    data_encoding::BASE64URL_NOPAD.decode(text.as_bytes()).ok()
}

/// Equal, in time that does not depend on where they differ.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn json(value: &serde_json::Value, status: u16) -> Result<Response> {
    Ok(Response::from_json(value)?.with_status(status))
}

/// Routes `/v1/handle/…` and `/v1/drop/…`; `None` for any other path.
pub async fn route(request: Request, env: &Env, path: &str) -> Option<Result<Response>> {
    if let Some(rest) = path.strip_prefix("/v1/handle/") {
        return Some(handle_route(request, env, rest).await);
    }
    if let Some(id) = path.strip_prefix("/v1/drop/") {
        return Some(drop_route(request, env, id).await);
    }
    None
}

async fn forward(env: &Env, name: &str, action: &str, request: Request) -> Result<Response> {
    let mut init = RequestInit::new();
    init.with_method(request.method());
    let headers = worker::Headers::new();
    if let Some(token) = request.headers().get("krypt-backup-token")? {
        headers.set("krypt-backup-token", &token)?;
    }
    init.with_headers(headers);
    let mut request = request;
    if request.method() != Method::Get {
        init.with_body(Some(request.bytes().await?.into()));
    }
    let inner = Request::new_with_init(&format!("https://directory/{action}"), &init)?;
    env.durable_object(BINDING)?
        .get_by_name(name)?
        .fetch_with_request(inner)
        .await
}

async fn handle_route(request: Request, env: &Env, rest: &str) -> Result<Response> {
    if !allowed(env, &request, HANDLE_RATE_BINDING).await? {
        return Response::error("slow down", 429);
    }
    let (name, action) = rest.split_once('/').unwrap_or((rest, ""));
    let Some(handle) = normalize(name) else {
        return Response::error("not a handle", 400);
    };
    let action = match (request.method(), action) {
        (Method::Get, "") => "get",
        (Method::Post, "challenge") => "challenge",
        (Method::Post, "claim") => "claim",
        (Method::Post, "restore") => "restore",
        (Method::Post, "release") => "release",
        (Method::Post, "card") => "card",
        (Method::Put, "backup") => "backup",
        _ => return Response::error("not found", 404),
    };
    forward(
        env,
        &format!("h:{handle}"),
        &format!("{action}?h={handle}"),
        request,
    )
    .await
}

async fn drop_route(request: Request, env: &Env, id: &str) -> Result<Response> {
    if !allowed(env, &request, DROP_RATE_BINDING).await? {
        return Response::error("slow down", 429);
    }
    if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Response::error("bad drop", 400);
    }
    let action = match request.method() {
        Method::Put => "put",
        Method::Get => "take",
        _ => return Response::error("not found", 404),
    };
    forward(
        env,
        &format!("d:{}", id.to_ascii_lowercase()),
        action,
        request,
    )
    .await
}

/// What a handle holds.
struct Record {
    card: ContactCard,
    credential: Vec<u8>,
    key: [u8; 65],
    counter: u32,
    /// BLAKE3 of the token that may replace the backup.
    token: [u8; 32],
}

const RECORD_VERSION: u8 = 1;

impl Record {
    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(RECORD_VERSION)
            .bytes(&self.card.encode())
            .bytes(&self.credential)
            .array(&self.key)
            .u32(self.counter)
            .array(&self.token);
        w.finish()
    }

    fn decode(bytes: &[u8]) -> Option<Record> {
        let mut r = Reader::new(bytes);
        (r.u8().ok()? == RECORD_VERSION).then_some(())?;
        let record = Record {
            card: ContactCard::decode(r.bytes(64).ok()?).ok()?,
            credential: r.bytes(CREDENTIAL_ID_MAX).ok()?.to_vec(),
            key: r.array().ok()?,
            counter: r.u32().ok()?,
            token: r.array().ok()?,
        };
        r.finish().ok()?;
        Some(record)
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct Claim {
    card: String,
    credential_id: String,
    public_key: String,
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    authenticator_data: String,
    identity_signature: String,
    backup_token: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct Assertion {
    credential_id: String,
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    authenticator_data: String,
    signature: String,
    /// Restore: the new device's card, signed by the same identity, and its
    /// backup token.
    card: Option<String>,
    identity_signature: Option<String>,
    backup_token: Option<String>,
}

/// A device of the handle's identity pointing the handle at its own card
/// (a restored or new device), signed by the identity, not the passkey.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct CardUpdate {
    card: String,
    challenge: String,
    identity_signature: String,
    backup_token: Option<String>,
}

#[durable_object]
#[allow(missing_debug_implementations)] // holds JavaScript objects
pub struct Directory {
    state: State,
    env: Env,
    ready: Cell<bool>,
}

impl Directory {
    /// Whether the table exists, creating it if `create`. Reading never
    /// creates it: looking up a handle or a drop leaves no storage behind.
    fn table(&self, create: bool) -> Result<bool> {
        if self.ready.get() {
            return Ok(true);
        }
        let sql = self.state.storage().sql();
        let exists = sql
            .exec(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'kv'",
                None,
            )?
            .raw()
            .next()
            .is_some();
        if !exists && !create {
            return Ok(false);
        }
        if !exists {
            sql.exec(
                "CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v BLOB NOT NULL)",
                None,
            )?;
        }
        self.ready.set(true);
        Ok(true)
    }

    fn sql(
        &self,
        query: &str,
        bindings: Vec<SqlStorageValue>,
    ) -> Result<Vec<Vec<SqlStorageValue>>> {
        self.table(true)?;
        self.state
            .storage()
            .sql()
            .exec(query, bindings)?
            .raw()
            .collect()
    }

    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        if !self.table(false)? {
            return Ok(None);
        }
        let rows = self.sql("SELECT v FROM kv WHERE k = ?", vec![key.into()])?;
        Ok(rows
            .into_iter()
            .next()
            .and_then(|row| match row.into_iter().next() {
                Some(SqlStorageValue::Blob(bytes)) => Some(bytes),
                _ => None,
            }))
    }

    fn put(&self, key: &str, value: Vec<u8>) -> Result<()> {
        self.sql(
            "INSERT OR REPLACE INTO kv (k, v) VALUES (?, ?)",
            vec![key.into(), SqlStorageValue::Blob(value)],
        )?;
        Ok(())
    }

    fn rp(&self) -> RelyingParty {
        let var = |name: &str, default: &str| {
            self.env
                .var(name)
                .map_or_else(|_| default.to_owned(), |v| v.to_string())
        };
        RelyingParty {
            id: var(RP_ID_VAR, "krypt.chat"),
            origins: var(ORIGINS_VAR, "https://krypt.chat")
                .split(',')
                .map(|o| o.trim().to_owned())
                .collect(),
        }
    }

    /// The key challenges are MACed with: from a deployed secret, or (when
    /// there is none, as in some local runs) one kept by this object.
    fn challenge_key(&self) -> Result<[u8; 32]> {
        if let Ok(secret) = self.env.secret(CHALLENGE_SECRET) {
            return Ok(blake3::derive_key(
                "krypt directory challenges v1",
                secret.to_string().as_bytes(),
            ));
        }
        if let Some(key) = self.get("challenge_key")?.and_then(|k| k.try_into().ok()) {
            return Ok(key);
        }
        let key: [u8; 32] = Rand::os().bytes();
        self.put("challenge_key", key.to_vec())?;
        Ok(key)
    }

    /// A challenge: nonce (8), expiry (8, little-endian), MAC (16) over
    /// both and the handle.
    fn mac(&self, handle: &str, nonce: &[u8], expires: &[u8]) -> Result<[u8; 16]> {
        let key = self.challenge_key()?;
        let input = [
            b"krypt challenge v1".as_slice(),
            handle.as_bytes(),
            b"\0",
            nonce,
            expires,
        ]
        .concat();
        Ok(blake3::keyed_hash(&key, &input).as_bytes()[..16]
            .try_into()
            .expect("16 bytes"))
    }

    /// Challenges used already (until they expire): (challenge, expiry).
    fn used(&self) -> Result<Vec<([u8; 32], u64)>> {
        let now = now_ms();
        let Some(bytes) = self.get("used")? else {
            return Ok(Vec::new());
        };
        let mut r = Reader::new(&bytes);
        let mut out = Vec::new();
        let n = r.count(USED_CHALLENGES_MAX).unwrap_or(0);
        for _ in 0..n {
            let (Ok(challenge), Ok(expires)) = (r.array::<32>(), r.u64()) else {
                break;
            };
            if expires > now {
                out.push((challenge, expires));
            }
        }
        Ok(out)
    }

    /// Whether `challenge` was issued for `handle`, is current, and is unused.
    fn fresh(&self, handle: &str, challenge: &[u8; 32]) -> Result<bool> {
        let (nonce, rest) = challenge.split_at(8);
        let (expires, mac) = rest.split_at(8);
        let at = u64::from_le_bytes(expires.try_into().expect("8 bytes"));
        if at <= now_ms() || at > now_ms() + CHALLENGE_TTL_MS {
            return Ok(false);
        }
        let expected = self.mac(handle, nonce, expires)?;
        if !ct_eq(&expected, mac) {
            return Ok(false);
        }
        Ok(!self.used()?.iter().any(|(c, _)| c == challenge))
    }

    /// Records `challenge` as used. Called only once a signature over it
    /// checked out, so only the handle's owner ever writes here.
    fn spend(&self, challenge: &[u8; 32]) -> Result<()> {
        let mut used = self.used()?;
        if used.len() == USED_CHALLENGES_MAX {
            used.remove(0);
        }
        let expires = u64::from_le_bytes(challenge[8..16].try_into().expect("8 bytes"));
        used.push((*challenge, expires));
        let mut w = Writer::new();
        w.count(used.len());
        for (challenge, expires) in &used {
            w.array(challenge).u64(*expires);
        }
        self.put("used", w.finish())
    }

    fn record(&self) -> Result<Option<Record>> {
        Ok(self.get("record")?.and_then(|bytes| Record::decode(&bytes)))
    }

    async fn body<T: serde::de::DeserializeOwned>(request: &mut Request) -> Option<T> {
        let bytes = request.bytes().await.ok()?;
        (bytes.len() <= JSON_MAX).then_some(())?;
        serde_json::from_slice(&bytes).ok()
    }

    fn challenge(&self, handle: &str) -> Result<Response> {
        let nonce: [u8; 8] = Rand::os().bytes();
        let expires = (now_ms() + CHALLENGE_TTL_MS).to_le_bytes();
        let mac = self.mac(handle, &nonce, &expires)?;
        let challenge = [nonce.as_slice(), &expires, &mac].concat();
        json(&serde_json::json!({ "challenge": b64(&challenge) }), 200)
    }

    async fn claim(&self, handle: &str, mut request: Request) -> Result<Response> {
        if self.record()?.is_some() {
            return Response::error("taken", 409);
        }
        let Some(claim) = Self::body::<Claim>(&mut request).await else {
            return Response::error("malformed claim", 400);
        };
        let (
            Some(card),
            Some(credential),
            Some(spki),
            Some(client),
            Some(data),
            Some(signature),
            Some(token),
        ) = (
            ContactCard::from_text(&claim.card),
            unb64(&claim.credential_id).filter(|c| !c.is_empty() && c.len() <= CREDENTIAL_ID_MAX),
            unb64(&claim.public_key),
            unb64(&claim.client_data_json),
            unb64(&claim.authenticator_data),
            unb64(&claim.identity_signature).and_then(|s| <[u8; 64]>::try_from(s).ok()),
            unb64(&claim.backup_token).and_then(|t| <[u8; 32]>::try_from(t).ok()),
        )
        else {
            return Response::error("malformed claim", 400);
        };
        let Ok(key) = webauthn::public_key(&spki) else {
            return Response::error("only P-256 passkeys", 400);
        };
        let (challenge, counter) = match webauthn::registration(&self.rp(), &client, &data) {
            Ok(checked) => checked,
            Err(e) => return Response::error(format!("passkey refused: {e:?}"), 403),
        };
        if !self.fresh(handle, &challenge)? {
            return Response::error("stale challenge", 409);
        }
        if !verify(
            &card.identity,
            &handle_signed_bytes(handle, &card, &challenge),
            &signature,
        ) {
            return Response::error("not signed by the card's identity", 403);
        }
        self.spend(&challenge)?;
        let record = Record {
            card,
            credential,
            key,
            counter,
            token: *blake3::hash(&token).as_bytes(),
        };
        self.put("record", record.encode())?;
        Response::empty().map(|r| r.with_status(201))
    }

    /// Checks a passkey assertion against the record; the record with its
    /// counter moved on, or the response refusing it.
    async fn assert(
        &self,
        handle: &str,
        request: &mut Request,
    ) -> Result<std::result::Result<(Record, Assertion, [u8; 32]), Response>> {
        let Some(mut record) = self.record()? else {
            return Ok(Err(Response::error("no such handle", 404)?));
        };
        let Some(assertion) = Self::body::<Assertion>(request).await else {
            return Ok(Err(Response::error("malformed assertion", 400)?));
        };
        let (Some(credential), Some(client), Some(data), Some(signature)) = (
            unb64(&assertion.credential_id),
            unb64(&assertion.client_data_json),
            unb64(&assertion.authenticator_data),
            unb64(&assertion.signature),
        ) else {
            return Ok(Err(Response::error("malformed assertion", 400)?));
        };
        if credential != record.credential {
            return Ok(Err(Response::error("another passkey", 403)?));
        }
        let checked = webauthn::assertion(
            &self.rp(),
            &record.key,
            record.counter,
            &client,
            &data,
            &signature,
        );
        let (challenge, counter) = match checked {
            Ok(checked) => checked,
            Err(e) => {
                return Ok(Err(Response::error(
                    format!("passkey refused: {e:?}"),
                    403,
                )?));
            }
        };
        // The passkey signed it: only now is it remembered as used.
        if !self.fresh(handle, &challenge)? {
            return Ok(Err(Response::error("stale challenge", 409)?));
        }
        self.spend(&challenge)?;
        record.counter = counter;
        Ok(Ok((record, assertion, challenge)))
    }

    /// With the passkey: the backup, and (for a restored device of the same
    /// identity) the handle pointed at its new card.
    async fn restore(&self, handle: &str, mut request: Request) -> Result<Response> {
        let (mut record, assertion, challenge) = match self.assert(handle, &mut request).await? {
            Ok(ok) => ok,
            Err(refused) => return Ok(refused),
        };
        if let (Some(card), Some(signature)) = (&assertion.card, &assertion.identity_signature) {
            let (Some(card), Some(signature)) = (
                ContactCard::from_text(card),
                unb64(signature).and_then(|s| <[u8; 64]>::try_from(s).ok()),
            ) else {
                return Response::error("malformed card", 400);
            };
            if card.identity != record.card.identity
                || !verify(
                    &card.identity,
                    &handle_signed_bytes(handle, &card, &challenge),
                    &signature,
                )
            {
                return Response::error("not this handle's identity", 403);
            }
            record.card = card;
        }
        if let Some(token) = assertion.backup_token.as_deref().and_then(unb64) {
            let Ok(token) = <[u8; 32]>::try_from(token) else {
                return Response::error("malformed token", 400);
            };
            record.token = *blake3::hash(&token).as_bytes();
        }
        self.put("record", record.encode())?;
        let backup = self.get("backup")?.map(|b| b64(&b));
        json(&serde_json::json!({ "backup": backup }), 200)
    }

    async fn card(&self, handle: &str, mut request: Request) -> Result<Response> {
        let Some(mut record) = self.record()? else {
            return Response::error("no such handle", 404);
        };
        let Some(update) = Self::body::<CardUpdate>(&mut request).await else {
            return Response::error("malformed update", 400);
        };
        let (Some(card), Some(challenge), Some(signature)) = (
            ContactCard::from_text(&update.card),
            unb64(&update.challenge).and_then(|c| <[u8; 32]>::try_from(c).ok()),
            unb64(&update.identity_signature).and_then(|s| <[u8; 64]>::try_from(s).ok()),
        ) else {
            return Response::error("malformed update", 400);
        };
        if card.identity != record.card.identity
            || !verify(
                &card.identity,
                &handle_signed_bytes(handle, &card, &challenge),
                &signature,
            )
        {
            return Response::error("not this handle's identity", 403);
        }
        if !self.fresh(handle, &challenge)? {
            return Response::error("stale challenge", 409);
        }
        self.spend(&challenge)?;
        record.card = card;
        if let Some(token) = update.backup_token.as_deref().and_then(unb64) {
            let Ok(token) = <[u8; 32]>::try_from(token) else {
                return Response::error("malformed token", 400);
            };
            record.token = *blake3::hash(&token).as_bytes();
        }
        self.put("record", record.encode())?;
        Response::empty().map(|r| r.with_status(204))
    }

    async fn release(&self, handle: &str, mut request: Request) -> Result<Response> {
        if let Err(refused) = self.assert(handle, &mut request).await? {
            return Ok(refused);
        }
        self.state.storage().delete_all().await?;
        self.ready.set(false);
        Response::empty().map(|r| r.with_status(204))
    }

    async fn backup(&self, mut request: Request) -> Result<Response> {
        let Some(record) = self.record()? else {
            return Response::error("no such handle", 404);
        };
        let token = request
            .headers()
            .get("krypt-backup-token")?
            .and_then(|t| unb64(&t))
            .unwrap_or_default();
        if !krypt_core::constant_time_eq(blake3::hash(&token).as_bytes(), &record.token) {
            return Response::error("wrong token", 403);
        }
        let body = request.bytes().await?;
        if body.is_empty() || body.len() > BACKUP_MAX {
            return Response::error("backup size", 413);
        }
        self.put("backup", body)?;
        Response::empty().map(|r| r.with_status(204))
    }

    async fn drop_put(&self, mut request: Request) -> Result<Response> {
        // Write-once: a drop that was filled (and perhaps taken) stays
        // closed until its alarm deletes it.
        if self.get("blob")?.is_some() || self.get("taken")?.is_some() {
            return Response::error("already filled", 409);
        }
        let body = request.bytes().await?;
        if body.is_empty() || body.len() > DROP_MAX {
            return Response::error("drop size", 413);
        }
        self.put("blob", body)?;
        self.state.storage().set_alarm(DROP_TTL_MS as i64).await?;
        Response::empty().map(|r| r.with_status(201))
    }

    async fn drop_take(&self) -> Result<Response> {
        let Some(blob) = self.get("blob")? else {
            return Response::error("empty", 404);
        };
        // Taken once: what is left marks it used, so it cannot be refilled,
        // until the alarm set when it was filled deletes everything.
        self.sql("DELETE FROM kv WHERE k = 'blob'", Vec::new())?;
        self.put("taken", vec![1])?;
        let mut response = Response::from_bytes(blob)?;
        response
            .headers_mut()
            .set("content-type", "application/octet-stream")?;
        Ok(response)
    }
}

impl DurableObject for Directory {
    fn new(state: State, env: Env) -> Self {
        Directory {
            state,
            env,
            ready: Cell::new(false),
        }
    }

    async fn fetch(&self, request: Request) -> Result<Response> {
        let url = request.url()?;
        let handle = url
            .query_pairs()
            .find(|(k, _)| k == "h")
            .map(|(_, v)| v.into_owned())
            .unwrap_or_default();
        match url.path() {
            "/get" => match self.record()? {
                Some(record) => json(&serde_json::json!({ "card": record.card.to_text() }), 200),
                None => Response::error("no such handle", 404),
            },
            "/challenge" => self.challenge(&handle),
            "/claim" => self.claim(&handle, request).await,
            "/restore" => self.restore(&handle, request).await,
            "/release" => self.release(&handle, request).await,
            "/card" => self.card(&handle, request).await,
            "/backup" => self.backup(request).await,
            "/put" => self.drop_put(request).await,
            "/take" => self.drop_take().await,
            _ => Response::error("not found", 404),
        }
    }

    /// A drop nobody took expires.
    async fn alarm(&self) -> Result<Response> {
        self.state.storage().delete_all().await?;
        self.ready.set(false);
        Response::empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles_are_normalized_and_bounded() {
        assert_eq!(normalize("@Alice_1").as_deref(), Some("alice_1"));
        assert_eq!(normalize(" bob ").as_deref(), Some("bob"));
        for bad in [
            "ab",
            "_alice",
            "al ice",
            "alice!",
            "ålice",
            "krypt",
            "Support",
            &"a".repeat(25),
        ] {
            assert_eq!(normalize(bad), None, "{bad}");
        }
    }
}
