//! The krypt mailbox on Cloudflare.
//!
//! The same Worker serves the web client as static assets (Cloudflare serves
//! those without running it), so the app and the mailbox share one origin.
//!
//! The Worker accepts request frames (`POST /v1/frame`) and WebSocket
//! subscriptions (`GET /v1/ws/<route>`), applies a per-IP rate limit, and
//! hands each to the Durable Object for the route: one object per
//! conversation log or inbox, each with its own SQLite database. The object
//! runs the very same `krypt_core::mailbox::Mailbox` the simulator verifies;
//! only its storage ([`SqlStore`]) is specific to Cloudflare.
//!
//! Costs, which shape everything here (decision 15):
//! - An ordinary message is one row written. Commits write four.
//! - Devices keep a hibernating WebSocket per log they follow. Requests sent
//!   over it are billed at a twentieth of an HTTP request, and new entries
//!   are pushed to every socket for free, so nobody polls.
//! - Expiry runs from an alarm at most once a day per log.
//! - Reading a route that was never written creates nothing.
//!
//! Files are stored encrypted in R2, one object per part, under
//! `f/<route>/<file>/<part>`. A part is stored only after the conversation's
//! object says the uploader is a member with allowance left (one request to
//! it per part); the body streams from the request into R2 without passing
//! through the Worker. A lifecycle rule on the bucket deletes parts after the
//! retention period (`scripts/cloudflare-r2.sh`). Reading is open to anyone
//! who knows the route and file id, like reading a log.
//!
//! Calls connect browsers directly (WebRTC), through Cloudflare's TURN relay
//! when they cannot reach each other. Relay credentials (`POST
//! /v1/turn/<route>`) go only to members, checked by the conversation's
//! object like file parts, within a daily allowance per conversation and a
//! per-IP limit: relayed traffic costs money past the free tier.
//!
//! Abuse reports (`POST /v1/report`) hold only what a reporter chose to send
//! (by default, the last messages the reported identity sent them). They are
//! stored in the same bucket under `r/<day>/<id>.json`, deleted after 90 days,
//! and read with `just reports`.
//!
//! Welcomes for new members (forwards) are written to a `pending` table in
//! the same synchronous block that accepts the commit, then delivered to the
//! inbox objects by the alarm, which retries until each one lands. Delivery
//! is idempotent, so a retry after a lost acknowledgement is harmless.

mod directory;
mod push;
mod webauthn;

use std::cell::{Cell, OnceCell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;

use krypt_core::mailbox::{Blob, Forward, Hash, Mailbox, Meta, Store, push_target};
use krypt_wire::frame::{self, HEADER_SIZE, Kind, Route};
use krypt_wire::limits::{DAY_MS, FRAME_BODY_MAX, GROUP_MEMBERS_MAX};
use krypt_wire::msg::{FilePart, Platform, Reject, Rejected, Submit, TurnGrant};
use push::Vapid;
use worker::{
    Conditional, Data, Date, DurableObject, Env, Fetch, Headers, Method, Request, RequestInit,
    Response, Result, SqlStorage, SqlStorageValue, State, WebSocket, WebSocketIncomingMessage,
    WebSocketPair, durable_object, event,
};

const LOG_BINDING: &str = "LOG";
const RATE_BINDING: &str = "PER_IP";
const FILES_BINDING: &str = "FILES";
/// Per-IP limit on stored file parts, separate from requests: parts are the
/// expensive thing (storage billed for a month).
const FILE_RATE_BINDING: &str = "FILES_PER_IP";
/// Per-IP limit on relay credentials.
const TURN_RATE_BINDING: &str = "TURN_PER_IP";
/// Per-IP limit on abuse reports.
const REPORT_RATE_BINDING: &str = "REPORTS_PER_IP";
/// Per-IP limit on new logs (a conversation's first commit, a requests log
/// opened): each costs storage for months.
const CREATE_RATE_BINDING: &str = "CREATES_PER_IP";
/// Largest abuse report: twenty messages of a few kilobytes.
const REPORT_MAX: usize = 96 * 1024;
/// The Cloudflare TURN key (a var) and its API token (a secret, `just
/// edge-turn-secret`). Without them, calls get STUN only: direct paths work,
/// relayed ones do not.
const TURN_KEY_VAR: &str = "TURN_KEY_ID";
const TURN_TOKEN_SECRET: &str = "TURN_KEY_API_TOKEN";
/// How long relay credentials last. A longer call asks again and restarts
/// ICE before they expire. Short, because a credential is a general relay
/// billed by the gigabyte for as long as it lasts.
const TURN_TTL_S: u64 = 60 * 60;
/// A secret; "1" (`just edge-kill`) refuses all traffic, open sockets
/// included. Cloudflare budgets alert but never stop spending; this does.
const KILL_VAR: &str = "KILL_SWITCH";
/// The VAPID private key (a secret); without it, no wakeups are sent.
const VAPID_SECRET: &str = "VAPID_PRIVATE_KEY";
/// "1" lets wakeups go to http://127.0.0.1 (local tests only).
const LOCAL_PUSH_VAR: &str = "ALLOW_LOCAL_PUSH";
const FRAME_MAX: usize = HEADER_SIZE + FRAME_BODY_MAX as usize;
/// Retry delay for undelivered forwards, doubling up to the cap.
const RETRY_MS: u64 = 1_000;
const RETRY_MAX_MS: u64 = 60_000;
/// While the kill switch is on, a log looks at its queue this often.
const KILLED_RETRY_MS: u64 = 60 * 60_000;
/// Expiry runs at most once a day per log: every alarm is a billed request
/// and a row written, and retention only has to hold to the day.
const EXPIRE_GRANULARITY_MS: u64 = DAY_MS;
/// Requests one log serves, across all its sockets: the sustained rate per
/// second and the burst. Chat never comes close; a flood stops here.
const LOG_RATE_PER_S: u64 = 20;
const LOG_BURST: u64 = 200;
/// Sockets one log accepts: every member device, with room for reconnects.
const SOCKETS_MAX: usize = GROUP_MEMBERS_MAX * 2;
/// Sockets one log accepts from one address (or IPv6 /64): a household's
/// devices behind one router, not a flood that crowds members out.
const SOCKETS_PER_IP: usize = 16;

/// What a log's socket keeps (across hibernation): its route, and who
/// opened it ([`ip_key`]).
#[derive(serde::Serialize, serde::Deserialize)]
struct Subscriber {
    route: String,
    ip: String,
}

fn hex(route: &Route) -> String {
    route.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Option<Route> {
    unhex_bytes(text)
}

/// `/v1/file/<route>/<file>/<part>`: the route and file id in hex, the part
/// in decimal.
fn file_path(path: &str) -> Option<(Route, [u8; 16], u32)> {
    let mut segments = path.strip_prefix("/v1/file/")?.split('/');
    let route = unhex(segments.next()?)?;
    let file = unhex(segments.next()?)?;
    let part = segments.next()?;
    if segments.next().is_some() || part.is_empty() || part.len() > 3 || part.starts_with('+') {
        return None;
    }
    Some((route, file, part.parse().ok()?))
}

fn file_key(route: &Route, file: &[u8; 16], part: u32) -> String {
    format!("f/{}/{}/{part}", hex(route), hex(file))
}

fn now_ms() -> u64 {
    Date::now().as_millis()
}

fn killed(env: &Env) -> bool {
    env.var(KILL_VAR).is_ok_and(|v| v.to_string() == "1")
}

fn octets(body: Vec<u8>) -> Result<Response> {
    let mut response = Response::from_bytes(body)?;
    response
        .headers_mut()
        .set("content-type", "application/octet-stream")?;
    Ok(response)
}

fn stub(env: &Env, route: &Route) -> Result<worker::Stub> {
    env.durable_object(LOG_BINDING)?.get_by_name(&hex(route))
}

/// Sends `body` to the object owning `route`, at `path`.
async fn to_log(env: &Env, route: &Route, path: &str, body: Vec<u8>) -> Result<Response> {
    let mut init = RequestInit::new();
    init.with_method(Method::Post).with_body(Some(body.into()));
    let request = Request::new_with_init(&format!("https://log{path}"), &init)?;
    stub(env, route)?.fetch_with_request(request).await
}

/// Browsers say which page is asking. Other websites may not use the
/// mailbox through their visitors' browsers (WebSockets ignore CORS, so this
/// is the only guard). Native clients send no Origin; pages served from the
/// user's own machine (development) are not a website anyone stumbles on.
fn origin_allowed(request: &Request) -> Result<bool> {
    let Some(origin) = request.headers().get("origin")? else {
        return Ok(true);
    };
    let host = origin.split("://").nth(1).unwrap_or("");
    let host = host.rsplit_once(':').map_or(host, |(host, _)| host);
    // By host: `wrangler dev` presents local pages as http://krypt.chat.
    Ok(matches!(
        host,
        "krypt.chat" | "api.krypt.chat" | "localhost" | "127.0.0.1" | "[::1]"
    ))
}

/// Pages served from elsewhere that may read the mailbox's answers (CORS).
/// None: krypt is the web app on krypt.chat alone (the native apps are
/// gone), and websites never are.
const APP_ORIGINS: [&str; 0] = [];
/// How long a webview may reuse a preflight's answer for a URL (Chromium
/// caps it at two hours). One frame URL, so apps ask once in a while; each
/// stored file part has a URL of its own, so one preflight per 4 MiB.
const PREFLIGHT_MAX_AGE_S: &str = "7200";

fn app_origin(request: &Request) -> Result<Option<String>> {
    Ok(request
        .headers()
        .get("origin")?
        .filter(|origin| APP_ORIGINS.contains(&origin.as_str())))
}

/// The answer to an app's preflight: the methods and headers krypt sends.
fn preflight(origin: &str) -> Result<Response> {
    let headers = Headers::new();
    headers.set("access-control-allow-origin", origin)?;
    headers.set("access-control-allow-methods", "GET, POST, PUT")?;
    headers.set(
        "access-control-allow-headers",
        "content-type, krypt-auth, krypt-backup-token",
    )?;
    headers.set("access-control-max-age", PREFLIGHT_MAX_AGE_S)?;
    headers.set("vary", "origin")?;
    Ok(Response::empty()?.with_status(204).with_headers(headers))
}

/// Lets an app's page read `response`. WebSockets need no permission. The
/// headers are copied: those of a response from an object are immutable.
fn readable_by(response: Response, origin: Option<&str>) -> Result<Response> {
    let Some(origin) = origin else {
        return Ok(response);
    };
    if response.status_code() == 101 {
        return Ok(response);
    }
    let headers = Headers::new();
    for (name, value) in response.headers().entries() {
        headers.append(&name, &value)?;
    }
    headers.set("access-control-allow-origin", origin)?;
    headers.append("vary", "origin")?;
    Ok(response.with_headers(headers))
}

/// Who is asking, for per-address limits: the IPv4 address, or the IPv6
/// /64 (one subscriber's whole network; a single address there is free to
/// change). Used as a counter key and kept with an open socket, never
/// written to storage.
fn ip_key(request: &Request) -> Result<String> {
    let ip = request
        .headers()
        .get("cf-connecting-ip")?
        .unwrap_or_default();
    Ok(match ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V6(v6)) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
        _ => ip,
    })
}

/// Whether the request says its body is larger than `max`, so it is
/// refused before being read. (One that says nothing is still measured
/// after reading.)
fn declared_over(request: &Request, max: usize) -> Result<bool> {
    Ok(request
        .headers()
        .get("content-length")?
        .and_then(|n| n.parse::<usize>().ok())
        .is_some_and(|n| n > max))
}

/// Per-IP limit.
async fn allowed(env: &Env, request: &Request, binding: &str) -> Result<bool> {
    let key = ip_key(request)?;
    limited(env, &key, binding).await
}

async fn limited(env: &Env, key: &str, binding: &str) -> Result<bool> {
    Ok(env
        .rate_limiter(binding)?
        .limit(key.to_owned())
        .await?
        .success)
}

/// The `krypt-auth` header: an epoch (little-endian) and a tag, in hex.
fn proof(request: &Request) -> Result<Option<(u64, [u8; 16])>> {
    Ok(request
        .headers()
        .get("krypt-auth")?
        .and_then(|a| unhex_bytes::<24>(&a))
        .map(|auth| {
            (
                u64::from_le_bytes(auth[..8].try_into().expect("8 bytes")),
                auth[8..].try_into().expect("16 bytes"),
            )
        }))
}

/// Asks the conversation's object to authorize a request (`kind`, with
/// `body`). `None` if it agrees, else the response refusing it.
async fn authorize(env: &Env, route: &Route, kind: Kind, body: &[u8]) -> Result<Option<Response>> {
    let frame = frame::encode_vec(kind, 0, *route, body);
    let mut answer = to_log(env, route, "/frame", frame).await?;
    if answer.status_code() != 200 {
        return Response::error("slow down", 429).map(Some);
    }
    let answer = answer.bytes().await?;
    let Ok(answer) = frame::decode(&answer) else {
        return Response::error("unavailable", 503).map(Some);
    };
    if answer.kind == Kind::Accepted {
        return Ok(None);
    }
    let rejected = Rejected::decode(answer.body).ok();
    let (status, text) = match rejected.map(|r| r.reason) {
        Some(Reject::StaleEpoch | Reject::FutureEpoch) => (409, "stale proof"),
        Some(Reject::Forbidden) => (403, "not a member"),
        Some(Reject::OverQuota) => (429, "over the daily allowance"),
        Some(Reject::UnknownLog) => (404, "unknown conversation"),
        _ => (400, "refused"),
    };
    Response::error(text, status).map(Some)
}

/// Call relay credentials for a member of the conversation, as WebRTC
/// `iceServers` (JSON), from Cloudflare's TURN service; STUN only if no TURN
/// key is configured. The browser drops the port 53 relay addresses, which
/// browsers block.
async fn turn(request: Request, env: &Env, path: &str) -> Result<Response> {
    let Some(route) = path.strip_prefix("/v1/turn/").and_then(unhex) else {
        return Response::error("bad route", 400);
    };
    if !allowed(env, &request, TURN_RATE_BINDING).await? {
        return Response::error("slow down", 429);
    }
    let Some((epoch, auth)) = proof(&request)? else {
        return Response::error("missing proof", 401);
    };
    let grant = TurnGrant { epoch, auth };
    if let Some(refused) = authorize(env, &route, Kind::AuthorizeTurn, &grant.encode()).await? {
        return Ok(refused);
    }
    let (Ok(key), Ok(token)) = (env.var(TURN_KEY_VAR), env.secret(TURN_TOKEN_SECRET)) else {
        let mut response = Response::from_bytes(
            br#"{"iceServers":[{"urls":["stun:stun.cloudflare.com:3478"]}]}"#.to_vec(),
        )?;
        response
            .headers_mut()
            .set("content-type", "application/json")?;
        return Ok(response);
    };
    let headers = Headers::new();
    headers.set("authorization", &format!("Bearer {token}"))?;
    headers.set("content-type", "application/json")?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(format!(r#"{{"ttl":{TURN_TTL_S}}}"#).into()));
    let url = format!(
        "https://rtc.live.cloudflare.com/v1/turn/keys/{key}/credentials/generate-ice-servers"
    );
    let mut upstream = Fetch::Request(Request::new_with_init(&url, &init)?)
        .send()
        .await?;
    if !(200..300).contains(&upstream.status_code()) {
        return Response::error("relay unavailable", 502);
    }
    let mut response = Response::from_bytes(upstream.bytes().await?)?;
    let headers = response.headers_mut();
    headers.set("content-type", "application/json")?;
    headers.set("cache-control", "no-store")?;
    headers.set("krypt-ttl", &TURN_TTL_S.to_string())?;
    Ok(response)
}

/// `YYYY-MM-DD` for a count of days since 1970-01-01 (Howard Hinnant's
/// `civil_from_days`).
fn civil_date(days: u64) -> String {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

/// Stores an abuse report as sent. The app builds it; nothing here reads
/// it, so it only has to be small, JSON-shaped, and rate limited.
async fn report(mut request: Request, env: &Env) -> Result<Response> {
    if !allowed(env, &request, REPORT_RATE_BINDING).await? {
        return Response::error("slow down", 429);
    }
    if declared_over(&request, REPORT_MAX)? {
        return Response::error("report too large", 413);
    }
    if request.headers().get("content-type")?.as_deref() != Some("application/json") {
        return Response::error("json only", 415);
    }
    let body = request.bytes().await?;
    if body.len() > REPORT_MAX {
        return Response::error("report too large", 413);
    }
    // A JSON object, or nothing is kept: the operator's tools must be able
    // to read every report that is.
    if !serde_json::from_slice::<serde_json::Value>(&body).is_ok_and(|v| v.is_object()) {
        return Response::error("malformed report", 400);
    }
    // Unique per request (Cloudflare's ray id), and says nothing about the
    // reporter.
    let ray = request.headers().get("cf-ray")?.unwrap_or_default();
    let id = krypt_core::hash16(&[ray.as_bytes(), &now_ms().to_le_bytes(), &body].concat());
    let key = format!("r/{}/{}.json", civil_date(now_ms() / DAY_MS), hex(&id));
    env.bucket(FILES_BINDING)?.put(key, body).execute().await?;
    Ok(Response::empty()?.with_status(201))
}

/// Stores one encrypted part of a file, once the conversation's object has
/// checked the uploader's proof of membership (`krypt-auth`: the epoch,
/// little-endian, and the tag, in hex) and the day's allowance. A part
/// already stored is never replaced; a retry after a lost response gets 200.
async fn put_file(request: Request, env: &Env) -> Result<Response> {
    let Some((route, file, part)) = file_path(&request.path()) else {
        return Response::error("bad file path", 400);
    };
    if !allowed(env, &request, FILE_RATE_BINDING).await? {
        return Response::error("slow down", 429);
    }
    let Some(len) = request
        .headers()
        .get("content-length")?
        .and_then(|l| l.parse::<u32>().ok())
    else {
        return Response::error("length required", 411);
    };
    let Some((epoch, auth)) = proof(&request)? else {
        return Response::error("missing proof", 401);
    };
    let part = FilePart {
        file,
        part,
        len,
        epoch,
        auth,
    };
    // Decoding checks the limits: part index and stored length.
    let Ok(part) = FilePart::decode(&part.encode()) else {
        return Response::error("part too large", 413);
    };
    if let Some(refused) = authorize(env, &route, Kind::AuthorizeFile, &part.encode()).await? {
        return Ok(refused);
    }
    let Some(body) = request.inner().body() else {
        return Response::error("empty part", 400);
    };
    let stored = env
        .bucket(FILES_BINDING)?
        .put(
            file_key(&route, &part.file, part.part),
            Data::ReadableStream(body),
        )
        .only_if(Conditional {
            etag_does_not_match: Some("*".to_owned()),
            ..Conditional::default()
        })
        .execute()
        .await?;
    Ok(Response::empty()?.with_status(if stored.is_some() { 201 } else { 200 }))
}

/// Streams one stored part straight from R2.
async fn get_file(path: &str, env: &Env) -> Result<Response> {
    let Some((route, file, part)) = file_path(path) else {
        return Response::error("bad file path", 400);
    };
    let Some(object) = env
        .bucket(FILES_BINDING)?
        .get(file_key(&route, &file, part))
        .execute()
        .await?
    else {
        return Response::error("no such part", 404);
    };
    let Some(body) = object.body() else {
        return Response::error("no such part", 404);
    };
    let mut response = Response::from_body(body.response_body()?)?;
    let headers = response.headers_mut();
    headers.set("content-type", "application/octet-stream")?;
    // A part never changes once stored.
    headers.set("cache-control", "private, max-age=2592000, immutable")?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::civil_date;

    #[test]
    fn civil_dates() {
        assert_eq!(civil_date(0), "1970-01-01");
        assert_eq!(civil_date(11_016), "2000-02-29");
        assert_eq!(civil_date(20_764), "2026-11-07");
    }
}

fn unhex_bytes<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

#[event(fetch)]
async fn fetch(request: Request, env: Env, _ctx: worker::Context) -> Result<Response> {
    if killed(&env) {
        return Response::error("unavailable", 503);
    }
    let path = request.path();
    if request.method() == Method::Get && path == "/" {
        return Response::ok("krypt mailbox\n");
    }
    if !origin_allowed(&request)? {
        return Response::error("forbidden origin", 403);
    }
    let app = app_origin(&request)?;
    if let Some(origin) = &app
        && request.method() == Method::Options
    {
        // Answered here: nothing to count or forward.
        return preflight(origin);
    }
    // Stored bytes (file parts, drops) are for the app's own fetches only:
    // never a page, image or script someone links to or navigates to, so
    // nobody can host content on krypt.chat through them.
    let stored = path.starts_with("/v1/file/") || path.starts_with("/v1/drop/");
    if stored
        && request.method() == Method::Get
        && request
            .headers()
            .get("sec-fetch-dest")?
            .is_some_and(|dest| dest != "empty")
    {
        return Response::error("not a page", 403);
    }
    let response = route(request, &env, &path).await?;
    let response = if response.status_code() == 101 {
        response
    } else {
        inert(response)?
    };
    readable_by(response, app.as_deref())
}

/// Whatever the mailbox returns is data: never sniffed, rendered or
/// embedded elsewhere, and saved rather than shown if opened.
fn inert(response: Response) -> Result<Response> {
    // A copy: a response from an object or R2 has immutable headers.
    let headers = Headers::new();
    for (name, value) in response.headers().entries() {
        headers.append(&name, &value)?;
    }
    headers.set("x-content-type-options", "nosniff")?;
    headers.set("content-security-policy", "default-src 'none'; sandbox")?;
    headers.set("cross-origin-resource-policy", "same-origin")?;
    if headers.get("content-type")?.as_deref() == Some("application/octet-stream") {
        headers.set("content-disposition", "attachment")?;
    }
    Ok(response.with_headers(headers))
}

async fn route(mut request: Request, env: &Env, path: &str) -> Result<Response> {
    if !allowed(env, &request, RATE_BINDING).await? {
        return Response::error("slow down", 429);
    }
    if path.starts_with("/v1/handle/") || path.starts_with("/v1/drop/") {
        return directory::route(request, env, path)
            .await
            .expect("a directory path");
    }
    match (request.method(), path) {
        (Method::Post, "/v1/frame") => {
            if declared_over(&request, FRAME_MAX)? {
                return Response::error("frame too large", 413);
            }
            let body = request.bytes().await?;
            if body.len() > FRAME_MAX {
                return Response::error("frame too large", 413);
            }
            // The object re-validates everything; this only needs the route,
            // and whether the frame would make a new log.
            let Ok(frame) = frame::decode(&body) else {
                return Response::error("malformed frame", 400);
            };
            let creates = match frame.kind {
                Kind::Submit => Submit::decode(frame.body).is_ok_and(|s| s.creation.is_some()),
                Kind::OpenRequests => true,
                _ => false,
            };
            if creates && !allowed(env, &request, CREATE_RATE_BINDING).await? {
                return Response::error("slow down", 429);
            }
            let route = frame.route;
            to_log(env, &route, "/frame", body).await
        }
        (Method::Put, path) if path.starts_with("/v1/file/") => put_file(request, env).await,
        (Method::Get, path) if path.starts_with("/v1/file/") => get_file(path, env).await,
        (Method::Post, path) if path.starts_with("/v1/turn/") => turn(request, env, path).await,
        (Method::Post, "/v1/report") => report(request, env).await,
        (Method::Get, path) if path.starts_with("/v1/ws/") => {
            let Some(route) = unhex(&path["/v1/ws/".len()..]) else {
                return Response::error("bad route", 400);
            };
            if request.headers().get("upgrade")?.as_deref() != Some("websocket") {
                return Response::error("expected a websocket", 426);
            }
            stub(env, &route)?.fetch_with_request(request).await
        }
        _ => Response::error("not found", 404),
    }
}

// ---- Storage ----------------------------------------------------------------

/// No secondary indexes: each would add a row written per message. `data` is
/// last in `entries` so reading the other columns never loads it, and
/// `total` (the running byte count) gives the log's size from two rows.
const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS entries (
        seq INTEGER PRIMARY KEY,
        at INTEGER NOT NULL,
        hash BLOB NOT NULL,
        total INTEGER NOT NULL,
        data BLOB NOT NULL
    );
    CREATE TABLE IF NOT EXISTS commits (
        epoch INTEGER PRIMARY KEY,
        hash BLOB NOT NULL,
        seq INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS blobs (id INTEGER PRIMARY KEY, value BLOB NOT NULL);
    CREATE TABLE IF NOT EXISTS pending (
        id INTEGER PRIMARY KEY,
        route BLOB NOT NULL,
        entry BLOB NOT NULL
    );
";
/// The meta record shares the blobs table, under an id no [`Blob`] uses.
const META_ID: i64 = 0;

type Row = Vec<SqlStorageValue>;

fn int(value: &SqlStorageValue) -> u64 {
    match value {
        SqlStorageValue::Integer(n) => u64::try_from(*n).expect("non-negative"),
        SqlStorageValue::Float(n) if *n >= 0.0 && n.fract() == 0.0 => {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let n = *n as u64;
            n
        }
        other => panic!("expected an integer, got {other:?}"),
    }
}

fn blob(value: SqlStorageValue) -> Vec<u8> {
    match value {
        SqlStorageValue::Blob(bytes) => bytes,
        other => panic!("expected a blob, got {other:?}"),
    }
}

fn hash(value: SqlStorageValue) -> Hash {
    blob(value).try_into().expect("16-byte hash")
}

fn n(value: u64) -> SqlStorageValue {
    SqlStorageValue::Integer(i64::try_from(value).expect("fits in i64"))
}

/// The mailbox's storage, in a Durable Object's SQLite. Every call is
/// synchronous, so the writes one request makes commit atomically. Tables
/// are created by the first write: a read of a route nobody has written
/// leaves no storage behind.
#[allow(missing_debug_implementations)] // wraps a JavaScript object
pub struct SqlStore<'a> {
    sql: &'a SqlStorage,
    /// Whether the tables exist; `None` until first checked.
    ready: &'a Cell<Option<bool>>,
}

impl SqlStore<'_> {
    fn rows(&self, query: &str, bindings: Vec<SqlStorageValue>) -> Vec<Row> {
        self.sql
            .exec(query, bindings)
            .expect("durable object sql")
            .raw()
            .collect::<Result<Vec<_>>>()
            .expect("durable object rows")
    }

    fn one(&self, query: &str, bindings: Vec<SqlStorageValue>) -> Option<Row> {
        if !self.ready() {
            return None;
        }
        self.rows(query, bindings).into_iter().next()
    }

    fn write(&self, query: &str, bindings: Vec<SqlStorageValue>) {
        if !self.ready() {
            self.rows(SCHEMA, Vec::new());
            self.ready.set(Some(true));
        }
        self.rows(query, bindings);
    }

    fn ready(&self) -> bool {
        if let Some(ready) = self.ready.get() {
            return ready;
        }
        let exists = !self
            .rows(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'blobs'",
                Vec::new(),
            )
            .is_empty();
        self.ready.set(Some(exists));
        exists
    }

    /// `(seq, total)` of the newest entry.
    fn last(&self) -> Option<(u64, u64)> {
        let row = self.one(
            "SELECT seq, total FROM entries ORDER BY seq DESC LIMIT 1",
            Vec::new(),
        )?;
        Some((int(&row[0]), int(&row[1])))
    }

    /// `(seq, bytes before it)` of the oldest entry.
    fn first(&self) -> Option<(u64, u64)> {
        let row = self.one(
            "SELECT seq, total - length(data) FROM entries ORDER BY seq LIMIT 1",
            Vec::new(),
        )?;
        Some((int(&row[0]), int(&row[1])))
    }

    fn has_pending(&self) -> bool {
        self.one("SELECT 1 FROM pending LIMIT 1", Vec::new())
            .is_some()
    }

    fn add_pending(&self, forward: &Forward) {
        self.write(
            "INSERT INTO pending (route, entry) VALUES (?, ?)",
            vec![
                SqlStorageValue::Blob(forward.route.to_vec()),
                SqlStorageValue::Blob(forward.entry.clone()),
            ],
        );
    }

    fn pending(&self) -> Vec<(u64, Forward)> {
        if !self.ready() {
            return Vec::new();
        }
        self.rows(
            "SELECT id, route, entry FROM pending ORDER BY id",
            Vec::new(),
        )
        .into_iter()
        .map(|row| {
            let mut row = row.into_iter();
            let id = int(&row.next().expect("id"));
            let route = blob(row.next().expect("route"));
            let entry = blob(row.next().expect("entry"));
            let route = route.try_into().expect("16-byte route");
            (id, Forward { route, entry })
        })
        .collect()
    }

    fn remove_pending(&self, id: u64) {
        self.write("DELETE FROM pending WHERE id = ?", vec![n(id)]);
    }
}

impl Store for SqlStore<'_> {
    fn meta(&self) -> Option<Meta> {
        let row = self.one(
            "SELECT value FROM blobs WHERE id = ?",
            vec![SqlStorageValue::Integer(META_ID)],
        )?;
        let bytes = blob(row.into_iter().next().expect("value"));
        Some(Meta::decode(&bytes).expect("meta is corrupt"))
    }

    fn set_meta(&mut self, meta: &Meta) {
        self.write(
            "INSERT OR REPLACE INTO blobs (id, value) VALUES (?, ?)",
            vec![
                SqlStorageValue::Integer(META_ID),
                SqlStorageValue::Blob(meta.encode()),
            ],
        );
    }

    fn last_seq(&self) -> Option<u64> {
        self.last().map(|(seq, _)| seq)
    }

    fn append(&mut self, seq: u64, at_ms: u64, hash: &Hash, data: &[u8]) {
        let total = self.last().map_or(0, |(last, total)| {
            assert!(seq > last);
            total
        }) + data.len() as u64;
        self.write(
            "INSERT INTO entries (seq, at, hash, total, data) VALUES (?, ?, ?, ?, ?)",
            vec![
                n(seq),
                n(at_ms),
                SqlStorageValue::Blob(hash.to_vec()),
                n(total),
                SqlStorageValue::Blob(data.to_vec()),
            ],
        );
    }

    fn range(&self, after: u64, limit: usize, max_bytes: u64) -> Vec<(u64, Vec<u8>)> {
        if !self.ready() {
            return Vec::new();
        }
        // By the running total, so rows past the budget are never loaded;
        // the first is always included.
        self.rows(
            "SELECT seq, data FROM entries WHERE seq > ?1 AND total <= ( \
                 SELECT total - length(data) + max(?2, length(data)) FROM entries \
                 WHERE seq > ?1 ORDER BY seq LIMIT 1) \
             ORDER BY seq LIMIT ?3",
            vec![n(after), n(max_bytes), n(limit as u64)],
        )
        .into_iter()
        .map(|row| {
            let mut row = row.into_iter();
            let seq = int(&row.next().expect("seq"));
            (seq, blob(row.next().expect("data")))
        })
        .collect()
    }

    fn recent_hashes(&self, count: usize) -> Vec<(u64, Hash)> {
        if !self.ready() {
            return Vec::new();
        }
        self.rows(
            "SELECT seq, hash FROM entries ORDER BY seq DESC LIMIT ?",
            vec![n(count as u64)],
        )
        .into_iter()
        .map(|row| {
            let mut row = row.into_iter();
            let seq = int(&row.next().expect("seq"));
            (seq, hash(row.next().expect("hash")))
        })
        .collect()
    }

    fn oldest(&self) -> Option<(u64, u64)> {
        let row = self.one(
            "SELECT seq, at FROM entries ORDER BY seq LIMIT 1",
            Vec::new(),
        )?;
        Some((int(&row[0]), int(&row[1])))
    }

    fn last_appended_by(&self, at_ms: u64) -> Option<u64> {
        // Seqs are contiguous and append times never decrease, so the answer
        // is just before the first entry appended later. Scanning from the
        // oldest reads only the entries about to expire.
        let (first, _) = self.first()?;
        match self.one(
            "SELECT seq FROM entries WHERE at > ? ORDER BY seq LIMIT 1",
            vec![n(at_ms)],
        ) {
            Some(row) => Some(int(&row[0]) - 1).filter(|seq| *seq >= first),
            None => self.last_seq(),
        }
    }

    fn evict_through(&mut self, seq: u64) {
        self.write("DELETE FROM entries WHERE seq <= ?", vec![n(seq)]);
    }

    fn count(&self) -> u64 {
        match (self.first(), self.last()) {
            (Some((first, _)), Some((last, _))) => last - first + 1,
            _ => 0,
        }
    }

    fn bytes(&self) -> u64 {
        match (self.first(), self.last()) {
            (Some((_, before)), Some((_, total))) => total - before,
            _ => 0,
        }
    }

    fn sizes(&self, after: u64, limit: usize) -> Vec<(u64, u64)> {
        if !self.ready() {
            return Vec::new();
        }
        // length() of a blob reads its size, not its content.
        self.rows(
            "SELECT seq, length(data) FROM entries WHERE seq > ? ORDER BY seq LIMIT ?",
            vec![n(after), n(limit as u64)],
        )
        .into_iter()
        .map(|row| {
            let mut row = row.into_iter();
            (
                int(&row.next().expect("seq")),
                int(&row.next().expect("length")),
            )
        })
        .collect()
    }

    fn commit(&self, epoch: u64) -> Option<(Hash, u64)> {
        let row = self.one(
            "SELECT hash, seq FROM commits WHERE epoch = ?",
            vec![n(epoch)],
        )?;
        let mut row = row.into_iter();
        let hash = hash(row.next().expect("hash"));
        Some((hash, int(&row.next().expect("seq"))))
    }

    fn put_commit(&mut self, epoch: u64, hash: &Hash, seq: u64) {
        self.write(
            "INSERT OR REPLACE INTO commits (epoch, hash, seq) VALUES (?, ?, ?)",
            vec![n(epoch), SqlStorageValue::Blob(hash.to_vec()), n(seq)],
        );
    }

    fn evict_commits_through(&mut self, seq: u64) {
        self.write("DELETE FROM commits WHERE seq <= ?", vec![n(seq)]);
    }

    fn blob(&self, which: Blob) -> Option<Vec<u8>> {
        let row = self.one(
            "SELECT value FROM blobs WHERE id = ?",
            vec![SqlStorageValue::Integer(which as i64)],
        )?;
        Some(blob(row.into_iter().next().expect("value")))
    }

    fn set_blob(&mut self, which: Blob, value: &[u8]) {
        self.write(
            "INSERT OR REPLACE INTO blobs (id, value) VALUES (?, ?)",
            vec![
                SqlStorageValue::Integer(which as i64),
                SqlStorageValue::Blob(value.to_vec()),
            ],
        );
    }

    fn clear(&mut self) {
        if self.ready() {
            self.rows(
                "DROP TABLE entries; DROP TABLE commits; DROP TABLE blobs; DROP TABLE pending;",
                Vec::new(),
            );
        }
        self.ready.set(Some(false));
    }
}

// ---- The Durable Object -------------------------------------------------------

#[durable_object]
#[allow(missing_debug_implementations)] // holds JavaScript objects
pub struct Log {
    state: State,
    env: Env,
    mailbox: RefCell<Mailbox>,
    ready: Cell<Option<bool>>,
    /// The alarm as last set or read; `None` until known.
    alarm: Cell<Option<Option<u64>>>,
    retry_ms: Cell<u64>,
    /// Token bucket for this log: tokens, and when last refilled.
    bucket: Cell<(u64, u64)>,
    vapid: OnceCell<Option<Rc<Vapid>>>,
    /// VAPID tokens by push service, with when they expire (Unix seconds):
    /// one signature per service per twelve hours, not one per push.
    tokens: RefCell<BTreeMap<String, (u64, String)>>,
}

/// One wakeup; returns the push service's status, if it answered.
async fn send_push(endpoint: &str, authorization: &str) -> Option<u16> {
    let headers = Headers::new();
    headers.set("authorization", authorization).ok()?;
    headers.set("ttl", &push::TTL_S.to_string()).ok()?;
    headers.set("urgency", "high").ok()?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some("".into()));
    let request = Request::new_with_init(endpoint, &init).ok()?;
    Fetch::Request(request)
        .send()
        .await
        .ok()
        .map(|r| r.status_code())
}

impl Log {
    fn with_store<T>(&self, f: impl FnOnce(&mut SqlStore<'_>) -> T) -> T {
        let sql = self.state.storage().sql();
        let mut store = SqlStore {
            sql: &sql,
            ready: &self.ready,
        };
        f(&mut store)
    }

    fn take_token(&self, now: u64) -> bool {
        let (tokens, at) = self.bucket.get();
        let refill = now.saturating_sub(at) * LOG_RATE_PER_S / 1_000;
        let tokens = (tokens + refill).min(LOG_BURST);
        let at = if refill > 0 { now } else { at };
        if tokens == 0 {
            self.bucket.set((0, at));
            return false;
        }
        self.bucket.set((tokens - 1, at));
        true
    }

    fn broadcast(&self, notify: Option<Vec<u8>>) {
        let Some(notify) = notify else { return };
        for socket in self.state.get_websockets() {
            // A socket that is closing just misses it; it fetches on reconnect.
            let _ = socket.send_with_bytes(&notify);
        }
    }

    fn vapid(&self) -> Option<Rc<Vapid>> {
        self.vapid
            .get_or_init(|| {
                let secret = self.env.secret(VAPID_SECRET).ok()?.to_string();
                Vapid::from_secret(&secret).map(Rc::new)
            })
            .clone()
    }

    fn token(&self, vapid: &Vapid, audience: &str, now_s: u64) -> String {
        let mut tokens = self.tokens.borrow_mut();
        // Renew an hour early, so no push carries a token about to lapse.
        if let Some((expires, header)) = tokens.get(audience)
            && *expires > now_s + 3_600
        {
            return header.clone();
        }
        let expires = now_s + push::TOKEN_LIFETIME_S;
        let header = vapid.authorization(audience, expires);
        tokens.insert(audience.to_owned(), (expires, header.clone()));
        header
    }

    /// Wakes devices through their push services, all at once, and drops
    /// targets that are gone or not push services at all. Web Push only:
    /// APNs and FCM need accounts that are not set up yet.
    async fn wake(&self, wakeups: Vec<Vec<u8>>) {
        if wakeups.is_empty() {
            return;
        }
        let Some(vapid) = self.vapid() else { return };
        let local = self
            .env
            .var(LOCAL_PUSH_VAR)
            .is_ok_and(|v| v.to_string() == "1");
        let now_s = now_ms() / 1_000;
        let mut forget = Vec::new();
        let mut sends = Vec::new();
        for target in wakeups {
            let Some(parsed) = push_target(&target) else {
                continue;
            };
            if parsed.platform != Platform::WebPush {
                continue;
            }
            let address = std::str::from_utf8(parsed.address).unwrap_or("");
            let Some((endpoint, audience)) = push::endpoint(address, local) else {
                forget.push(target);
                continue;
            };
            let authorization = self.token(&vapid, &audience, now_s);
            sends.push(async move { (target, send_push(&endpoint, &authorization).await) });
        }
        for (target, status) in futures_util::future::join_all(sends).await {
            if matches!(status, Some(404 | 410)) {
                forget.push(target);
            }
        }
        if !forget.is_empty() {
            self.with_store(|store| {
                for target in &forget {
                    Mailbox::forget(store, target);
                }
            });
        }
    }

    /// Runs one request frame: the response (`None` when malformed, not a
    /// request, or over the log's rate) and the wakeups it calls for.
    fn frame(
        &self,
        now: u64,
        bytes: &[u8],
        route: Option<&Route>,
    ) -> (Option<Vec<u8>>, Vec<Vec<u8>>) {
        if !self.take_token(now) {
            return (None, Vec::new());
        }
        let Ok(frame) = frame::decode(bytes) else {
            return (None, Vec::new());
        };
        // A socket speaks only for its own log: a frame naming another
        // route would make this log push entries labelled as that one's.
        if route.is_some_and(|route| *route != frame.route) {
            return (None, Vec::new());
        }
        let handled = self.with_store(|store| {
            let handled = self.mailbox.borrow_mut().handle(store, now, &frame);
            for forward in &handled.forwards {
                store.add_pending(forward);
            }
            handled
        });
        if !handled.forwards.is_empty() {
            self.retry_ms.set(0);
        }
        self.broadcast(handled.notify);
        (handled.response, handled.wakeups)
    }

    /// Sets the alarm to the next thing due, writing only when it changes.
    async fn reschedule(&self, now: u64) -> Result<()> {
        let (expiry, pending) =
            self.with_store(|store| (Mailbox::deadline(store), store.has_pending()));
        let expiry = expiry.map(|at| at.div_ceil(EXPIRE_GRANULARITY_MS) * EXPIRE_GRANULARITY_MS);
        let retry = pending.then(|| now + self.retry_ms.get());
        let want = [expiry, retry].into_iter().flatten().min();
        let current = match self.alarm.get() {
            Some(current) => current,
            None => {
                let current = self
                    .state
                    .storage()
                    .get_alarm()
                    .await?
                    .and_then(|at| u64::try_from(at).ok());
                self.alarm.set(Some(current));
                current
            }
        };
        if want == current {
            return Ok(());
        }
        let storage = self.state.storage();
        match want {
            Some(at) => {
                let offset =
                    i64::try_from(at).unwrap_or(i64::MAX) - i64::try_from(now).unwrap_or(0);
                storage.set_alarm(offset.max(0)).await?;
            }
            None => storage.delete_alarm().await?,
        }
        self.alarm.set(Some(want));
        Ok(())
    }

    async fn post(&self, mut request: Request) -> Result<Response> {
        let body = request.bytes().await?;
        let now = now_ms();
        // Sent here by the Worker for the frame's own route.
        let (response, wakeups) = self.frame(now, &body, None);
        self.wake(wakeups).await;
        self.reschedule(now).await?;
        match response {
            Some(response) => octets(response),
            None => Response::error("slow down", 429),
        }
    }

    /// Accepts a hibernating subscription to an existing log. The socket
    /// keeps its route and who opened it.
    fn subscribe(&self, request: &Request) -> Result<Response> {
        let Some(route) = request.path().strip_prefix("/v1/ws/").and_then(unhex) else {
            return Response::error("bad route", 400);
        };
        if self.with_store(|store| store.meta()).is_none() {
            return Response::error("unknown log", 404);
        }
        let ip = ip_key(request)?;
        let sockets = self.state.get_websockets();
        if sockets.len() >= SOCKETS_MAX {
            return Response::error("too many subscribers", 503);
        }
        let from_ip = sockets
            .iter()
            .filter(|s| {
                s.deserialize_attachment::<Subscriber>()
                    .ok()
                    .flatten()
                    .is_some_and(|sub| sub.ip == ip)
            })
            .count();
        if from_ip >= SOCKETS_PER_IP {
            return Response::error("too many subscribers from here", 429);
        }
        let pair = WebSocketPair::new()?;
        self.state.accept_web_socket(&pair.server);
        pair.server.serialize_attachment(Subscriber {
            route: hex(&route),
            ip,
        })?;
        // Keepalives are answered without waking the object.
        let ping = worker::worker_sys::WebSocketRequestResponsePair::new("ping", "pong")?;
        self.state.set_websocket_auto_response(&ping);
        Response::from_websocket(pair.client)
    }

    /// Appends a forwarded entry to this object's log (idempotently).
    async fn deliver(&self, mut request: Request) -> Result<Response> {
        if killed(&self.env) {
            // The sending log keeps it and retries.
            return Response::error("unavailable", 503);
        }
        let body = request.bytes().await?;
        if body.len() < 16 || body.len() > FRAME_MAX {
            return Response::error("bad forward", 400);
        }
        let (route, entry) = body.split_at(16);
        let forward = Forward {
            route: route.try_into().expect("16 bytes"),
            entry: entry.to_vec(),
        };
        let now = now_ms();
        let delivered =
            self.with_store(|store| self.mailbox.borrow_mut().deliver(store, now, &forward));
        self.broadcast(delivered.notify);
        self.wake(delivered.wakeups).await;
        self.reschedule(now).await?;
        Ok(Response::empty()?.with_status(204))
    }
}

impl DurableObject for Log {
    fn new(state: State, env: Env) -> Self {
        // Nothing touches storage here: an object woken for a route nobody
        // has written must not create a database.
        Log {
            state,
            env,
            mailbox: RefCell::new(Mailbox::new()),
            ready: Cell::new(None),
            alarm: Cell::new(None),
            retry_ms: Cell::new(0),
            bucket: Cell::new((LOG_BURST, 0)),
            vapid: OnceCell::new(),
            tokens: RefCell::new(BTreeMap::new()),
        }
    }

    async fn fetch(&self, request: Request) -> Result<Response> {
        let path = request.path();
        match path.as_str() {
            "/frame" => self.post(request).await,
            "/deliver" => self.deliver(request).await,
            _ if path.starts_with("/v1/ws/") => self.subscribe(&request),
            _ => Response::error("not found", 404),
        }
    }

    async fn websocket_message(
        &self,
        socket: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        if killed(&self.env) {
            socket.close(Some(1013), Some("unavailable"))?;
            return Ok(());
        }
        let WebSocketIncomingMessage::Binary(bytes) = message else {
            return Ok(());
        };
        if bytes.len() > FRAME_MAX {
            socket.close(Some(1009), Some("frame too large"))?;
            return Ok(());
        }
        let Some(subscriber) = socket.deserialize_attachment::<Subscriber>()? else {
            socket.close(Some(1008), Some("unknown subscriber"))?;
            return Ok(());
        };
        let route = unhex(&subscriber.route);
        // The per-address limit holds on sockets too, not only on requests
        // through the Worker.
        if !limited(&self.env, &subscriber.ip, RATE_BINDING).await? {
            return Ok(());
        }
        let now = now_ms();
        // Over the rate, the request is dropped: the device times out and
        // retries, which is the backoff.
        let (response, wakeups) = self.frame(now, &bytes, route.as_ref());
        if let Some(response) = response {
            socket.send_with_bytes(&response)?;
        }
        self.wake(wakeups).await;
        self.reschedule(now).await
    }

    async fn websocket_close(
        &self,
        _socket: WebSocket,
        _code: usize,
        _reason: String,
        _was_clean: bool,
    ) -> Result<()> {
        // The runtime answers close frames itself (compatibility date
        // 2026-04-07 and later).
        Ok(())
    }

    /// Delivers pending forwards (retrying with backoff), then expires what
    /// is due. A log that is gone deletes all of its storage.
    async fn alarm(&self) -> Result<Response> {
        self.alarm.set(Some(None));
        let now = now_ms();
        if killed(&self.env) {
            // Nothing goes out while the switch is on: look again later.
            self.retry_ms.set(KILLED_RETRY_MS);
            self.reschedule(now).await?;
            return Response::empty();
        }
        let mut failed = false;
        for (id, forward) in self.with_store(|store| store.pending()) {
            let body = [forward.route.as_slice(), &forward.entry].concat();
            match to_log(&self.env, &forward.route, "/deliver", body).await {
                Ok(response) if response.status_code() == 204 => {
                    self.with_store(|store| store.remove_pending(id));
                }
                _ => failed = true,
            }
        }
        self.retry_ms.set(if failed {
            (self.retry_ms.get() * 2).clamp(RETRY_MS, RETRY_MAX_MS)
        } else {
            0
        });
        let gone = self.with_store(|store| {
            self.mailbox.borrow_mut().expire(store, now).is_none() && !store.has_pending()
        });
        if gone {
            for socket in self.state.get_websockets() {
                let _ = socket.close(Some(1000), Some("gone"));
            }
            self.state.storage().delete_all().await?;
            self.ready.set(Some(false));
            return Response::empty();
        }
        self.reschedule(now).await?;
        Response::empty()
    }
}
