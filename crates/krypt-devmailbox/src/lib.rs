//! The mailbox's API, served from one process with in-memory storage:
//! request frames over HTTP (`POST /v1/frame`) or over a WebSocket per log
//! (`GET /v1/ws/<route>`), which also carries the log's `Notify` frames.
//! File parts are stored and fetched at `/v1/file/<route>/<file>/<part>`
//! once the log has authorized them, as the edge does with R2.
//! Production serves the same API from Cloudflare; this exists so devices
//! can be developed and tested without it.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Bytes;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use futures_util::{SinkExt as _, StreamExt as _};
use krypt_core::mailbox::LocalMailbox;
use krypt_wire::Route;
use krypt_wire::frame::{self, HEADER_SIZE, Kind};
use krypt_wire::limits::{FILE_PART_SIZE, FILE_TAG_SIZE, FRAME_BODY_MAX};
use krypt_wire::msg::{FilePart, Reject, Rejected};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

fn now_ms() -> u64 {
    let since = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
}

/// Largest request accepted: one maximal frame.
const REQUEST_MAX: usize = HEADER_SIZE + FRAME_BODY_MAX as usize;
/// Largest file part accepted.
const PART_MAX: usize = (FILE_PART_SIZE + FILE_TAG_SIZE) as usize;

#[derive(Debug, Default)]
struct Inner {
    mailbox: LocalMailbox,
    /// Sockets following each log.
    followers: BTreeMap<Route, Vec<mpsc::UnboundedSender<Vec<u8>>>>,
    /// Stored file parts, as R2 holds them in production.
    files: BTreeMap<(Route, [u8; 16], u32), Vec<u8>>,
}

impl Inner {
    /// Runs a request and pushes whatever it appended to the logs' sockets.
    fn handle(&mut self, request: &[u8]) -> Option<Vec<u8>> {
        let response = self.mailbox.handle(now_ms(), request);
        // Push wakeups need credentials; the dev mailbox only has sockets.
        drop(self.mailbox.take_wakeups());
        for (route, notify) in self.mailbox.take_notifications() {
            if let Some(followers) = self.followers.get_mut(&route) {
                followers.retain(|socket| socket.send(notify.clone()).is_ok());
            }
        }
        response
    }
}

type Shared = Arc<Mutex<Inner>>;

async fn frame(State(shared): State<Shared>, body: Bytes) -> Response {
    let response = shared.lock().expect("mailbox lock").handle(&body);
    match response {
        Some(frame) => ([("content-type", "application/octet-stream")], frame).into_response(),
        None => StatusCode::NO_CONTENT.into_response(),
    }
}

fn unhex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let mut out = [0u8; N];
    if text.len() != N * 2 {
        return None;
    }
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

type PartPath = Path<(String, String, u32)>;

fn part_key(path: (String, String, u32)) -> Option<(Route, [u8; 16], u32)> {
    Some((unhex(&path.0)?, unhex(&path.1)?, path.2))
}

/// Stores a file part once the log authorizes it; never replaces one.
async fn put_part(
    State(shared): State<Shared>,
    Path(path): PartPath,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some((route, file, part)) = part_key(path) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Some(auth) = headers
        .get("krypt-auth")
        .and_then(|a| a.to_str().ok())
        .and_then(unhex::<24>)
    else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let part = FilePart {
        file,
        part,
        len: u32::try_from(body.len()).unwrap_or(u32::MAX),
        epoch: u64::from_le_bytes(auth[..8].try_into().expect("8 bytes")),
        auth: auth[8..].try_into().expect("16 bytes"),
    };
    let Ok(part) = FilePart::decode(&part.encode()) else {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    };
    let request = frame::encode_vec(Kind::AuthorizeFile, 0, route, &part.encode());
    let mut inner = shared.lock().expect("mailbox lock");
    let answer = inner.handle(&request).expect("an answer");
    let answer = frame::decode(&answer).expect("the mailbox's own frame");
    if answer.kind != Kind::Accepted {
        return match Rejected::decode(answer.body).map(|r| r.reason) {
            Ok(Reject::StaleEpoch | Reject::FutureEpoch) => StatusCode::CONFLICT,
            Ok(Reject::Forbidden) => StatusCode::FORBIDDEN,
            Ok(Reject::OverQuota) => StatusCode::TOO_MANY_REQUESTS,
            Ok(Reject::UnknownLog) => StatusCode::NOT_FOUND,
            _ => StatusCode::BAD_REQUEST,
        }
        .into_response();
    }
    let key = (route, part.file, part.part);
    if inner.files.contains_key(&key) {
        return StatusCode::OK.into_response();
    }
    inner.files.insert(key, body.to_vec());
    StatusCode::CREATED.into_response()
}

async fn get_part(State(shared): State<Shared>, Path(path): PartPath) -> Response {
    let Some(key) = part_key(path) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match shared.lock().expect("mailbox lock").files.get(&key) {
        Some(bytes) => (
            [("content-type", "application/octet-stream")],
            bytes.clone(),
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn subscribe(
    State(shared): State<Shared>,
    Path(route): Path<String>,
    upgrade: WebSocketUpgrade,
) -> Response {
    let Some(route) = unhex::<16>(&route) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if !shared.lock().expect("mailbox lock").mailbox.exists(&route) {
        return StatusCode::NOT_FOUND.into_response();
    }
    upgrade
        .max_message_size(REQUEST_MAX)
        .on_upgrade(move |socket| follow(shared, route, socket))
}

async fn follow(shared: Shared, route: Route, socket: WebSocket) {
    let (tx, mut rx) = mpsc::unbounded_channel();
    shared
        .lock()
        .expect("mailbox lock")
        .followers
        .entry(route)
        .or_default()
        .push(tx.clone());
    let (mut sink, mut stream) = socket.split();
    let writer = tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            if sink.send(Message::Binary(frame.into())).await.is_err() {
                break;
            }
        }
    });
    while let Some(Ok(message)) = stream.next().await {
        let reply = match message {
            Message::Binary(request) => shared.lock().expect("mailbox lock").handle(&request),
            Message::Close(_) => break,
            // "ping" keepalives need no answer here.
            _ => None,
        };
        if let Some(reply) = reply
            && tx.send(reply).is_err()
        {
            break;
        }
    }
    drop(tx);
    writer.abort();
}

pub fn router() -> Router {
    Router::new()
        .route(
            "/v1/frame",
            post(frame).layer(DefaultBodyLimit::max(REQUEST_MAX)),
        )
        .route("/v1/ws/{route}", get(subscribe))
        .route(
            "/v1/file/{route}/{file}/{part}",
            get(get_part)
                .put(put_part)
                .layer(DefaultBodyLimit::max(PART_MAX)),
        )
        .with_state(Shared::default())
}

/// Serves on `listener` until the task is dropped; returns the bound address.
pub async fn serve(
    listener: TcpListener,
) -> std::io::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, router()).await;
    });
    Ok((addr, task))
}
