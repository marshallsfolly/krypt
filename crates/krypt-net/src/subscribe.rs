//! Live subscriptions: one WebSocket per log the device follows. The mailbox
//! pushes each new entry over it the moment it lands, so the device never
//! polls, and requests for that log ride the same socket, which the edge
//! bills at a twentieth of an HTTP request.
//!
//! A socket that drops reconnects with backoff, and every (re)connect makes
//! the device fetch what it missed. A log that does not exist yet (an inbox
//! before its first publish, a conversation before its first commit) is
//! refused and retried the same way.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt as _, StreamExt as _};
use krypt_wire::Route;
use krypt_wire::frame::HEADER_SIZE;
use krypt_wire::limits::FRAME_BODY_MAX;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_tungstenite::Connector;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tracing::debug;

/// Keepalive interval; Cloudflare closes WebSockets idle for 100 seconds.
/// The edge answers "ping" without waking the log's object.
const PING: Duration = Duration::from_secs(30);
const BACKOFF_MIN: Duration = Duration::from_millis(500);
const BACKOFF_MAX: Duration = Duration::from_secs(30);
/// Requests queued on one socket before falling back to HTTP.
const QUEUE_MAX: usize = 64;

type OnFrame = Arc<dyn Fn(Vec<u8>) + Send + Sync>;
type OnConnected = Arc<dyn Fn(Route) + Send + Sync>;

struct Socket {
    task: JoinHandle<()>,
    /// Present while connected.
    outgoing: Arc<Mutex<Option<mpsc::Sender<Vec<u8>>>>>,
}

pub(crate) struct Subscriptions {
    base: String,
    connector: Option<Connector>,
    on_frame: OnFrame,
    on_connected: OnConnected,
    sockets: Mutex<BTreeMap<Route, Socket>>,
}

impl std::fmt::Debug for Subscriptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Subscriptions")
            .field("base", &self.base)
            .finish_non_exhaustive()
    }
}

fn hex(route: &Route) -> String {
    route.iter().map(|b| format!("{b:02x}")).collect()
}

/// Up to a quarter of `delay` extra, so devices that lost the same
/// connection do not all come back at once.
fn jittered(delay: Duration) -> Duration {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    delay + delay.mul_f64(f64::from(nanos % 1000) / 4000.0)
}

impl Subscriptions {
    /// `mailbox` is the mailbox's HTTP base URL; sockets use the same host.
    pub(crate) fn new(
        mailbox: &str,
        on_frame: impl Fn(Vec<u8>) + Send + Sync + 'static,
        on_connected: impl Fn(Route) + Send + Sync + 'static,
    ) -> Result<Subscriptions, crate::mailbox::Error> {
        let mailbox = mailbox.trim_end_matches('/');
        let (base, connector) = if let Some(host) = mailbox.strip_prefix("https://") {
            use rustls_platform_verifier::ConfigVerifierExt as _;
            let config = rustls::ClientConfig::with_platform_verifier()
                .map_err(|e| crate::mailbox::Error::Tls(e.to_string()))?;
            (
                format!("wss://{host}"),
                Some(Connector::Rustls(Arc::new(config))),
            )
        } else {
            let host = mailbox.strip_prefix("http://").unwrap_or(mailbox);
            (format!("ws://{host}"), None)
        };
        Ok(Subscriptions {
            base,
            connector,
            on_frame: Arc::new(on_frame),
            on_connected: Arc::new(on_connected),
            sockets: Mutex::new(BTreeMap::new()),
        })
    }

    /// Follows exactly `routes`: opens sockets for new ones, closes the rest.
    pub(crate) fn set_routes(&self, routes: &BTreeSet<Route>) {
        let mut sockets = self.sockets.lock().expect("subscriptions lock");
        sockets.retain(|route, socket| {
            let keep = routes.contains(route);
            if !keep {
                socket.task.abort();
            }
            keep
        });
        for route in routes {
            if sockets.contains_key(route) {
                continue;
            }
            let outgoing = Arc::new(Mutex::new(None));
            let task = tokio::spawn(follow(
                format!("{}/v1/ws/{}", self.base, hex(route)),
                *route,
                self.connector.clone(),
                Arc::clone(&outgoing),
                Arc::clone(&self.on_frame),
                Arc::clone(&self.on_connected),
            ));
            sockets.insert(*route, Socket { task, outgoing });
        }
    }

    /// Sends a request over its log's socket if one is connected; otherwise
    /// hands it back for HTTP.
    pub(crate) fn try_send(&self, frame: Vec<u8>) -> Result<(), Vec<u8>> {
        let Some(route) = frame
            .get(HEADER_SIZE - 16..HEADER_SIZE)
            .and_then(|r| Route::try_from(r).ok())
        else {
            return Err(frame);
        };
        let sockets = self.sockets.lock().expect("subscriptions lock");
        let Some(sender) = sockets
            .get(&route)
            .and_then(|s| s.outgoing.lock().expect("socket lock").clone())
        else {
            return Err(frame);
        };
        sender.try_send(frame).map_err(|e| e.into_inner())
    }
}

impl Drop for Subscriptions {
    fn drop(&mut self) {
        for socket in self.sockets.lock().expect("subscriptions lock").values() {
            socket.task.abort();
        }
    }
}

async fn follow(
    url: String,
    route: Route,
    connector: Option<Connector>,
    outgoing: Arc<Mutex<Option<mpsc::Sender<Vec<u8>>>>>,
    on_frame: OnFrame,
    on_connected: OnConnected,
) {
    let mut config = WebSocketConfig::default();
    config.max_message_size = Some(HEADER_SIZE + FRAME_BODY_MAX as usize);
    config.max_frame_size = config.max_message_size;
    let mut backoff = BACKOFF_MIN;
    loop {
        let connected = tokio_tungstenite::connect_async_tls_with_config(
            url.as_str(),
            Some(config),
            false,
            connector.clone(),
        )
        .await;
        match connected {
            Ok((socket, _)) => {
                backoff = BACKOFF_MIN;
                let (sender, mut requests) = mpsc::channel(QUEUE_MAX);
                *outgoing.lock().expect("socket lock") = Some(sender);
                on_connected(route);
                let (mut sink, mut stream) = socket.split();
                let mut ping = tokio::time::interval(PING);
                ping.tick().await;
                loop {
                    tokio::select! {
                        message = stream.next() => match message {
                            Some(Ok(Message::Binary(bytes))) => on_frame(bytes.to_vec()),
                            Some(Ok(Message::Close(_)) | Err(_)) | None => break,
                            Some(Ok(_)) => {}
                        },
                        Some(request) = requests.recv() => {
                            if sink.send(Message::Binary(request.into())).await.is_err() {
                                break;
                            }
                        }
                        _ = ping.tick() => {
                            if sink.send(Message::Text("ping".into())).await.is_err() {
                                break;
                            }
                        }
                    }
                }
                *outgoing.lock().expect("socket lock") = None;
                debug!("subscription to {} closed", hex(&route));
            }
            Err(e) => debug!("subscribing to {}: {e}", hex(&route)),
        }
        tokio::time::sleep(jittered(backoff)).await;
        backoff = (backoff * 2).min(BACKOFF_MAX);
    }
}
