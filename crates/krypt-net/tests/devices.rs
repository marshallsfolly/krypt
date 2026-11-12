//! Real devices: SQLite stores, WebSocket subscriptions, a mailbox (the dev
//! mailbox, or the edge via `KRYPT_TEST_MAILBOX`), and the actual clocks.

use std::path::Path;
use std::time::Duration;

use krypt_net::{Config, Content, Event, Node};
use tokio::sync::broadcast;
use tokio::time::{Instant, timeout};

/// The dev mailbox, or the one in `KRYPT_TEST_MAILBOX` (e.g. `wrangler dev`
/// or production) to run the same tests against the edge.
async fn mailbox() -> String {
    if let Ok(url) = std::env::var("KRYPT_TEST_MAILBOX") {
        return url;
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let (addr, task) = krypt_devmailbox::serve(listener)
        .await
        .expect("serve mailbox");
    // The server lives for the rest of the test process.
    std::mem::forget(task);
    format!("http://{addr}")
}

fn config(dir: &Path, mailbox: &str, poll_ms: u64) -> Config {
    let mut config = Config::new(dir, mailbox);
    config.client.poll_interval_ms = poll_ms;
    config
}

/// Waits for the first event matching `pick`.
async fn wait_for<T>(
    events: &mut broadcast::Receiver<Event>,
    within: Duration,
    mut pick: impl FnMut(&Event) -> Option<T>,
) -> T {
    timeout(within, async {
        loop {
            match events.recv().await {
                Ok(event) => {
                    if let Some(found) = pick(&event) {
                        return found;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(e) => panic!("event stream ended: {e}"),
            }
        }
    })
    .await
    .expect("timed out waiting for an event")
}

fn message(text: &'static str) -> impl FnMut(&Event) -> Option<()> {
    move |event| {
        matches!(event, Event::Message { content: Content::Text(t), .. } if t == text).then_some(())
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn two_devices_chat_both_ways() {
    let mailbox = mailbox().await;
    let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let alice = Node::open(config(a.path(), &mailbox, 200)).await.unwrap();
    let bob = Node::open(config(b.path(), &mailbox, 200)).await.unwrap();
    let mut alice_events = alice.subscribe();
    let mut bob_events = bob.subscribe();

    let conversation = alice.start_conversation(bob.contact_card()).await.unwrap();
    let joined = wait_for(&mut bob_events, Duration::from_secs(15), |e| match e {
        Event::Joined { conversation, .. } => Some(*conversation),
        _ => None,
    })
    .await;
    assert_eq!(joined, conversation);

    alice.send(conversation, "hello bob").await.unwrap();
    wait_for(
        &mut bob_events,
        Duration::from_secs(10),
        message("hello bob"),
    )
    .await;
    bob.send(conversation, "hi alice").await.unwrap();
    wait_for(
        &mut alice_events,
        Duration::from_secs(10),
        message("hi alice"),
    )
    .await;

    let listed = alice.conversations().await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].members.len(), 2);

    alice.shutdown().await;
    bob.shutdown().await;
}

/// A file crosses the mailbox sealed, opens intact on the other side, and a
/// stored part can never be replaced, not even by a member.
#[tokio::test(flavor = "multi_thread")]
async fn a_shared_file_arrives_intact_and_parts_are_never_replaced() {
    let mailbox = mailbox().await;
    let (a, b, c) = (
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
    );
    let alice = Node::open(config(a.path(), &mailbox, 200)).await.unwrap();
    let bob = Node::open(config(b.path(), &mailbox, 200)).await.unwrap();
    let carol = Node::open(config(c.path(), &mailbox, 200)).await.unwrap();
    let mut bob_events = bob.subscribe();
    let conversation = alice.start_conversation(bob.contact_card()).await.unwrap();
    wait_for(&mut bob_events, Duration::from_secs(15), |e| {
        matches!(e, Event::Joined { .. }).then_some(())
    })
    .await;

    // Two parts: one full, one short.
    #[allow(clippy::cast_possible_truncation)]
    let bytes: Vec<u8> = (0..4 * 1024 * 1024 + 1_000)
        .map(|i| (i % 251) as u8)
        .collect();
    alice
        .send_file(
            conversation,
            &bytes,
            "notes.bin",
            "application/octet-stream",
        )
        .await
        .unwrap();
    let shared = wait_for(&mut bob_events, Duration::from_secs(30), |e| match e {
        Event::Message {
            content: Content::File(file),
            ..
        } => Some((**file).clone()),
        _ => None,
    })
    .await;
    assert_eq!(shared.name, "notes.bin");
    assert_eq!(bob.fetch_file(conversation, &shared).await.unwrap(), bytes);

    // A member's attempt to replace a part is answered "already stored".
    let garbage = vec![0xEE; 4 * 1024 * 1024 + 16];
    let status = bob
        .store_part(conversation, shared.id, 0, garbage)
        .await
        .unwrap();
    assert_eq!(status, 200);
    assert_eq!(bob.fetch_file(conversation, &shared).await.unwrap(), bytes);
    // Someone outside the conversation cannot even make a proof.
    assert!(
        carol
            .store_part(conversation, [7; 16], 0, vec![0; 100])
            .await
            .is_err()
    );

    alice.shutdown().await;
    bob.shutdown().await;
    carol.shutdown().await;
}

/// With polling effectively off, only the mailbox's WebSocket push can
/// deliver within the deadline.
#[tokio::test(flavor = "multi_thread")]
async fn the_mailbox_pushes_without_polling() {
    let mailbox = mailbox().await;
    let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let quiet = |dir| config(dir, &mailbox, 600_000);
    let alice = Node::open(quiet(a.path())).await.unwrap();
    let bob = Node::open(quiet(b.path())).await.unwrap();
    let mut bob_events = bob.subscribe();
    // Let both devices publish key packages and subscribe to their inboxes.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let conversation = alice.start_conversation(bob.contact_card()).await.unwrap();
    let joined = wait_for(&mut bob_events, Duration::from_secs(5), |e| match e {
        Event::Joined { conversation, .. } => Some(*conversation),
        _ => None,
    })
    .await;
    assert_eq!(joined, conversation);
    // Bob's subscription to the new conversation connects after joining.
    tokio::time::sleep(Duration::from_millis(500)).await;

    for text in ["one", "two", "three"] {
        let sent = Instant::now();
        alice.send(conversation, text).await.unwrap();
        wait_for(&mut bob_events, Duration::from_secs(2), message(text)).await;
        println!("pushed {text:?} in {:?}", sent.elapsed());
    }
    alice.shutdown().await;
    bob.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn offline_device_catches_up_from_the_mailbox() {
    let mailbox = mailbox().await;
    let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let alice = Node::open(config(a.path(), &mailbox, 200)).await.unwrap();
    let bob = Node::open(config(b.path(), &mailbox, 200)).await.unwrap();
    let bob_device = bob.device();
    let mut bob_events = bob.subscribe();

    let conversation = alice.start_conversation(bob.contact_card()).await.unwrap();
    wait_for(&mut bob_events, Duration::from_secs(15), |e| {
        matches!(e, Event::Joined { .. }).then_some(())
    })
    .await;
    bob.shutdown().await;

    alice
        .send(conversation, "while you were away")
        .await
        .unwrap();

    // Same directory: same identity, same device, same history.
    let bob = Node::open(config(b.path(), &mailbox, 200)).await.unwrap();
    assert_eq!(bob.device(), bob_device);
    let mut bob_events = bob.subscribe();
    wait_for(
        &mut bob_events,
        Duration::from_secs(15),
        message("while you were away"),
    )
    .await;
    assert_eq!(bob.conversations().await.unwrap()[0].id, conversation);

    alice.shutdown().await;
    bob.shutdown().await;
}

/// Against the edge (`KRYPT_TEST_MAILBOX`): strangers probing random routes
/// get nothing, and (checked from outside) leave no storage behind.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs KRYPT_TEST_MAILBOX"]
async fn strangers_get_nothing() {
    use krypt_wire::frame::{self, Kind};
    use krypt_wire::msg::{Entries, Fetch};
    let base = std::env::var("KRYPT_TEST_MAILBOX").expect("KRYPT_TEST_MAILBOX");
    let http = krypt_net::mailbox::HttpMailbox::new(&base).unwrap();
    for i in 0..20u8 {
        let route = [i ^ 0xA5; 16];
        let fetch = Fetch { after: 0, max: 64 }.encode();
        let response = http
            .request(frame::encode_vec(Kind::Fetch, 1, route, &fetch))
            .await
            .unwrap()
            .expect("a response");
        // A log nobody has written is simply empty.
        let response = frame::decode(&response).unwrap();
        assert_eq!(response.kind, Kind::Entries);
        assert!(Entries::decode(response.body).unwrap().entries.is_empty());
        let claim = frame::encode_vec(Kind::ClaimKeyPackage, 2, route, &[]);
        http.request(claim).await.unwrap();
    }
    let ws = format!("{}/v1/ws/{}", base.replace("http", "ws"), "a5".repeat(16));
    let refused = tokio_tungstenite::connect_async(ws.as_str()).await;
    assert!(refused.is_err(), "subscribed to a log that does not exist");
}

/// Against the local edge with push enabled (`just edge-dev-push`; then
/// `KRYPT_TEST_MAILBOX=http://127.0.0.1:8788 KRYPT_TEST_PUSH=1`): a device
/// with a push target is woken, by an empty Web Push request whose VAPID
/// token verifies, both when invited and when a message arrives.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the local edge with push enabled"]
async fn the_edge_wakes_devices() {
    use axum::extract::Path as UrlPath;
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::post;
    use data_encoding::BASE64URL_NOPAD;
    use krypt_net::Platform;
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};

    assert!(
        std::env::var("KRYPT_TEST_PUSH").is_ok(),
        "set KRYPT_TEST_PUSH=1"
    );
    let mailbox = mailbox().await;
    let (pushes, mut pushed) = tokio::sync::mpsc::unbounded_channel();
    let service = axum::Router::new().route(
        "/push/{device}",
        post(
            move |UrlPath(device): UrlPath<String>, headers: HeaderMap, body: axum::body::Bytes| {
                let pushes = pushes.clone();
                async move {
                    let header = |name: &str| {
                        headers
                            .get(name)
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_owned()
                    };
                    let _ = pushes.send((
                        device,
                        header("authorization"),
                        header("ttl"),
                        header("urgency"),
                        body.len(),
                    ));
                    StatusCode::CREATED
                }
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, service).await });

    let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let alice = Node::open(config(a.path(), &mailbox, 600_000))
        .await
        .unwrap();
    let bob = Node::open(config(b.path(), &mailbox, 600_000))
        .await
        .unwrap();
    let mut bob_events = bob.subscribe();
    bob.set_push_target(Some((
        Platform::WebPush,
        format!("{origin}/push/bob").into_bytes(),
    )))
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(1_000)).await;

    let check =
        |(device, authorization, ttl, urgency, length): (String, String, String, String, usize)| {
            assert_eq!(
                (device.as_str(), ttl.as_str(), urgency.as_str(), length),
                ("bob", "86400", "high", 0)
            );
            let (token, public) = authorization
                .strip_prefix("vapid t=")
                .and_then(|rest| rest.split_once(", k="))
                .expect("a VAPID authorization");
            let (signed, signature) = token.rsplit_once('.').unwrap();
            let claims = BASE64URL_NOPAD
                .decode(signed.split('.').nth(1).unwrap().as_bytes())
                .unwrap();
            let claims = String::from_utf8(claims).unwrap();
            assert!(claims.contains(&format!(r#""aud":"{origin}""#)), "{claims}");
            let key =
                VerifyingKey::from_sec1_bytes(&BASE64URL_NOPAD.decode(public.as_bytes()).unwrap())
                    .unwrap();
            let signature =
                Signature::from_slice(&BASE64URL_NOPAD.decode(signature.as_bytes()).unwrap())
                    .unwrap();
            key.verify(signed.as_bytes(), &signature)
                .expect("the token verifies");
        };

    // Invited: the welcome lands in Bob's inbox, which wakes him.
    let conversation = alice.start_conversation(bob.contact_card()).await.unwrap();
    check(
        timeout(Duration::from_secs(10), pushed.recv())
            .await
            .expect("a wakeup for the invitation")
            .unwrap(),
    );
    wait_for(&mut bob_events, Duration::from_secs(10), |e| {
        matches!(e, Event::Joined { .. }).then_some(())
    })
    .await;
    tokio::time::sleep(Duration::from_millis(1_000)).await;
    while pushed.try_recv().is_ok() {}

    // A message in the conversation wakes him again.
    alice.send(conversation, "wake up").await.unwrap();
    check(
        timeout(Duration::from_secs(10), pushed.recv())
            .await
            .expect("a wakeup for the message")
            .unwrap(),
    );

    alice.shutdown().await;
    bob.shutdown().await;
}
