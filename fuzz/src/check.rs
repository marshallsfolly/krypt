//! What must hold of every frame krypt emits, whatever it was fed.

use krypt_wire::frame::{self, Kind, Route};
use krypt_wire::msg::{
    Accepted, Entries, Fetch, FilePart, KeyPackages, PushTarget, Rejected, Submit, Watch,
};
use openmls::prelude::KeyPackageIn;
use openmls::prelude::tls_codec::Deserialize as _;

/// A request a device sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sent {
    pub seq: u64,
    pub kind: Kind,
    pub route: Route,
}

fn key_package(bytes: &[u8]) {
    KeyPackageIn::tls_deserialize_exact(bytes).expect("a key package parses");
}

/// A device's request: a frame of a request kind whose body decodes.
pub fn request(bytes: &[u8]) -> Sent {
    let f = frame::decode(bytes).expect("a request frame decodes");
    match f.kind {
        Kind::Submit => {
            Submit::decode(f.body).expect("a submit decodes");
        }
        Kind::Fetch => {
            Fetch::decode(f.body).expect("a fetch decodes");
        }
        Kind::PublishKeyPackages => {
            let list = KeyPackages::decode(f.body).expect("key packages decode");
            list.list.iter().for_each(|kp| key_package(kp));
        }
        Kind::ClaimKeyPackage => assert!(f.body.is_empty(), "a claim has no body"),
        Kind::Watch => {
            Watch::decode(f.body).expect("a watch decodes");
        }
        Kind::Signal => {
            krypt_wire::msg::Signal::decode(f.body).expect("a signal decodes");
        }
        Kind::OpenRequests => {
            krypt_wire::msg::OpenRequests::decode(f.body).expect("opening a requests log decodes");
        }
        other => panic!("a device sent {other:?}, which is not a request"),
    }
    Sent {
        seq: f.seq,
        kind: f.kind,
        route: f.route,
    }
}

fn is_request(kind: Kind) -> bool {
    matches!(
        kind,
        Kind::Submit
            | Kind::Fetch
            | Kind::PublishKeyPackages
            | Kind::ClaimKeyPackage
            | Kind::Watch
            | Kind::AuthorizeFile
            | Kind::AuthorizeTurn
            | Kind::Signal
            | Kind::OpenRequests
            | Kind::JoinRequest
            | Kind::JoinHeader
    )
}

/// The mailbox answers a request frame, and nothing else, with one response
/// for the same request id and route, of a kind that answers that request,
/// whose body decodes.
pub fn response(request: &[u8], response: Option<&[u8]>) {
    let request = frame::decode(request).ok().filter(|f| is_request(f.kind));
    let (request, response) = match (request, response) {
        (None, None) => return,
        (Some(request), Some(response)) => (request, response),
        (request, response) => panic!(
            "{:?} was answered: {}",
            request.map(|r| r.kind),
            response.is_some()
        ),
    };
    let f = frame::decode(response).expect("a response decodes");
    assert_eq!(
        (f.seq, f.route),
        (request.seq, request.route),
        "a response answers its request"
    );
    match (request.kind, f.kind) {
        (_, Kind::Rejected) => {
            Rejected::decode(f.body).expect("a rejection decodes");
        }
        (Kind::Fetch, Kind::Entries) => {
            Entries::decode(f.body).expect("entries decode");
        }
        (Kind::ClaimKeyPackage, Kind::KeyPackage) => key_package(f.body),
        // A requests log's header, as its admin wrote it.
        (Kind::JoinHeader, Kind::Header) => {}
        (
            Kind::Submit
            | Kind::PublishKeyPackages
            | Kind::Watch
            | Kind::AuthorizeFile
            | Kind::AuthorizeTurn
            | Kind::Signal
            | Kind::OpenRequests
            | Kind::JoinRequest,
            Kind::Accepted,
        ) => {
            Accepted::decode(f.body).expect("an acceptance decodes");
        }
        (asked, answer) => panic!("{asked:?} was answered with {answer:?}"),
    }
    // An authorized upload's proof was well formed.
    if request.kind == Kind::AuthorizeFile && f.kind == Kind::Accepted {
        FilePart::decode(request.body).expect("an authorized part decodes");
    }
}

/// A push: a `Notify` frame carrying entries, or a relayed signal.
pub fn notify(bytes: &[u8]) {
    let f = frame::decode(bytes).expect("a push decodes");
    match f.kind {
        Kind::Notify => {
            Entries::decode(f.body).expect("a push carries entries");
        }
        Kind::Signaled => {
            krypt_wire::msg::Signal::decode(f.body).expect("a relayed signal decodes");
        }
        other => panic!("a push of kind {other:?}"),
    }
}

/// A wakeup goes to a well-formed push target.
pub fn wakeup(bytes: &[u8]) {
    PushTarget::decode(bytes).expect("a wakeup target decodes");
}
