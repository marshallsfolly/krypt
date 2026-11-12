//! Scripts against the mailbox: a sequence of request frames, from anyone,
//! with time passing between them.

use krypt_core::mailbox::LocalMailbox;
use krypt_wire::frame::{self, Kind, Route};

use crate::check;
use crate::input::Input;

/// 2026-10-27: requests arrive at plausible times. Time never runs anywhere
/// near overflow: 1,024 steps of at most 455 days each.
pub const START_MS: u64 = 1_793_000_000_000;
pub const OPS_MAX: usize = 1024;
/// Routes a structured request can name by index: the first ones seen.
const ROUTES_MAX: usize = 16;

/// Flags, the first byte of each step. The low two bits say how time
/// advances before the request: not at all, or by a `u16` of milliseconds,
/// seconds or ten-minute spans.
pub mod flag {
    pub const TIME_MS: u8 = 1;
    pub const TIME_S: u8 = 2;
    pub const TIME_10_MIN: u8 = 3;
    /// The request is raw bytes, sent as is.
    pub const RAW: u8 = 4;
    /// Run expiry over every log after the request.
    pub const EXPIRE: u8 = 8;
}

/// In a structured request, this bit of the route selector says the route
/// follows in full; otherwise it picks one already seen.
pub const ROUTE_GIVEN: u8 = 0x80;

/// Frames a structured request (`kind, route selector, id, [route,] body`)
/// with correct checksums.
fn structured(bytes: &[u8], routes: &[Route]) -> Vec<u8> {
    let mut input = Input::new(bytes);
    let kind = Kind::from_u8(input.u8()).unwrap_or(Kind::Submit);
    let sel = input.u8();
    let seq = input.u64();
    let route = if sel & ROUTE_GIVEN != 0 || routes.is_empty() {
        input.array()
    } else {
        routes[usize::from(sel) % routes.len()]
    };
    frame::encode_vec(kind, seq, route, input.rest())
}

/// Runs one script: every request gets the response it should, and every
/// push and wakeup is well formed.
pub fn run(input: &mut Input) {
    let mut mailbox = LocalMailbox::new();
    let mut now = START_MS;
    let mut routes = Vec::new();
    for _ in 0..OPS_MAX {
        if input.is_empty() {
            break;
        }
        let flags = input.u8();
        now += match flags & 3 {
            0 => 0,
            flag::TIME_MS => u64::from(input.u16()),
            flag::TIME_S => u64::from(input.u16()) * 1_000,
            _ => u64::from(input.u16()) * 600_000,
        };
        let bytes = input.chunk();
        let request = if flags & flag::RAW != 0 {
            bytes.to_vec()
        } else {
            structured(bytes, &routes)
        };
        let response = mailbox.handle(now, &request);
        check::response(&request, response.as_deref());
        if let Ok(f) = frame::decode(&request)
            && routes.len() < ROUTES_MAX
            && !routes.contains(&f.route)
        {
            routes.push(f.route);
        }
        if flags & flag::EXPIRE != 0 {
            mailbox.expire(now);
        }
        for (_, notify) in mailbox.take_notifications() {
            check::notify(&notify);
        }
        for (_, wakeup) in mailbox.take_wakeups() {
            check::wakeup(&wakeup);
        }
    }
}
