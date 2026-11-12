//! krypt's wire format: frames, message bodies and the hard limits that bound
//! them. Nothing here allocates more than a limit allows, and every decoder
//! rejects malformed input instead of panicking.

pub mod codec;
pub mod frame;
pub mod limits;
pub mod msg;

pub use frame::{Frame, FrameError, HEADER_SIZE, Kind, Route};
