//! Shared by krypt's fuzz targets and their seed generator.
//!
//! - [`input`] reads the fuzzer's bytes as a script of operations; past the
//!   end every read is zero, so every input means something.
//! - [`check`] holds what must be true of every frame krypt emits, whatever
//!   it was fed: it decodes, and it answers what was asked.
//! - [`fixture`] is a device in two real conversations, with the log entries
//!   meant for it. MLS draws OS randomness, so that state is written once
//!   (`seeds --fixture`) and committed rather than rebuilt: every crash
//!   replays against the same device.
//! - [`client`] and [`mailbox`] run scripts against a device and a mailbox.
//!   The targets and the seed generator share them, so seeds mean exactly
//!   what the targets will do with them.
//! - [`scenario`] is the conversation the fixture and seeds come from.

pub mod check;
pub mod client;
pub mod fixture;
pub mod input;
pub mod mailbox;
pub mod scenario;
