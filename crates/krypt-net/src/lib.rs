//! Runs a krypt device on real networks.
//!
//! [`Node`] drives the sans-IO client from `krypt-core`: it persists every
//! step to `krypt-store` before acting on it, and follows its logs over
//! WebSockets to the mailbox (HTTP when a socket is down). Messages travel
//! only through the mailbox, so no peer ever learns a device's IP address.

pub mod mailbox;
mod node;
mod subscribe;

pub use krypt_core::client::{Content, Event, SharedFile};
pub use krypt_wire::msg::Platform;
pub use node::{Config, Conversation, Error, Node};

/// rustls needs exactly one process-wide crypto provider; krypt uses ring.
pub(crate) fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
