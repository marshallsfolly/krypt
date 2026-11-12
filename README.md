# krypt

An end-to-end encrypted messenger for the web, at [krypt.chat](https://krypt.chat).

- Conversations use MLS (RFC 9420) with a post-quantum hybrid key exchange
  (X-Wing), through a mailbox on Cloudflare that stores only ciphertext.
- No phone number or account: an identity is a key on your device; a
  passkey can back it up and claim an @handle.
- Groups with admins and invite links, calls, files with their metadata
  removed, disappearing messages, linked devices.

The core is Rust (`crates/`), sans-IO and checked by a deterministic
simulator; the app is SolidJS over the core in WebAssembly (`apps/web`);
the mailbox is a Cloudflare Worker with Durable Objects (`services/edge`).

## Reading

- [docs/threat-model.md](docs/threat-model.md): what krypt protects, from
  whom, and what it does not.
- [docs/protocol.md](docs/protocol.md): how it works.
- [docs/releases.md](docs/releases.md): how releases are built, signed,
  pinned in the browser, and how to check one.
- [docs/decisions.md](docs/decisions.md): every decision and what it rules
  out.

krypt has had an internal security review (decision 53), not an
independent audit.

## Building

Everything builds from the Nix flake: `nix develop`, then `just` lists the
tasks (`just check` runs the tests and lints, `just web-dev` the app
against a local mailbox).
