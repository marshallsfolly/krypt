# Engineering style

krypt borrows TigerBeetle's discipline, adapted to Rust. These rules are
checked by code review, by `nix flake check`, and most of all by the
simulator.

## 1. Sans-IO cores

Protocol logic (`krypt-core`) never performs IO, reads a clock or draws OS
randomness on its own:
- time arrives as `now_ms`
- randomness comes through `provider::Rand`, seeded in simulation
- every effect (frames to send, events for the UI) is *returned*

This lets the same state machines run on a phone, at the edge (the mailbox),
and inside `krypt-sim`.

## 2. Persist, then act

Every client call returns a `Step { writes, effects }`. The driver must make
`writes` durable, as one atomic batch, *before* performing any effect.

- **Why:** a device may never forget a frame it has already sent. For MLS,
  forgetting means re-encrypting with a consumed generation after a crash,
  which is nonce reuse.
- **How it's tested:** the simulator crashes devices between persist and
  effects, and mid-step (losing both writes and effects).
- **Batching:** `krypt-store` commits each batch in one SQLite transaction with
  `synchronous = FULL`. `Store::apply_many` lets drivers group-commit several
  steps behind a single fsync.

## 3. One path for state changes

A group's state advances only in log order, and that includes a device's own
commits: they merge when the device reads them from the conversation log, not
when the mailbox acknowledges them. Recovery after a crash is therefore not a
separate code path.

## 4. Everything is bounded

Every queue, list and buffer has a limit in `krypt-wire::limits`, and every
decoder enforces it before allocating. No unbounded growth, anywhere. When a
limit is reached, the operation is refused (for example `Error::OutboxFull`)
instead of degrading silently.

## 5. Assertions are documentation that runs

- Invariants that would mean memory corruption or a logic error use `assert!`,
  and stay on in release builds.
- Conditions caused by input (malformed frames, misbehaving peers, damaged
  storage) are handled as values and never panic. The fuzz targets in
  `fuzz/` hold every decoder, the mailbox and the client to this.
- `#![forbid(unsafe_code)]` applies across the workspace.

## 6. Determinism

- No `HashMap` iteration in protocol code; use `BTreeMap`/`BTreeSet`.
- Nothing branches on ciphertext byte values; hashes are only compared for
  equality.

Together these mean a simulator seed always replays the same trace, which the
simulator checks (`--determinism`) and `nix flake check` enforces.

Known limit: OpenMLS draws HPKE and signature-key randomness from the OS, so
ciphertext *bytes* differ between runs. Control flow does not.

## 7. Loud failure

- A failure the user should know about becomes an `Event`: `Undecryptable`,
  `Desync`, `InviteFailed`.
- Errors are never swallowed silently. In an honest network the simulator
  treats any of these events as a bug.

## 8. Measure before optimizing

- Hot paths have divan benchmarks: `just bench`.
- Profiles come from `perf`: `just profile <bench>`.
- `docs/perf.md` records the current numbers and where the time goes.

## Tooling

| Command | What it does |
|---|---|
| `just check` | fmt, clippy `-D warnings`, tests, then `nix flake check` |
| `just sim [seeds] [args]` | Simulator over many seeds, with replay checks |
| `just sim-trace <seed>` | Replay one seed with a full event trace |
| `just bench` / `just profile <bench>` | Benchmarks and CPU profiles |
| `just fuzz <target> [seconds]` | libFuzzer on hostile input (wire, scrubbers, mailbox, client, identity), nightly shell; `just fuzz-all` runs every target |
| `just audit` | RustSec and npm advisories, cargo-vet (needs the network) |
| `just vendor-mls-store` | Regenerate vendored OpenMLS storage after an upgrade |
