# Performance

Machine: Intel i7-13700K (AVX2). Release build, Rust 1.99.1. Run with
`just bench`; profile with `just profile <bench>`.

## Current numbers (2026-11-06)

| Path | Median | Throughput |
|---|---|---|
| Send one message: seal, membership tag, frame, persist batch, mailbox round trip | 28.8 µs | ~35k msg/s/core |
| Receive one pushed message: decode, decrypt, verify, dedup, deliver | 33.9 µs | ~29k msg/s/core |
| Storage written per message sent | 0.9 KB (2 members), 1.3 KB (33) | 2.2 KB and 4.1 KB with OpenMLS state as JSON; 4.4 KB and 1.35 MB with 8 past epochs kept |
| Storage written processing a commit | 8.5 KB (2 members), 102 KB (33) | 29 KB and 373 KB as JSON |
| Restarting a device (restore) | 0.08–0.10 ms (2 members), 0.17–0.21 ms (33) | 0.17–0.24 ms and 1.7–1.8 ms as JSON |
| Frame encode, 64 B / 16 KiB | 93 ns / 3.1 µs | 5.2 GB/s at 16 KiB |
| Frame decode, 64 B / 16 KiB | 81 ns / 3.0 µs | 5.4 GB/s at 16 KiB |
| Simulator | 10,000 seeds in 124 s (16 threads) | ~1.2 M simulated messages, hostile client included; 75 s before post-quantum keys |
| Push, production (send → delivered, polling off) | 124–210 ms | from Los Angeles, where the TCP connect alone takes 140–190 ms; the edge adds little |
| Push, local dev mailbox | 2–26 ms | loopback |
| Edge cost per message | 1 row written | commits: 4; expiry: one alarm per log per day at most |

## Post-quantum costs (2026-11-06)

X-Wing (X25519 + ML-KEM-768) keys are 1,216 bytes instead of 32, so only
messages and state that carry keys grow. Chat messages carry none.

| | Classic | Post-quantum |
|---|---|---|
| Key package | 432 B | 2.8 KB |
| Welcome into a full 128-member group | 54 KB | 360 KB |
| Largest add in a 128-member group (commit + welcome) | 55 KB | 382 KB |
| Storage written processing one commit, 33 members | — | 102 KB (373 KB as JSON) |
| Browser core (wasm, raw) | 1.53 MB | 1.60 MB |
| Simulator, 10,000 seeds | 75 s | 124 s |

## Files (2026-11-06)

| | Cost |
|---|---|
| Sealing a 4 MiB part (ChaCha20-Poly1305, one core, this machine) | 2.1 ms, about 2 GB/s (plan target: 1.5 GB/s) |
| Storing a part | 1 Worker request, 1 Durable Object request, 1 row written (the day's allowance), 1 R2 write ($4.50 per million) |
| Fetching a part | 1 Worker request, 1 R2 read ($0.36 per million); downloads are free |
| Keeping it | $0.015 per GB a month after 10 GB, for at most 30 days |
| A 3 MB photo, sent to a group of 10 who all open it | about $0.00006: $0.00001 in requests, the rest a month of storage (free under 10 GB) |
| Browser core (wasm, raw) | 1.64 MB (+35 KB: the cipher and the metadata scrubber) |

The part body streams from the request into R2 without passing through the
Worker's code, so a part costs the same CPU as a chat message.

## OpenMLS state at rest (2026-11-06)

OpenMLS rewrites its whole ratchet tree on every commit, and the vendored
store wrote it as JSON, which spells each byte as a number. It now writes
postcard (decision 39). Measured by `just bench` (the `restore` benchmark
prints the bytes): a device's writes while it sends one message until the
mailbox has it, and while it processes another member's commit; every node
of the tree filled.

| | 2 members, JSON | 2 members, postcard | 33 members, JSON | 33 members, postcard |
|---|---|---|---|---|
| Written sending a message | 2,186 B | 880 B (2.5×) | 4,132 B | 1,292 B (3.2×) |
| Written processing a commit | 29,177 B | 8,472 B (3.4×) | 372,880 B | 101,652 B (3.7×) |
| Stored (one device) | 128 KB | 36 KB | 471 KB | 129 KB |
| Restore, median of two runs | 169–236 µs | 84–99 µs | 1.74–1.79 ms | 0.17–0.21 ms (≈9×) |
| Browser core (wasm, raw) | 1.64 MB | 1.67 MB | | |

Byte counts are exact and repeat run to run. The times were taken on a
machine shared with other builds (load average 40–60), so only their ratios
mean much; send and receive times were not re-measured. At 256 members the
tree costs roughly 0.8 MB per commit instead of 2.9 MB.

## Where the time goes

`perf` on `send_message`:
- **~68% is Ed25519 signing.** That's curve25519-dalek field arithmetic for the
  basepoint scalar multiplication and point compression.
- The rest is AES-GCM, storage serialization (the vendored OpenMLS store;
  serde_json took about 3–7% before it became postcard) and copying.

`receive_pushed` is dominated by Ed25519 verification, which already runs on
curve25519-dalek's AVX2 backend.

Every MLS application message is signed by its sender and verified by every
receiver (RFC 9420 FramedContent signatures), so for chat messages the
signature is the floor. The original budget of under 20 µs to seal was a
guess; the measured floor on this machine is ~20 µs of signature work alone.

## Optimization backlog, by expected payoff

1. **Group-commit storage.** One fsync per *batch* of steps
   (`Store::apply_many`) instead of per step. On real disks the fsync
   (0.1–2 ms) dwarfs every number above, so this matters most in practice.
2. **Avoid cloning values in `take_changes`.** Share buffers with the store.
3. **Batch signature verification** when draining a backlog. OpenMLS would need
   a hook; worth upstreaming.
4. Revisit faster curve backends (AVX-512 IFMA) on hardware that has them.
