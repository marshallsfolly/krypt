set shell := ["bash", "-euo", "pipefail", "-c"]

cf_secrets := "secrets/cloudflare.yaml"
cf_api := "https://api.cloudflare.com/client/v4"

default:
    @just --list

# Lint and test everything (what CI runs).
check: lint test
    nix flake check

lint:
    scripts/check-secrets.sh
    cargo fmt --check
    cargo clippy --workspace --all-targets -- -D warnings

test:
    cargo nextest run --workspace

# Needs the network, so it is not part of `nix flake check` (which runs the
# offline cargo-deny checks).
# Known vulnerabilities (RustSec, npm) and unaudited crates (cargo-vet).
audit:
    cargo deny check advisories
    cd apps/web && pnpm audit
    cargo vet --locked

# Simulator: `just sim` runs 10k seeds; extra args pass through (e.g. --clients 6).
sim seeds="10000" *args="":
    cargo build --release -p krypt-sim
    ./target/release/krypt-sim --seeds {{seeds}} --determinism {{args}}

# Replay one simulator seed with a full event trace.
sim-trace seed *args="":
    cargo build --release -p krypt-sim
    KRYPT_SIM_VERBOSE=1 ./target/release/krypt-sim --seed {{seed}} {{args}}

bench:
    cargo bench -p krypt-core --bench hot_path

# Targets: wire_frame wire_msg identity scrub_image scrub_mp4 scrub_webm mailbox
# client_receive client_restore. Crashes land in fuzz/artifacts/<target>.
# Fuzz one target for a while (nightly shell; extra args go to libFuzzer).
fuzz target seconds="600" *args="":
    nix develop .#fuzz -c scripts/fuzz.sh {{target}} {{seconds}} {{args}}

# Every fuzz target at once, `jobs` processes each (logs in fuzz/logs).
fuzz-all seconds="600" jobs="1":
    nix develop .#fuzz -c scripts/fuzz.sh all {{seconds}} {{jobs}}

# Run after changing what devices store; commit the result.
# Rewrite the client fuzz fixture (a device in real conversations).
fuzz-fixture:
    nix develop .#fuzz -c bash -c 'cd fuzz && cargo run --release --quiet --example seeds -- --fixture seeds'

# CPU profile of one benchmark (e.g. `just profile send_message`).
profile bench:
    cargo bench -p krypt-core --bench hot_path --no-run
    perf record -e cycles:u -g --call-graph dwarf -o target/{{bench}}.perf \
        $(ls -t target/release/deps/hot_path-* | grep -v '\.d$' | head -1) --bench {{bench}} --sample-count 20000
    perf report -i target/{{bench}}.perf --no-children --sort symbol

# Regenerate the vendored OpenMLS storage after an OpenMLS upgrade.
vendor-mls-store:
    python3 scripts/vendor-mls-store.py $(dirname $(cargo metadata --format-version 1 | jq -r '.packages[] | select(.name == "openmls_memory_storage") | .manifest_path'))

# Local mailbox for development (in-process, in-memory).
devmailbox addr="127.0.0.1:8787":
    cargo run --release -p krypt-devmailbox -- {{addr}}

# The real edge Worker, locally on workerd (Durable Objects + SQLite).
edge-dev port="8788": web-build
    cd services/edge && wrangler dev --local --port {{port}} --var RP_ID:localhost --var ORIGINS:http://localhost:{{port}}

# Build the browser core (WebAssembly + bindings) into the web app.
web-core:
    cargo build --locked --profile wasm -p krypt-wasm --target wasm32-unknown-unknown
    rm -rf apps/web/src/core
    wasm-bindgen --target web --out-dir apps/web/src/core target/wasm32-unknown-unknown/wasm/krypt_wasm.wasm
    wasm-opt -Oz --enable-bulk-memory --enable-nontrapping-float-to-int --enable-sign-ext --enable-mutable-globals --strip-debug -o apps/web/src/core/krypt_wasm_bg.wasm apps/web/src/core/krypt_wasm_bg.wasm

# Stop every local edge (`edge-dev`, `edge-dev-push`).
edge-stop:
    scripts/stop-local-edge.sh

# The edge locally, sending push wakeups to localhost too (for tests), with
# a throwaway VAPID key.
edge-dev-push port="8788": web-build
    cd services/edge && (umask 077 && ../../scripts/dev-vapid.sh > .dev.vars) && wrangler dev --local --port {{port}} --var ALLOW_LOCAL_PUSH:1 --var RP_ID:localhost --var ORIGINS:http://localhost:{{port}}

# Send the VAPID private key (from secrets/push.yaml) to Cloudflare.
edge-push-secret:
    cd services/edge && sops exec-env ../../secrets/push.yaml 'printenv VAPID_PRIVATE_KEY | sops exec-env ../../{{cf_secrets}} "wrangler secret put VAPID_PRIVATE_KEY"'

# The web client's packages, exactly as locked.
web-deps:
    cd apps/web && pnpm install --frozen-lockfile

# Run the web client locally against the local edge (`just edge-dev`).
web-dev: web-deps web-core
    cd apps/web && pnpm dev

# Render the app icons from apps/web/icons/*.svg.
web-icons:
    cd apps/web && cp icons/favicon.svg public/icon.svg && rsvg-convert -w 192 -h 192 icons/mark.svg -o public/icon-192.png && rsvg-convert -w 512 -h 512 icons/mark.svg -o public/icon-512.png && rsvg-convert -w 512 -h 512 icons/square.svg -o public/maskable-512.png && rsvg-convert -w 180 -h 180 icons/square.svg -o public/apple-touch-icon.png

# Render the link-preview card, apps/web/icons/og.html, to public/og.png
# (needs Chromium: CHROMIUM or PATH).
web-og: web-deps
    cd apps/web && "${CHROMIUM:-chromium}" --headless --disable-gpu --hide-scrollbars --allow-file-access-from-files --force-device-scale-factor=1 --window-size=1200,630 --virtual-time-budget=3000 --screenshot=public/og.png "file://$PWD/icons/og.html"

# Build the web client for production (apps/web/dist).
web-build: web-deps web-core
    cd apps/web && pnpm build

# Build the mailbox Worker (services/edge/build), with no secrets in reach.
edge-build:
    env -u CLOUDFLARE_API_TOKEN scripts/edge-build.sh

# A deploy ships a commit: nothing uncommitted, tracked or not.
committed:
    @test -z "$(git status --porcelain)" || { git status --short; echo "commit first: a deploy ships a commit" >&2; exit 1; }

# Deploy a signed release (docs/releases.md) to Cloudflare (krypt.chat,
# api.krypt.chat): its web app exactly as signed (fetched and checked, never
# built here), and the mailbox Worker built here from the same commit,
# which must be checked out. Everything is in place before the token is
# decrypted; the deploy is tagged with the release.
edge-deploy version: committed
    scripts/release-fetch.sh {{version}} apps/web/dist
    @test "$(git rev-parse HEAD)" = "$(git rev-parse '{{version}}^{commit}')" || { echo "check out {{version}} first: the Worker is built from it" >&2; exit 1; }
    just edge-build
    @test -z "$(git status --porcelain)" || { git status --short; echo "the build changed the tree; deploy refused" >&2; exit 1; }
    cd services/edge && sops exec-env ../../{{cf_secrets}} "wrangler deploy --tag {{version}} --message 'krypt {{version}}'"

# ---- Releases (docs/releases.md) ----

# Make the release key on a YubiKey, once: touch it (and give its PIN) when
# asked. The private key never leaves it; the public key is what the app pins.
release-keygen:
    mkdir -p ~/.config/krypt
    ssh-keygen -t ed25519-sk -O resident -O verify-required -O application=ssh:krypt-release -C "krypt release key" -f ~/.config/krypt/release-key \
      || ssh-keygen -t ecdsa-sk -O resident -O verify-required -O application=ssh:krypt-release -C "krypt release key" -f ~/.config/krypt/release-key
    cp ~/.config/krypt/release-key.pub apps/web/release-key.pub
    @echo "Pinned key: apps/web/release-key.pub (commit it before the first release)."

# Tag a release of the current commit and push the tag: CI builds a draft.
release-tag version: committed
    scripts/release-tag.sh {{version}}

# Check CI's build of a release against a local one, sign it with the
# YubiKey and publish it.
release-sign version:
    scripts/release-sign.sh {{version}}

# The release checks' own tests.
release-test:
    cd apps/web && node --test scripts/release.test.mjs

# Refuse all mailbox traffic within seconds (no rebuild): the spending stop.
edge-kill:
    cd services/edge && sops exec-env ../../{{cf_secrets}} 'echo 1 | wrangler secret put KILL_SWITCH'

# Undo edge-kill.
edge-unkill:
    cd services/edge && sops exec-env ../../{{cf_secrets}} 'echo 0 | wrangler secret put KILL_SWITCH'

# Run any command with Cloudflare credentials in its environment (never printed).
cf +cmd:
    sops exec-env {{cf_secrets}} '{{cmd}}'

# Confirm the Cloudflare API token is active.
cf-verify:
    just cf 'printf "header = \"Authorization: Bearer %s\"\n" "$CLOUDFLARE_API_TOKEN" | curl -fsS -K - "{{cf_api}}/accounts/$CLOUDFLARE_ACCOUNT_ID/tokens/verify" | jq -r .result.status'

# Show the krypt.chat zone status and its assigned nameservers.
cf-zone:
    just cf 'printf "header = \"Authorization: Bearer %s\"\n" "$CLOUDFLARE_API_TOKEN" | curl -fsS -K - "{{cf_api}}/zones?name=krypt.chat" | jq ".result[] | {status, name_servers}"'

# Bring the krypt.chat zone (records, TLS settings, DNSSEC) to its declared baseline.
cf-zone-apply:
    sops exec-env {{cf_secrets}} 'bash scripts/cloudflare-zone.sh'

# Bring the R2 bucket for shared files (lifecycle, no public access) to its baseline.
cf-r2-apply:
    sops exec-env {{cf_secrets}} 'bash scripts/cloudflare-r2.sh'

# Read the abuse reports people sent (kept 90 days).
reports:
    sops exec-env {{cf_secrets}} 'bash scripts/reports.sh'

# Create the TURN key for calls (once), keeping its secret in secrets/turn.yaml.
cf-turn-apply:
    sops exec-env {{cf_secrets}} 'bash scripts/cloudflare-turn.sh'

# Send the TURN key's secret (from secrets/turn.yaml) to the Worker.
edge-turn-secret:
    cd services/edge && sops exec-env ../../secrets/turn.yaml 'printenv TURN_KEY_API_TOKEN | sops exec-env ../../{{cf_secrets}} "wrangler secret put TURN_KEY_API_TOKEN"'

# Edit secrets in $EDITOR (decrypted only in memory/tmpfs by sops).
secrets-edit file=cf_secrets:
    sops edit {{file}}

# Public DNS view of the domain.
dns:
    @for t in NS A AAAA CAA TXT DS; do echo "--- $t"; dig +short $t krypt.chat; done
