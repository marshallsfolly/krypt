#!/usr/bin/env bash
# Builds the mailbox Worker (services/edge/build) with the flake's tools:
# its wasm-bindgen and wasm-opt, not ones worker-build would download.
#
# wrangler runs this as the Worker's build command. A deploy runs it with
# the Cloudflare token in the environment, so there it builds nothing and
# only checks that `just edge-build` already did: no build script, proc
# macro or build tool ever runs while the token is in reach.
set -euo pipefail
cd "$(dirname "$0")/../services/edge"
if [[ -n "${CLOUDFLARE_API_TOKEN:-}" ]]; then
    if [[ ! -f build/worker/shim.mjs || ! -f build/index_bg.wasm ]]; then
        echo "edge-build: build first with \`just edge-build\` (it never sees the token)" >&2
        exit 1
    fi
    exit 0
fi
WASM_BINDGEN_BIN=$(command -v wasm-bindgen) worker-build --release --no-opt -- --locked
wasm-opt -Oz --enable-bulk-memory --enable-nontrapping-float-to-int --enable-sign-ext \
    --enable-mutable-globals --enable-reference-types --enable-multivalue --enable-exception-handling \
    --strip-debug \
    -o build/index_bg.wasm build/index_bg.wasm
