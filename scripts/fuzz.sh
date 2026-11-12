#!/usr/bin/env bash
# Runs fuzz targets in the nightly shell (`nix develop .#fuzz`).
#
#   scripts/fuzz.sh <target> [seconds] [libFuzzer args...]
#   scripts/fuzz.sh all [seconds] [jobs per target]    every target at once
#   scripts/fuzz.sh check                              every seed, once
#
# Seeds are rewritten from real encodings first (fuzz/examples/seeds.rs);
# what libFuzzer learns accumulates in fuzz/corpus/<target>, and crashes
# land in fuzz/artifacts/<target>.
set -euo pipefail

cd "$(dirname "$0")/../fuzz"
targets=(wire_frame wire_msg identity scrub_image scrub_mp4 scrub_webm mailbox client_receive client_restore)

target=${1:?usage: scripts/fuzz.sh <target|all|check> [seconds] [args...]}
seconds=${2:-600}
shift $(($# < 2 ? $# : 2))

cargo run --release --quiet --example seeds -- seeds
cargo fuzz build

run() {
    local t=$1
    shift
    mkdir -p "corpus/$t" "artifacts/$t"
    cargo fuzz run "$t" "corpus/$t" "seeds/$t" -- \
        -max_total_time="$seconds" -timeout=30 -rss_limit_mb=4096 "$@"
}

case "$target" in
check)
    for t in "${targets[@]}"; do
        echo "== $t"
        cargo fuzz run "$t" "seeds/$t" -- -runs=0
    done
    ;;
all)
    jobs=${1:-1}
    mkdir -p logs
    pids=()
    for t in "${targets[@]}"; do
        run "$t" -fork="$jobs" -ignore_crashes=1 >"logs/$t.log" 2>&1 &
        pids+=($!)
    done
    status=0
    for pid in "${pids[@]}"; do
        wait "$pid" || status=1
    done
    exit $status
    ;;
*)
    run "$target" "$@"
    ;;
esac
