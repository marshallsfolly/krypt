#!/usr/bin/env bash
# Fetches a published release into <dir>, refusing it unless the release
# key signed its manifest, GitHub attests this repository's workflow built
# it, and every file is the one the manifest names (docs/releases.md).
#
#   scripts/release-fetch.sh <version> <dir>
set -euo pipefail
source "$(dirname "$0")/release-common.sh"
version=${1:?usage: release-fetch.sh <version> <dir>}
out=${2:?usage: release-fetch.sh <version> <dir>}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
gh release download "$version" -R "$REPO" -D "$work" -p krypt-web.tar -p manifest.json -p manifest.json.sig
verify_signature "$work/manifest.json" "$work/manifest.json.sig"
gh attestation verify "$work/krypt-web.tar" -R "$REPO" >/dev/null
rm -rf "$out"
mkdir -p "$out"
tar -xf "$work/krypt-web.tar" -C "$out"
cmp -s "$work/manifest.json" "$out/release/manifest.json" || { echo "the archive's manifest is not the signed one" >&2; exit 1; }
cp "$work/manifest.json.sig" "$out/release/manifest.json.sig"
manifest_tool check "$out" "$out/release/manifest.json"
