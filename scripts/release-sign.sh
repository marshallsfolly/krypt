#!/usr/bin/env bash
# Signs a release CI has built and published it (docs/releases.md):
#   1. checks GitHub's attestation and that the archive matches its manifest;
#   2. builds the same commit here (the sealed Nix build) and checks it gives
#      exactly the same files, so the release is what the source says;
#   3. signs the manifest with the release key (touch the YubiKey);
#   4. uploads the signature and publishes the release.
#
#   scripts/release-sign.sh <version>
set -euo pipefail
source "$(dirname "$0")/release-common.sh"
version=${1:?usage: release-sign.sh <version>}
key=${KRYPT_RELEASE_KEY:-$HOME/.config/krypt/release-key}

work=$(mktemp -d)
trap 'git -C "$ROOT" worktree remove --force "$work/source" 2>/dev/null || true; rm -rf "$work"' EXIT
gh release download "$version" -R "$REPO" -D "$work" -p krypt-web.tar -p manifest.json
gh attestation verify "$work/krypt-web.tar" -R "$REPO" >/dev/null
mkdir "$work/dist"
tar -xf "$work/krypt-web.tar" -C "$work/dist"
cmp -s "$work/manifest.json" "$work/dist/release/manifest.json" || { echo "the archive's manifest differs" >&2; exit 1; }
manifest_tool check "$work/dist" "$work/manifest.json"

commit=$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1])).commit)' "$work/manifest.json")
[[ "$(git -C "$ROOT" rev-parse "$version^{commit}")" == "$commit" ]] || { echo "$version is not $commit here" >&2; exit 1; }
echo "Building $version ($commit) here to compare: this takes a while."
git -C "$ROOT" worktree add --detach "$work/source" "$commit" >/dev/null
nix build "$work/source#webDist" --out-link "$work/local"
manifest_tool check "$work/local" "$work/manifest.json"

echo "Touch the YubiKey to sign $version."
ssh-keygen -Y sign -f "$key" -n "$NAMESPACE" "$work/manifest.json"
verify_signature "$work/manifest.json" "$work/manifest.json.sig"
gh release upload "$version" -R "$REPO" "$work/manifest.json.sig"
gh release edit "$version" -R "$REPO" --draft=false --latest
echo "$version is signed and published."
