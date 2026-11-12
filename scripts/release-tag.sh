#!/usr/bin/env bash
# Tags the current commit as a release and pushes the tag: GitHub Actions
# builds a draft (docs/releases.md).
#
#   scripts/release-tag.sh <version>
set -euo pipefail
source "$(dirname "$0")/release-common.sh"
version=${1:?usage: release-tag.sh <version>}
[[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "a version is vX.Y.Z" >&2; exit 1; }
[[ -s "$KEY_PUB" ]] || { echo "no release key pinned yet: just release-keygen" >&2; exit 1; }
[[ -z "$(git -C "$ROOT" status --porcelain)" ]] || { echo "commit first" >&2; exit 1; }
git -C "$ROOT" tag -a "$version" -m "krypt $version"
git_as_owner -C "$ROOT" push origin "$version"
echo "Pushed $version: https://github.com/$REPO/actions"
