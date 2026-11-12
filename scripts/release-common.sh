# Shared by the release scripts (docs/releases.md). Sourced, not run.
REPO=marshallsfolly/krypt
OWNER=${REPO%%/*}
NAMESPACE=krypt-release
# Act as the repository's owner (signed in with `gh auth login`, active or
# not), unless a token is given (as in CI).
if [[ -z "${GH_TOKEN:-}" ]]; then
  GH_TOKEN=$(gh auth token -h github.com -u "$OWNER" 2>/dev/null || true)
  export GH_TOKEN
fi

# git, pushing as that owner (the token from the environment, never argv).
git_as_owner() {
  git -c credential.helper= -c 'credential.helper=!f() { echo username=x-access-token; echo "password=$GH_TOKEN"; }; f' "$@"
}
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
KEY_PUB="$ROOT/apps/web/release-key.pub"

# allowed_signers for ssh-keygen -Y verify: the pinned key, releases only.
allowed_signers() {
  [[ -s "$KEY_PUB" ]] || { echo "no release key: $KEY_PUB (just release-keygen)" >&2; exit 1; }
  printf '%s namespaces="%s" %s\n' "$NAMESPACE" "$NAMESPACE" "$(cut -d' ' -f1,2 "$KEY_PUB")"
}

# verify_signature <manifest> <signature>
verify_signature() {
  ssh-keygen -Y verify -f <(allowed_signers) -I "$NAMESPACE" -n "$NAMESPACE" -s "$2" <"$1" >/dev/null \
    || { echo "$1: not signed by the release key" >&2; exit 1; }
}

manifest_tool() {
  node "$ROOT/apps/web/scripts/manifest.mjs" "$@"
}
