#!/usr/bin/env bash
# secrets/ (never committed: see .gitignore) holds only SOPS files, with
# every value encrypted (keys and nesting may be plain; nothing else).
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -d secrets ]] || exit 0
if git ls-files --error-unmatch secrets >/dev/null 2>&1; then
  echo "secrets/ is tracked by git: it must never be committed" >&2
  exit 1
fi
for f in secrets/*; do
  case "$f" in *.yaml) ;; *) echo "not a SOPS file: $f" >&2; exit 1 ;; esac
  grep -q '^sops:' "$f" || { echo "unencrypted secret: $f" >&2; exit 1; }
  awk '
    /^sops:/ { exit }
    /^[[:space:]]*$/ { next }
    /^[[:space:]]*#ENC\[/ { next }
    /^[[:space:]]*[A-Za-z0-9_.-]+:[[:space:]]*$/ { next }
    /^[[:space:]]*[A-Za-z0-9_.-]+: ENC\[.*\]$/ { next }
    /^[[:space:]]*- ENC\[.*\]$/ { next }
    { print FILENAME ": line " NR " is not encrypted"; bad = 1 }
    END { exit bad }
  ' "$f"
done
