#!/usr/bin/env bash
# Does <origin> serve exactly the latest signed release? Run hourly by
# .github/workflows/monitor.yml; opens (or adds to) an issue if not.
#
#   scripts/release-monitor.sh <origin>
set -euo pipefail
source "$(dirname "$0")/release-common.sh"
origin=${1:?usage: release-monitor.sh <origin>}

latest=$(gh release view -R "$REPO" --json tagName -q .tagName 2>/dev/null || true)
if [[ -z "$latest" ]]; then
  echo "no release yet"
  exit 0
fi
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
gh release download "$latest" -R "$REPO" -D "$work" -p manifest.json -p manifest.json.sig
verify_signature "$work/manifest.json" "$work/manifest.json.sig"
if report=$(manifest_tool site "$origin" "$work/manifest.json" 2>&1); then
  echo "$report"
  exit 0
fi
echo "$report" >&2
title="$origin does not serve $latest"
existing=$(gh issue list -R "$REPO" --state open --search "\"$title\" in:title" --json number -q '.[0].number')
body=$(printf 'Checked %s at %s.\n\n```\n%s\n```\n' "$origin" "$(date -u +%FT%TZ)" "$report")
if [[ -n "$existing" ]]; then
  gh issue comment "$existing" -R "$REPO" --body "$body"
else
  gh issue create -R "$REPO" --title "$title" --body "$body"
fi
exit 1
