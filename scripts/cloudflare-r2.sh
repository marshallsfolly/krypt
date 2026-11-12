#!/usr/bin/env bash
# Brings the R2 bucket for shared files to its declared baseline. Safe to
# rerun.
#
# Run as `just cf-r2-apply` (credentials come from SOPS, never printed).
#
# Baseline:
#   - Bucket `krypt-files`: encrypted file parts, under f/<route>/<file>/<part>.
#     No public access and no custom domain: the Worker is the only way in.
#   - Lifecycle: parts are deleted 30 days after upload (RETENTION_MS), the
#     same as log entries, so the bucket can never grow without bound.
#   - Abuse reports (r/<day>/<id>.json, what a reporter chose to send) are
#     deleted after 90 days.
set -euo pipefail

BUCKET=krypt-files
RETENTION_S=$((30 * 24 * 60 * 60))
REPORTS_S=$((90 * 24 * 60 * 60))
API=https://api.cloudflare.com/client/v4
ACCOUNT="$API/accounts/$CLOUDFLARE_ACCOUNT_ID"

# The token reaches curl as a config on a file descriptor (written by a
# shell builtin), never as an argument other processes could read.
api() {
  curl -fsS -K <(printf 'header = "Authorization: Bearer %s"\n' "$CLOUDFLARE_API_TOKEN") -H "Content-Type: application/json" "$@"
}

if api "$ACCOUNT/r2/buckets/$BUCKET" >/dev/null 2>&1; then
  echo "  ok      bucket $BUCKET"
else
  api -X POST "$ACCOUNT/r2/buckets" --data "{\"name\":\"$BUCKET\"}" >/dev/null
  echo "  created bucket $BUCKET"
fi

rules=$(jq -n --argjson age "$RETENTION_S" --argjson reports "$REPORTS_S" '{rules: [{
  id: "expire-files",
  enabled: true,
  conditions: {prefix: "f/"},
  deleteObjectsTransition: {condition: {type: "Age", maxAge: $age}},
  abortMultipartUploadsTransition: {condition: {type: "Age", maxAge: 86400}}
}, {
  id: "expire-reports",
  enabled: true,
  conditions: {prefix: "r/"},
  deleteObjectsTransition: {condition: {type: "Age", maxAge: $reports}}
}]}')
api -X PUT "$ACCOUNT/r2/buckets/$BUCKET/lifecycle" --data "$rules" >/dev/null
echo "  set     lifecycle: delete f/ after $((RETENTION_S / 86400)) days, r/ after $((REPORTS_S / 86400))"

public=$(api "$ACCOUNT/r2/buckets/$BUCKET/domains/managed" | jq -r '.result.enabled')
[[ "$public" == "false" ]] || { echo "  WARNING public r2.dev access is on" >&2; exit 1; }
echo "  ok      no public access"
