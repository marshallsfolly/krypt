#!/usr/bin/env bash
# Prints the abuse reports people sent (r/ in the krypt-files bucket), newest
# last, through R2's S3 API. Run as `just reports` (credentials from SOPS,
# never printed). Reports are deleted by the bucket's lifecycle after 90 days.
set -euo pipefail

BUCKET=krypt-files
# The keys reach curl as a config on a file descriptor (written by a shell
# builtin), never as arguments other processes could read.
s3() {
  curl -fsS --aws-sigv4 "aws:amz:auto:s3" -K <(printf 'user = "%s:%s"\n' "$R2_ACCESS_KEY_ID" "$R2_SECRET_ACCESS_KEY") "$@"
}

# Every page of the listing (1000 keys each).
keys=""
token=""
while :; do
  page=$(s3 "$R2_ENDPOINT/$BUCKET?list-type=2&prefix=r/&max-keys=1000${token:+&continuation-token=$(jq -rn --arg t "$token" '$t|@uri')}")
  keys+=$(grep -o '<Key>[^<]*</Key>' <<<"$page" | sed 's/<[^>]*>//g')$'\n'
  token=$(grep -o '<NextContinuationToken>[^<]*</NextContinuationToken>' <<<"$page" | sed 's/<[^>]*>//g' || true)
  [[ -n "$token" ]] || break
done
keys=$(sort <<<"$keys" | sed '/^$/d')
if [[ -z "$keys" ]]; then
  echo "no reports"
  exit 0
fi
# One unreadable report is shown raw and the rest still follow.
for key in $keys; do
  echo "== $key"
  report=$(s3 "$R2_ENDPOINT/$BUCKET/$key") || { echo "(could not fetch)"; continue; }
  jq . <<<"$report" 2>/dev/null || { echo "(not JSON; raw follows)"; printf '%s\n' "$report" | head -c 4096; echo; }
done
