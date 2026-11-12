#!/usr/bin/env bash
# Creates krypt's Cloudflare TURN key (once) and keeps its secret only in
# secrets/turn.yaml (SOPS). The secret is piped from the API straight into
# sops and never printed or written in the clear. Run under
# `sops exec-env secrets/cloudflare.yaml` (see `just cf-turn-apply`).
set -euo pipefail

name="krypt-turn"
api="https://api.cloudflare.com/client/v4/accounts/$CLOUDFLARE_ACCOUNT_ID/calls/turn_keys"
# The token reaches curl as a config on a file descriptor (written by a
# shell builtin), never as an argument other processes could read.
cf() {
  curl -sf -K <(printf 'header = "Authorization: Bearer %s"\n' "$CLOUDFLARE_API_TOKEN") "$@"
}

existing=$(cf "$api" | jq -r --arg name "$name" '.result[] | select(.name == $name) | .uid')
if [[ -n "$existing" ]]; then
  if [[ -f secrets/turn.yaml ]]; then
    echo "TURN key $name exists ($existing); secrets/turn.yaml holds it"
    exit 0
  fi
  echo "TURN key $name exists ($existing) but secrets/turn.yaml is missing: delete the key in the dashboard and rerun" >&2
  exit 1
fi

umask 077
# The response is held only in memory. The API shows the secret once, so
# refuse to store anything but a real one.
response=$(cf -H "Content-Type: application/json" -d "{\"name\":\"$name\"}" "$api")
echo "response fields: $(jq -r '.result | keys | join(", ")' <<<"$response")"
printf '%s' "$response" \
  | jq -re '.result | ([to_entries[] | select((.key | IN("uid", "name", "created", "modified") | not) and (.value | type) == "string" and (.value | length) >= 32) | .value]) as $secrets | select($secrets | length == 1) | "TURN_KEY_ID: \(.uid)\nTURN_KEY_API_TOKEN: \($secrets[0])"' \
  | sops encrypt --filename-override secrets/turn.yaml --input-type yaml --output-type yaml /dev/stdin > secrets/turn.yaml.new
grep -q '^sops:' secrets/turn.yaml.new
mv secrets/turn.yaml.new secrets/turn.yaml
echo "created TURN key $name; its secret is in secrets/turn.yaml"
