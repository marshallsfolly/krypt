#!/usr/bin/env bash
# Brings the krypt.chat zone to its declared baseline. Safe to rerun: records
# that already exist are left alone, settings are set to the same value.
#
# Run as `just cf-zone-apply` (credentials come from SOPS, never printed).
#
# Baseline:
#   - CAA: only Cloudflare's certificate authorities may issue for krypt.chat.
#   - Email: the domain never sends mail, so DMARC and an empty DKIM key tell
#     every receiver to reject mail claiming to be from it. It does receive:
#     hello@ goes through Cloudflare Email Routing, which owns the MX and SPF
#     records (so this sets neither, and never a null MX).
#   - TLS: full (strict), HTTPS only, TLS 1.2 minimum, no 0-RTT (replayable).
#   - DNSSEC: on. Its DS record must then be published at the registrar.
set -euo pipefail

ZONE_NAME=krypt.chat
API=https://api.cloudflare.com/client/v4

# The token reaches curl as a config on a file descriptor (written by a
# shell builtin), never as an argument other processes could read.
api() {
  curl -fsS -K <(printf 'header = "Authorization: Bearer %s"\n' "$CLOUDFLARE_API_TOKEN") -H "Content-Type: application/json" "$@"
}

ZONE=$(api "$API/zones?name=$ZONE_NAME" | jq -r '.result[0].id')
[[ -n "$ZONE" && "$ZONE" != null ]] || { echo "zone $ZONE_NAME not found" >&2; exit 1; }

# ensure_record <json>: creates the record unless one with the same type,
# name and content (or CAA data) already exists.
ensure_record() {
  local record="$1" type name
  type=$(jq -r .type <<<"$record")
  name=$(jq -r .name <<<"$record")
  local existing
  existing=$(api "$API/zones/$ZONE/dns_records?type=$type&name=$name&per_page=100")
  if jq -e --argjson want "$record" '
      .result[] | select(
        if $want.type == "CAA" then .data.tag == $want.data.tag and .data.value == $want.data.value
        else .content == $want.content end)' <<<"$existing" >/dev/null; then
    echo "  ok      $type $name $(jq -c '.content // .data' <<<"$record")"
  else
    api -X POST "$API/zones/$ZONE/dns_records" --data "$record" >/dev/null
    echo "  created $type $name $(jq -c '.content // .data' <<<"$record")"
  fi
}

caa() {
  jq -nc --arg tag "$1" --arg value "$2" --arg name "$ZONE_NAME" \
    '{type: "CAA", name: $name, ttl: 3600, data: {flags: 0, tag: $tag, value: $value}}'
}

txt() {
  jq -nc --arg name "$1" --arg content "$2" '{type: "TXT", name: $name, content: $content, ttl: 3600}'
}

echo "records:"
for ca in letsencrypt.org "pki.goog; cansignhttpexchanges=yes" ssl.com; do
  ensure_record "$(caa issue "$ca")"
  ensure_record "$(caa issuewild "$ca")"
done
ensure_record "$(txt "_dmarc.$ZONE_NAME" "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s")"
ensure_record "$(txt "*._domainkey.$ZONE_NAME" "v=DKIM1; p=")"

echo "settings:"
set_setting() {
  api -X PATCH "$API/zones/$ZONE/settings/$1" --data "{\"value\": \"$2\"}" | jq -r '"  \(.result.id) = \(.result.value)"'
}
set_setting ssl strict
set_setting always_use_https on
set_setting min_tls_version 1.2
set_setting tls_1_3 on
set_setting 0rtt off

echo "dnssec:"
status=$(api "$API/zones/$ZONE/dnssec" | jq -r .result.status)
if [[ "$status" == disabled ]]; then
  api -X PATCH "$API/zones/$ZONE/dnssec" --data '{"status": "active"}' >/dev/null
fi
api "$API/zones/$ZONE/dnssec" | jq -r '.result | "  status: \(.status)\n  DS for the registrar: key tag \(.key_tag), algorithm \(.algorithm), digest type \(.digest_type)\n  digest: \(.digest)\n  ds: \(.ds)"'
