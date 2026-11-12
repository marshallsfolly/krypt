#!/usr/bin/env bash
# Prints a throwaway VAPID private key as a .dev.vars line, for running the
# edge locally. The real key lives only in secrets/push.yaml and Cloudflare.
set -euo pipefail
openssl ecparam -name prime256v1 -genkey -noout -outform DER | python3 -c '
import sys, base64
der = sys.stdin.buffer.read()
assert der[:7] == bytes([0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20]), "unexpected key encoding"
print("VAPID_PRIVATE_KEY=" + base64.urlsafe_b64encode(der[7:39]).rstrip(b"=").decode())'
