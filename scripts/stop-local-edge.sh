#!/usr/bin/env bash
# Stops every local `wrangler dev` (and its workerd), however it was started.
# Never touches this script's own ancestry (the shell that ran it may well
# mention wrangler), and the bracketed patterns cannot match their own text.
set -uo pipefail

ancestors=" $$ "
pid=$$
while [ "$pid" -gt 1 ]; do
  pid=$(awk '{print $4}' "/proc/$pid/stat" 2>/dev/null || echo 1)
  ancestors+="$pid "
done

targets() {
  pgrep -f '[w]rangler-[0-9.]+/bin/wrangler|[w]rangler-[0-9.]+/lib/node_modules|[w]orkerd serve' |
    while read -r p; do [[ "$ancestors" == *" $p "* ]] || echo "$p"; done
}

pids=$(targets)
[ -z "$pids" ] && exit 0
kill $pids 2>/dev/null
for _ in $(seq 1 20); do
  [ -z "$(targets)" ] && exit 0
  sleep 0.25
done
kill -9 $(targets) 2>/dev/null
exit 0
