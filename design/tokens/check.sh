#!/usr/bin/env bash
# Validates the theme token files: every theme defines the same tokens,
# every {reference} resolves, exactly one theme is the default, and
# haptic patterns are well formed. Prints each problem; exits 1 if any.
set -euo pipefail

dir="${1:-$(dirname "$0")}"

problems=$(jq -rs '
  # Token paths, ignoring parts that legitimately differ per theme:
  # accent names, and the parameters of each motion/haptic entry.
  def shape:
    [paths(type != "object" and type != "array") | map(select(type == "string"))
      | if .[0] == "accents" then .[0:1]
        elif .[0] == "haptics" or .[0] == "motion" then .[0:2]
        else . end]
    | unique;
  def isref: type == "string" and test("^\\{[A-Za-z.]+\\}$");
  def refname: ltrimstr("{") | rtrimstr("}");

  . as $all
  | ($all[0] | shape) as $ref
  | ([$all[] | select(.isDefault == true)] | length) as $defaults
  | (if $defaults != 1 then "exactly one theme must set isDefault (found \($defaults))" else empty end),
    ($all[] | . as $t | .id as $id
      | (if shape != $ref
           then "\($id): token shape differs from \($all[0].id): "
                + (((shape - $ref) + ($ref - shape)) | map(join(".")) | join(", "))
           else empty end),
        (if .accents | has($t.defaultAccent) then empty
           else "\($id): defaultAccent \(.defaultAccent) is not one of its accents" end),
        (.color | to_entries[] | .key as $mode | .value | to_entries[]
          | select(.value | isref) | (.value | refname) as $r
          | select((($r | test("^accent(\\.on|\\.ink)?$")) or ($t.color[$mode] | has($r))) | not)
          | "\($id): color.\($mode).\(.key) references unknown {\($r)}"),
        (.accents | to_entries[] | .key as $a | .value.ink | to_entries[]
          | select(.value | isref) | (.value | refname) as $r
          | select($t.color[.key] | has($r) | not)
          | "\($id): accents.\($a).ink.\(.key) references unknown {\($r)}"),
        (.haptics | to_entries[] | .key as $h | .value
          | (if (.web | length) == 0 then "\($id): haptics.\($h).web is empty" else empty end),
            (if ([.events[].t] | . != sort) then "\($id): haptics.\($h) events are not in time order" else empty end),
            (.events[]
              | select(.intensity < 0 or .intensity > 1 or .sharpness < 0 or .sharpness > 1)
              | "\($id): haptics.\($h) intensity/sharpness outside 0..1"),
            (.events[]
              | select(.kind == "continuous" and ((.durationMs // 0) <= 0))
              | "\($id): haptics.\($h) continuous event needs durationMs > 0")))
' "$dir"/*.json)

if [[ -n "$problems" ]]; then
  echo "$problems" >&2
  exit 1
fi
echo "design tokens ok: $(ls "$dir"/*.json | wc -l) themes"
