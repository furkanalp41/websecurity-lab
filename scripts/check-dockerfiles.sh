#!/bin/sh
# SPDX-License-Identifier: MIT
# Fail unless every external `FROM` in labs/**/Dockerfile is digest-pinned
# (FROM <image>@sha256:<64hex>). References to a prior build-stage alias are allowed.
set -eu

cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

status=0
found=0
for df in $(find labs -name Dockerfile 2>/dev/null); do
  found=$((found + 1))
  aliases=$(grep -iE '^[[:space:]]*FROM[[:space:]]' "$df" \
    | sed -nE 's/.*[[:space:]][Aa][Ss][[:space:]]+([A-Za-z0-9_.-]+).*/\1/p')
  grep -iE '^[[:space:]]*FROM[[:space:]]' "$df" > /tmp/_fromlines || true
  while IFS= read -r line; do
    img=$(printf '%s\n' "$line" | awk '{print $2}')
    if [ -n "$aliases" ] && printf '%s\n' $aliases | grep -qxF "$img"; then
      continue # references a previously-declared build stage
    fi
    case "$img" in
      *@sha256:*)
        digest=${img##*@sha256:}
        if ! printf '%s' "$digest" | grep -qE '^[0-9a-f]{64}$'; then
          echo "FAIL $df: malformed digest in '$img'"
          status=1
        fi
        ;;
      *)
        echo "FAIL $df: unpinned FROM '$img' (require @sha256:<64hex>)"
        status=1
        ;;
    esac
  done < /tmp/_fromlines
  rm -f /tmp/_fromlines
done

echo "checked $found Dockerfile(s)"
if [ "$found" = 0 ]; then echo "WARN: no Dockerfiles found"; fi
[ "$status" = 0 ] && echo "all Dockerfiles digest-pinned" || exit 1
