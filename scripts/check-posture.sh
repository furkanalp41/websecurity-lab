#!/bin/sh
# SPDX-License-Identifier: MIT
# Assert the container security baseline on every container of a lab.
# Usage: check-posture.sh <container-id> [<container-id> ...]
# Set LAB_RISK=elevated to relax cap_drop:ALL for a charter-approved elevated lab.
set -eu

[ "$#" -ge 1 ] || { echo "usage: check-posture.sh <container> [<container> ...]"; exit 2; }

fail=0

check_one() {
  cid="$1"
  insp="$(docker inspect "$cid")"
  name=$(printf '%s' "$insp" | jq -r '.[0].Name')
  echo "-- $name ($cid)"

  user=$(printf '%s' "$insp" | jq -r '.[0].Config.User')
  case "$user" in
    "" | "0" | "root" | "0:0") echo "   FAIL User=$user (root/empty)"; fail=1 ;;
    *) echo "   ok User=$user" ;;
  esac

  priv=$(printf '%s' "$insp" | jq -r '.[0].HostConfig.Privileged')
  [ "$priv" = "false" ] || { echo "   FAIL Privileged=$priv"; fail=1; }

  rorfs=$(printf '%s' "$insp" | jq -r '.[0].HostConfig.ReadonlyRootfs')
  [ "$rorfs" = "true" ] || { echo "   FAIL ReadonlyRootfs=$rorfs"; fail=1; }

  if [ "${LAB_RISK:-low}" = "elevated" ]; then
    echo "   info LAB_RISK=elevated -> cap_drop:ALL relaxed"
  else
    hasall=$(printf '%s' "$insp" | jq -r '(.[0].HostConfig.CapDrop // []) | map(ascii_upcase) | index("ALL")')
    [ "$hasall" != "null" ] || { echo "   FAIL CapDrop lacks ALL"; fail=1; }
  fi

  nnp=$(printf '%s' "$insp" | jq -r '(.[0].HostConfig.SecurityOpt // []) | index("no-new-privileges:true")')
  [ "$nnp" != "null" ] || { echo "   FAIL missing no-new-privileges:true"; fail=1; }

  pids=$(printf '%s' "$insp" | jq -r '.[0].HostConfig.PidsLimit')
  case "$pids" in "" | "null" | "0") echo "   FAIL PidsLimit=$pids"; fail=1 ;; *) : ;; esac

  mem=$(printf '%s' "$insp" | jq -r '.[0].HostConfig.Memory')
  case "$mem" in "" | "null" | "0") echo "   FAIL Memory=$mem"; fail=1 ;; *) : ;; esac

  badports=$(printf '%s' "$insp" | jq -r '
    [ (.[0].NetworkSettings.Ports // {}) | to_entries[] | (.value // [])[] | .HostIp ]
    | map(select(. != "127.0.0.1" and . != "::1" and . != "")) | length')
  [ "$badports" = "0" ] || { echo "   FAIL $badports published port(s) not on loopback"; fail=1; }
}

for cid in "$@"; do
  check_one "$cid"
done

if [ "$fail" = "0" ]; then echo "posture OK"; else echo "posture FAILED"; exit 1; fi
