#!/bin/sh
# SPDX-License-Identifier: MIT
# Assert the container security baseline on a running lab container.
# Usage: check-posture.sh <container-id-or-name>
# Set LAB_RISK=elevated to relax the cap_drop:ALL requirement for a charter-approved
# elevated lab (which must document elevated_caps in meta.json).
set -eu

CID="${1:?usage: check-posture.sh <container>}"
insp="$(docker inspect "$CID")"
fail=0

user=$(printf '%s' "$insp" | jq -r '.[0].Config.User')
case "$user" in
  "" | "0" | "root" | "0:0") echo "FAIL User=$user (root/empty)"; fail=1 ;;
  *) echo "ok   User=$user" ;;
esac

priv=$(printf '%s' "$insp" | jq -r '.[0].HostConfig.Privileged')
[ "$priv" = "false" ] || { echo "FAIL Privileged=$priv"; fail=1; }
[ "$priv" = "false" ] && echo "ok   Privileged=false"

rorfs=$(printf '%s' "$insp" | jq -r '.[0].HostConfig.ReadonlyRootfs')
[ "$rorfs" = "true" ] || { echo "FAIL ReadonlyRootfs=$rorfs"; fail=1; }
[ "$rorfs" = "true" ] && echo "ok   ReadonlyRootfs=true"

if [ "${LAB_RISK:-low}" = "elevated" ]; then
  echo "info LAB_RISK=elevated -> cap_drop:ALL requirement relaxed"
else
  hasall=$(printf '%s' "$insp" | jq -r '(.[0].HostConfig.CapDrop // []) | map(ascii_upcase) | index("ALL")')
  [ "$hasall" != "null" ] || { echo "FAIL CapDrop does not include ALL"; fail=1; }
  [ "$hasall" != "null" ] && echo "ok   CapDrop=[ALL]"
fi

nnp=$(printf '%s' "$insp" | jq -r '(.[0].HostConfig.SecurityOpt // []) | index("no-new-privileges:true")')
[ "$nnp" != "null" ] || { echo "FAIL missing security_opt no-new-privileges:true"; fail=1; }
[ "$nnp" != "null" ] && echo "ok   no-new-privileges:true"

pids=$(printf '%s' "$insp" | jq -r '.[0].HostConfig.PidsLimit')
case "$pids" in "" | "null" | "0") echo "FAIL PidsLimit=$pids"; fail=1 ;; *) echo "ok   PidsLimit=$pids" ;; esac

mem=$(printf '%s' "$insp" | jq -r '.[0].HostConfig.Memory')
case "$mem" in "" | "null" | "0") echo "FAIL Memory=$mem"; fail=1 ;; *) echo "ok   Memory=$mem" ;; esac

# Every published port must bind to loopback only.
badports=$(printf '%s' "$insp" | jq -r '
  [ (.[0].NetworkSettings.Ports // {}) | to_entries[] | (.value // [])[] | .HostIp ]
  | map(select(. != "127.0.0.1" and . != "::1" and . != "")) | length')
[ "$badports" = "0" ] || { echo "FAIL $badports published port(s) not bound to loopback"; fail=1; }
[ "$badports" = "0" ] && echo "ok   all published ports bound to loopback"

if [ "$fail" = "0" ]; then echo "posture OK"; else echo "posture FAILED"; exit 1; fi
