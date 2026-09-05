#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
: "${LAB_USER_SECRET:?LAB_USER_SECRET is required}"
FLAG_PATH="${FLAG_PATH:-/var/lib/lab/flag.txt}"
SLUG="sqli-cookie-tracking-id"

mkdir -p "$(dirname "$FLAG_PATH")"

# Per-container flag = FLAG{ hmac_sha256(LAB_USER_SECRET, "v1|<slug>") } in hex.
# openssl's -hmac uses the key argument as the HMAC key and stdin as the message;
# printf '%s' emits the message with no trailing newline. Never baked into a layer.
FLAG_HEX="$(printf '%s' "v1|${SLUG}" | openssl dgst -sha256 -hmac "${LAB_USER_SECRET}" | awk '{print $NF}')"
if [ "${#FLAG_HEX}" -ne 64 ]; then
  echo "entrypoint: flag derivation failed (unexpected digest length)" >&2
  exit 1
fi
printf 'FLAG{%s}\n' "$FLAG_HEX" > "$FLAG_PATH"
chmod 0640 "$FLAG_PATH" 2>/dev/null || true

# Drop the secret from the environment before the app starts, so an in-container
# read (e.g. /proc/self/environ) cannot recover it. The app derives nothing from
# LAB_USER_SECRET; it only reads the already-materialised flag file on /solve.
unset LAB_USER_SECRET

exec /usr/local/bin/lab-app
