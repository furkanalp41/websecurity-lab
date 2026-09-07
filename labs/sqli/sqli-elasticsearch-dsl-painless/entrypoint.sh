#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
: "${LAB_USER_SECRET:?LAB_USER_SECRET is required}"
FLAG_PATH="${FLAG_PATH:-/var/lib/lab/flag.txt}"
mkdir -p "$(dirname "$FLAG_PATH")"

# Per-container flag (returned by /solve on a correct secret_key submission).
node -e '
const {createHmac}=require("node:crypto");
process.stdout.write("FLAG{"+createHmac("sha256",process.env.LAB_USER_SECRET).update("v1|sqli-elasticsearch-dsl-painless").digest("hex")+"}\n");
' > "$FLAG_PATH"
chmod 0640 "$FLAG_PATH" 2>/dev/null || true

# Seed .credentials + logs (waits for ES; secret_key derived here too).
node /opt/app/seed.mjs

# Drop the secret before the server so an app-side read cannot re-derive flags.
unset LAB_USER_SECRET

exec node /opt/app/server.mjs
