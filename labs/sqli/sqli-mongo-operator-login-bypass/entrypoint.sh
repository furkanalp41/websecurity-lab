#!/bin/sh
# SPDX-License-Identifier: MIT
# Compute the per-container flag from LAB_USER_SECRET, write it to $FLAG_PATH on a
# tmpfs (never baked into the image or the source), drop the secret from the env,
# seed MongoDB idempotently, then hand off to the Express server on 0.0.0.0:8080.
set -eu
: "${LAB_USER_SECRET:?LAB_USER_SECRET is required}"
FLAG_PATH="${FLAG_PATH:-/var/lib/lab/flag.txt}"
mkdir -p "$(dirname "$FLAG_PATH")"

# FLAG{ hmac_sha256(LAB_USER_SECRET, "v1|<slug>") } — computed at runtime with the
# node crypto module that ships in the base image.
node -e 'const c=require("crypto");const s=process.env.LAB_USER_SECRET;process.stdout.write("FLAG{"+c.createHmac("sha256",s).update("v1|sqli-mongo-operator-login-bypass").digest("hex")+"}\n");' > "$FLAG_PATH"
chmod 0640 "$FLAG_PATH" 2>/dev/null || true

# The server never needs the raw secret; only the derived flag file remains.
unset LAB_USER_SECRET

# Idempotent seed: create the admin + decoy users and a random reset_token.
node /opt/app/seed.js

exec node /opt/app/server.js
