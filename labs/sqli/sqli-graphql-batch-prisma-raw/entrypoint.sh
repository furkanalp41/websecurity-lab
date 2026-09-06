#!/bin/sh
# SPDX-License-Identifier: MIT
# Runtime bootstrap:
#   1. derive the per-container flag from LAB_USER_SECRET (never baked into the image)
#   2. write it to $FLAG_PATH on a tmpfs, 0640
#   3. drop LAB_USER_SECRET from the environment
#   4. seed the database (idempotent; provisions the per-container secret)
#   5. exec the GraphQL server on 0.0.0.0:8080
set -eu
: "${LAB_USER_SECRET:?LAB_USER_SECRET is required}"
FLAG_PATH="${FLAG_PATH:-/var/lib/lab/flag.txt}"
cd /app

mkdir -p "$(dirname "$FLAG_PATH")"
# Flag = FLAG{ hmac_sha256(LAB_USER_SECRET, "v1|<slug>") }. Computed with node's
# crypto so no extra tooling is needed in the alpine runtime.
LAB_USER_SECRET="$LAB_USER_SECRET" node -e '
const c = require("crypto");
const s = process.env.LAB_USER_SECRET;
const mac = c.createHmac("sha256", s).update("v1|sqli-graphql-batch-prisma-raw").digest("hex");
process.stdout.write("FLAG{" + mac + "}");
' > "$FLAG_PATH"
chmod 0640 "$FLAG_PATH" 2>/dev/null || true

unset LAB_USER_SECRET

# Provision schema + per-container secret (batch_flag) + public reports.
node dist/seed.js

exec node dist/server.js
