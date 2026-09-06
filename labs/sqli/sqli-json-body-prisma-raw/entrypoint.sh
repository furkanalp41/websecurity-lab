#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
: "${LAB_USER_SECRET:?LAB_USER_SECRET is required}"
FLAG_PATH="${FLAG_PATH:-/var/lib/lab/flag.txt}"
mkdir -p "$(dirname "$FLAG_PATH")"

# Compute the per-container flag = FLAG{ hmac_sha256(LAB_USER_SECRET, "v1|<slug>") }
# with node's crypto (openssl CLI is not present on node:20-alpine). Write it to a
# tmpfs path; it is never baked into the image or the source tree.
LAB_USER_SECRET="$LAB_USER_SECRET" node -e '
const crypto = require("crypto");
const secret = process.env.LAB_USER_SECRET;
const mac = crypto.createHmac("sha256", secret).update("v1|sqli-json-body-prisma-raw").digest("hex");
process.stdout.write("FLAG{" + mac + "}");
' > "$FLAG_PATH"
chmod 0640 "$FLAG_PATH" 2>/dev/null || true

# Drop the secret from the environment before running any app code.
unset LAB_USER_SECRET

# Seed the database (idempotent), then start the server.
node /app/dist/seed.js
exec node /app/dist/server.js
