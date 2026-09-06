# SPDX-License-Identifier: MIT
# Two-stage build: compile TypeScript + generate the Prisma client (with the
# alpine/musl query engine) on a full node:20-alpine toolchain, then ship only
# production dependencies + the built dist/ on a fresh node:20-alpine runtime.
# No flag is baked in (entrypoint.sh writes the per-container flag at runtime).
#
# Bases are digest-pinned to a real, resolvable node:20-alpine manifest.

FROM node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293 AS build
# Prisma needs libssl/openssl present to select the correct query-engine.
RUN apk add --no-cache openssl
WORKDIR /app
# Install ALL deps (incl. prisma CLI + typescript) needed to generate + compile.
COPY src/package.json ./
RUN npm install --no-audit --no-fund
# Generate the Prisma client — emits native + linux-musl-openssl-3.0.x engines.
# A placeholder DATABASE_URL satisfies schema validation; generate never connects.
ENV DATABASE_URL="postgresql://placeholder:placeholder@localhost:5432/placeholder"
COPY src/prisma ./prisma
RUN npx prisma generate
# Compile TypeScript -> dist/.
COPY src/tsconfig.json ./
COPY src/app ./app
RUN npm run build

FROM node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293 AS runtime
ENV NODE_ENV=production
# openssl lets Prisma's query-engine detect libssl 3.x and load the musl-3.0.x engine.
RUN apk add --no-cache openssl
WORKDIR /app
# Production dependencies only. --ignore-scripts skips the @prisma/client
# postinstall (it cannot generate without the CLI/schema and we supply the
# generated client by copy below).
COPY src/package.json ./
RUN npm install --omit=dev --ignore-scripts --no-audit --no-fund \
 && npm cache clean --force \
 && rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx
# Bring in the generated Prisma client + musl query engine and the built app.
COPY --from=build /app/node_modules/.prisma ./node_modules/.prisma
COPY --from=build /app/node_modules/@prisma/client ./node_modules/@prisma/client
COPY --from=build /app/dist ./dist
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh

# 'node' is the base image's built-in non-root user (uid 1000).
USER node
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
