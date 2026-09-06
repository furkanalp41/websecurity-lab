# SPDX-License-Identifier: MIT
# Multi-stage build: compile TypeScript and generate the Prisma client on a full
# node:20-alpine toolchain, then ship only the production node_modules, the
# generated Prisma client (with the musl query-engine), and the built dist/ on a
# fresh node:20-alpine runtime. Digest-pinned bases; no baked flag (entrypoint.sh
# writes the per-container flag at runtime).

# ---- build stage -------------------------------------------------------------
FROM node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293 AS build
# Prisma needs libssl/openssl present to select the correct query-engine.
RUN apk add --no-cache openssl
WORKDIR /app
# Install the full dependency tree (incl. dev: prisma CLI + typescript) against
# the committed lockfile for a reproducible build.
COPY src/package.json src/package-lock.json ./
RUN npm ci --no-audit --no-fund
# Bring in the schema + sources, then generate the client and compile.
COPY src/ ./
# On Alpine, `native` resolves to linux-musl-openssl-3.0.x, so this fetches the
# musl query-engine the runtime needs.
RUN npx prisma generate
RUN npx tsc -p tsconfig.json

# ---- runtime stage -----------------------------------------------------------
FROM node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293
ENV NODE_ENV=production \
    HOME=/tmp
# openssl lets Prisma's query-engine detect libssl 3.x and load the musl-3.0.x
# engine at runtime (without it Prisma defaults to a missing 1.1.x engine).
RUN apk add --no-cache openssl \
 && addgroup -g 10001 app \
 && adduser -D -H -u 10001 -G app app
WORKDIR /app
# Production-only dependencies (fastify + @prisma/client runtime; no dev deps).
# --ignore-scripts skips the @prisma/client postinstall: it cannot generate
# without the prisma CLI/schema (both dev-only) and we supply the generated
# client by copy below, so its postinstall must not run (or fail) here.
COPY src/package.json src/package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund \
 && npm cache clean --force \
 && rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx
# Overlay the generated Prisma client (DMMF + musl query-engine) from the build
# stage. @prisma/client re-exports from node_modules/.prisma/client.
COPY --from=build /app/node_modules/.prisma ./node_modules/.prisma
# Built JavaScript.
COPY --from=build /app/dist ./dist
# Runtime entrypoint.
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh

USER app
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
