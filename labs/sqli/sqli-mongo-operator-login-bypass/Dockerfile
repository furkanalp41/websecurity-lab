# SPDX-License-Identifier: MIT
# Multi-stage build: install production-only Node deps on a build stage, then copy
# just node_modules + app source into a minimal non-root alpine runtime. No baked
# flag (entrypoint.sh writes the per-container flag at runtime). Digest-pinned bases.

FROM node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293 AS build
WORKDIR /opt/app
# Only package.json is needed to resolve deps; there is no compile/build step for
# this plain-JS app, so we install prod deps and drop the npm cache in one layer.
COPY src/package.json /opt/app/package.json
RUN npm install --omit=dev --no-audit --no-fund \
 && npm cache clean --force \
 && rm -rf /root/.npm /tmp/* \
 && rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx

FROM node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293
# Dedicated non-root user (uid 10001). -H: no home dir needed; the app writes only
# to tmpfs paths defined in docker-compose.yml. The runtime never runs npm (it only
# `node server.js`), so strip the base image's bundled npm — its deep dependency
# tree (tar/pacote/sigstore/minimatch/...) otherwise carries fixed HIGH CVEs that
# the Trivy library gate blocks, none of them reachable in a no-npm runtime.
RUN adduser -D -H -u 10001 app \
 && rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx
ENV NODE_ENV=production
WORKDIR /opt/app
COPY --from=build /opt/app/node_modules /opt/app/node_modules
COPY src/ /opt/app/
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh

USER app
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
