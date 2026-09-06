# SPDX-License-Identifier: MIT
# Multi-stage build: compile the CGO SQLite app on golang:1.25-alpine, then run a
# fully static binary on a minimal non-root alpine. Digest-pinned bases; no baked
# flag (entrypoint.sh writes the per-container flag at runtime).

FROM golang:1.25-alpine@sha256:1ae0735f00daffa3aaf1363a5184c0d2dc55c78e3db4ec70241cdac97bf84b59 AS build
# build-base supplies gcc + musl-dev so cgo (mattn/go-sqlite3) can compile.
RUN apk add --no-cache build-base
# Default -mod=readonly + committed go.sum verify module checksums at build time.
ENV CGO_ENABLED=1 \
    GOTOOLCHAIN=local
WORKDIR /src
COPY src/ ./
# Static musl build so the runtime image needs no C toolchain or shared libs.
# netgo/osusergo keep the Go resolver and user lookups pure-Go (cgo stays only
# for mattn/go-sqlite3), which is the reliable recipe for a static cgo binary.
RUN go build \
      -tags "sqlite_omit_load_extension netgo osusergo" \
      -ldflags '-s -w -linkmode external -extldflags "-static"' \
      -o /out/lab-app .

FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
# openssl computes the flag HMAC in entrypoint.sh; busybox wget (base) is the
# healthcheck client. Non-root app user; no baked secrets.
RUN apk add --no-cache openssl \
 && adduser -D -H -u 10001 app
COPY --from=build /out/lab-app /usr/local/bin/lab-app
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/lab-app /usr/local/bin/entrypoint.sh

USER app
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
