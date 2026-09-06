# SPDX-License-Identifier: MIT
# Multi-stage build. Stage 1 compiles native gems (pg) against build tools; the
# runtime stage carries only libpq5 + the resolved gems + app source, so the
# final image stays well under the 300 MB cap. Bases are digest-pinned.
#
# Bases are digest-pinned to a real, resolvable ruby:3.3-slim manifest.

FROM ruby:3.3-slim@sha256:79f7a07363931fde1a5b312dee281fd62ddf56c33bdba0c2622af9b4621182fb AS build

ENV LANG=C.UTF-8 \
    BUNDLE_WITHOUT="development:test" \
    BUNDLE_PATH=/opt/app/vendor/bundle \
    BUNDLE_JOBS=4 \
    BUNDLE_RETRY=3 \
    BUNDLE_NO_INSTALL_DOCUMENTATION=1 \
    # Compile the `pg` gem from source so its C extension links against the
    # system libpq (libpq-dev here / libpq5 at runtime). The precompiled
    # x86_64-linux fat gem instead ships a private "libpq-ruby-pg.so.1" that our
    # image slimming strips, leaving pg_ext.so unable to resolve it. Forcing the
    # ruby platform recompiles the native gems from source (pg + puma, and the
    # nokogiri that actionpack pulls in transitively — it vendors its own libxml2),
    # all supported by the build-essential toolchain installed above.
    BUNDLE_FORCE_RUBY_PLATFORM=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential libpq-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/app

# Resolve + build gems first (better layer caching), then copy the source.
# Aggressive slimming: no rdoc/ri, drop the gem cache, compiled object files,
# native-extension source, per-gem test/spec/doc trees, and nokogiri's bundled
# libxml/libxslt source tarballs ("ports") — the precompiled .so is all we ship.
COPY src/Gemfile /opt/app/Gemfile
RUN bundle install --no-cache \
 && rm -rf /opt/app/vendor/bundle/ruby/*/cache \
 && find /opt/app/vendor/bundle -type f \( -name '*.o' -o -name '*.c' -o -name '*.h' \) -delete \
 && rm -rf /opt/app/vendor/bundle/ruby/*/gems/*/test \
           /opt/app/vendor/bundle/ruby/*/gems/*/spec \
           /opt/app/vendor/bundle/ruby/*/gems/*/doc \
           /opt/app/vendor/bundle/ruby/*/gems/*/ports \
           /opt/app/vendor/bundle/ruby/*/gems/*/ext \
           /opt/app/vendor/bundle/ruby/*/gems/*/examples \
           /opt/app/vendor/bundle/ruby/*/doc \
           /opt/app/vendor/bundle/ruby/*/cache

COPY src/ /opt/app/

# ---------------------------------------------------------------------------

FROM ruby:3.3-slim@sha256:79f7a07363931fde1a5b312dee281fd62ddf56c33bdba0c2622af9b4621182fb AS runtime

ENV LANG=C.UTF-8 \
    BUNDLE_WITHOUT="development:test" \
    BUNDLE_PATH=/opt/app/vendor/bundle \
    BUNDLE_FROZEN=true \
    RAILS_ENV=production \
    RACK_ENV=production \
    RAILS_LOG_TO_STDOUT=1 \
    # The rootfs is read-only; point HOME at the app's writable tmpfs so that
    # bundler/rubygems never try to create ~/.bundle under a read-only path.
    HOME=/opt/app/tmp \
    BUNDLE_USER_HOME=/opt/app/tmp/.bundle

# libpq5 is the only shared library the runtime needs (for the pg gem). No
# compilers or -dev packages in the final image.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libpq5 \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -g 10001 app \
 && useradd -u 10001 -g 10001 -m -s /usr/sbin/nologin app \
 # The app uses resolv 0.7.2 from vendor/bundle, but ruby:3.3-slim still ships the
 # stale DEFAULT resolv 0.3.1 gemspec (CVE-2026-80212) which Trivy flags. Drop the
 # stale default marker; the patched bundled gem is what actually loads.
 && rm -f /usr/local/lib/ruby/gems/3.3.0/specifications/default/resolv-0.3.1.gemspec

WORKDIR /opt/app

# Bring over the fully-built app (gems in vendor/bundle, Gemfile.lock, source).
COPY --from=build /opt/app /opt/app
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh

USER app
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
