# SPDX-License-Identifier: MIT
ENV["BUNDLE_GEMFILE"] ||= File.expand_path("../Gemfile", __dir__)

require "bundler/setup"
# Intentionally NO bootsnap: bootsnap caches compiled code under tmp/cache, and
# this container runs with a read-only root filesystem. Skipping it removes a
# write path and a dependency.
