# SPDX-License-Identifier: MIT
require "active_support/core_ext/integer/time"

Rails.application.configure do
  # Eager load the whole app at boot (production default) so the first request
  # is not paying the load cost and any load error surfaces immediately.
  config.eager_load = true

  config.consider_all_requests_local = false

  # secret_key_base comes from the SECRET_KEY_BASE env var (set in compose).
  config.require_master_key = false

  # No file cache on a read-only rootfs.
  config.cache_store = :null_store

  config.active_support.report_deprecations = false

  # API responses are JSON; render framework exceptions as JSON, not HTML pages.
  config.action_dispatch.show_exceptions = :rescuable

  config.log_level = ENV.fetch("RAILS_LOG_LEVEL", "info").to_sym
end
