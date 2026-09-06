# SPDX-License-Identifier: MIT
require_relative "boot"

require "rails"
# Load only the frameworks this API needs. No Action Mailer / Active Storage /
# Action Cable / Action View templating -> smaller image, smaller attack surface.
require "active_model/railtie"
require "active_record/railtie"
require "action_controller/railtie"

Bundler.require(*Rails.groups)

module ReportsApi
  class Application < Rails::Application
    config.load_defaults 7.2

    # API-only: no cookies, no CSRF middleware, no view layer.
    config.api_only = true

    # Log to STDOUT so the read-only rootfs never needs a writable log/ file.
    config.logger = ActiveSupport::Logger.new($stdout)
    config.log_level = ENV.fetch("RAILS_LOG_LEVEL", "info").to_sym

    # We create the schema with idempotent DDL in db/seed_lab.rb rather than
    # migrations, so never try to dump db/schema.rb (the rootfs is read-only).
    config.active_record.dump_schema_after_migration = false

    # This lab is reached via its published 127.0.0.1 port and, inside the
    # compose network, by service name. Clearing the host allowlist keeps
    # ActionDispatch::HostAuthorization from rejecting either.
    config.hosts.clear

    # Deliberately no config/initializers/wrap_parameters.rb: parameter wrapping
    # stays OFF, so a JSON body like {"key":"..."} lands directly in params[:key].
  end
end
