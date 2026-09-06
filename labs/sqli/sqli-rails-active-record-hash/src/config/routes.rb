# SPDX-License-Identifier: MIT
Rails.application.routes.draw do
  # Liveness probe: a plain Rack endpoint so it never depends on the DB or the
  # controller stack. Returns exactly "ok" as text/plain.
  health = ->(_env) { [200, { "Content-Type" => "text/plain" }, ["ok"]] }
  get "/health", to: health
  get "/", to: health

  # The deliberately-vulnerable endpoint: GET /reports?filter[status]=open&sort=<x>
  get "/reports", to: "reports#index"

  # Submit the recovered secrets.master_key to claim the per-container flag.
  post "/solve", to: "solve#create"
end
