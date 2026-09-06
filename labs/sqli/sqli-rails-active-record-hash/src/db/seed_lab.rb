# SPDX-License-Identifier: MIT
#
# Idempotent schema + data seeding, run once at container startup via
# `rails runner`. We use plain CREATE TABLE IF NOT EXISTS DDL (not migrations)
# so nothing needs to write db/schema.rb on the read-only root filesystem.
require "securerandom"

conn = ActiveRecord::Base.connection

conn.execute(<<~SQL)
  CREATE TABLE IF NOT EXISTS reports (
    id         BIGSERIAL PRIMARY KEY,
    title      TEXT NOT NULL,
    status     TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP NOT NULL DEFAULT now()
  )
SQL

conn.execute(<<~SQL)
  CREATE TABLE IF NOT EXISTS secrets (
    id         BIGSERIAL PRIMARY KEY,
    master_key TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP NOT NULL DEFAULT now()
  )
SQL

# A handful of open incident reports. Distinct ids matter: the ORDER BY oracle
# flips the FIRST returned row between the lowest-id and the highest-id record.
if Report.count.zero?
  [
    "Q1 revenue reconciliation anomaly",
    "Login latency spike (eu-west)",
    "Nightly data export backlog",
    "Webhook delivery retries failing",
    "Stale cache entries after deploy",
    "Dashboard timezone off-by-one",
  ].each { |title| Report.create!(title: title, status: "open") }
end

# The per-container secret: a 16-char lowercase-hex token. 16 characters keeps
# the sort-based blind extraction (a few requests per character) well under the
# 60s exploit budget. SecureRandom.hex(8) => 16 hex chars.
if Secret.count.zero?
  Secret.create!(master_key: SecureRandom.hex(8))
end

puts "[seed] reports=#{Report.count} secrets=#{Secret.count}"
