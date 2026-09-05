-- SPDX-License-Identifier: MIT
-- Local progress database (~/.websec-lab/progress.db). Applied on serve startup.
CREATE TABLE IF NOT EXISTS _schema_migrations (
  version    INTEGER PRIMARY KEY,
  applied_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS labs (
  lab_slug            TEXT PRIMARY KEY,
  category            TEXT NOT NULL,
  first_launched_at   INTEGER,
  first_solved_at     INTEGER,
  attempts            INTEGER NOT NULL DEFAULT 0,
  successful_attempts INTEGER NOT NULL DEFAULT 0,
  time_to_flag_ms     INTEGER,
  last_launched_at    INTEGER,
  total_time_ms       INTEGER NOT NULL DEFAULT 0,
  mode                TEXT NOT NULL DEFAULT 'personal',  -- personal | shared
  flag_seen           TEXT
);

CREATE TABLE IF NOT EXISTS hint_uses (
  lab_slug   TEXT NOT NULL,
  hint_index INTEGER NOT NULL,
  used_at    INTEGER NOT NULL,
  PRIMARY KEY (lab_slug, hint_index)
);

CREATE TABLE IF NOT EXISTS flag_attempts (
  id         INTEGER PRIMARY KEY,
  lab_slug   TEXT NOT NULL,
  guess_hash TEXT NOT NULL,   -- sha256 of guess, never the guess itself
  correct    INTEGER NOT NULL,
  at         INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  id           INTEGER PRIMARY KEY,
  lab_slug     TEXT NOT NULL,
  started_at   INTEGER NOT NULL,
  ended_at     INTEGER,
  container_id TEXT,
  host_port    INTEGER
);
