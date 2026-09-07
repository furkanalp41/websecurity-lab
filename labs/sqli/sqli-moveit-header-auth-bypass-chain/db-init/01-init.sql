-- SPDX-License-Identifier: MIT
-- Runs ONCE at Postgres init (docker-entrypoint-initdb.d) as the bootstrap
-- superuser. It creates the schema + seed data AND a least-privilege application
-- role. The app connects as that non-superuser role, which is the security-
-- critical part: a non-superuser CANNOT run COPY ... FROM/TO PROGRAM, so the same
-- stacked-query injection that forges a session row can NOT be turned into
-- command execution. The intended attack (a plain INSERT into sessions) needs no
-- special privilege and still works.

CREATE TABLE IF NOT EXISTS audit_log (
    id         SERIAL PRIMARY KEY,
    comment    TEXT NOT NULL,
    client_ip  TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sessions (
    token    TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    is_admin BOOLEAN NOT NULL DEFAULT false,
    expires  TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id       SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    is_admin BOOLEAN NOT NULL DEFAULT false
);

-- The built-in sysadmin account. Its password is random and never exposed, so it
-- cannot be logged into — you must forge its session.
INSERT INTO users (username, password, is_admin)
VALUES ('sysadmin', md5(random()::text || clock_timestamp()::text || random()::text), true)
ON CONFLICT (username) DO NOTHING;
INSERT INTO users (username, password, is_admin)
VALUES ('guest', 'guest', false)
ON CONFLICT (username) DO NOTHING;

INSERT INTO audit_log (comment, client_ip) VALUES
    ('nightly backup complete', '10.0.0.9'),
    ('quarterly report uploaded', '10.0.0.14');

-- Least-privilege application role: NOSUPERUSER (cannot COPY ... PROGRAM), with
-- only the object privileges the app legitimately needs plus the INSERT on
-- sessions that makes the *intended* forgery injection reachable.
CREATE ROLE moveitapp LOGIN PASSWORD 'moveit-app-pw' NOSUPERUSER NOCREATEDB NOCREATEROLE;
GRANT USAGE ON SCHEMA public TO moveitapp;
GRANT INSERT ON audit_log TO moveitapp;
GRANT INSERT, SELECT ON sessions TO moveitapp;
GRANT SELECT ON users TO moveitapp;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO moveitapp;
