# Out-of-Band Exfiltration on Oracle via UTL_HTTP

> Track: `sqli` · Difficulty: **expert** · ~55 min · Free hints.
>
> **Heavy-tier lab.** Oracle Database 21c XE needs ~2.5 GB image and >512 MB RAM,
> so this lab runs in the project's nightly **heavy-nightly** CI matrix, not on
> every PR. Locally: `docker compose up` as usual (all posture rules are
> identical to the standard tier — only the resource budget is larger).

## Scenario

`Acme Reports` is an internal reporting endpoint backed by Oracle 21c. Its
`GET /reports/by-region?region=<r>` route runs a SQL query using the classic
string-concatenation anti-pattern:

```sql
SELECT COUNT(*) FROM reports WHERE region = '<r>'
```

Three things kill every "read data out of the response" strategy at once:

1. **No result echo** — the handler normalises the response to a fixed
   `{"ok": true, "message": "found N reports"}`. Rows never reach the client.
2. **No error text** — every exception collapses into a generic
   `{"ok": false, "error": "server error"}`. No SQL text leaks.
3. **No timing** — a random ~100 – 600 ms jitter is added to every response
   (documented here so you don't waste time trying time-based).

But the application's Oracle role (`REPORTAPP`) has been granted `EXECUTE ON
UTL_HTTP` plus a **network ACL** that permits it to call HTTP against exactly
one host: `oob:9000`, an in-lab collector sidecar sitting on the database's
private network. That is not the attacker channel the operators meant to
provide — it is your out-of-band channel.

## Objective

Exfiltrate `secrets.oracle_secret` (32 lowercase hex characters, unique per
container) to the collector, read it back through the app's proxy, and submit:

```
POST /solve   {"secret":"<32 hex>"}
```

`/solve` compares your submission constant-time against the stored value and
returns `FLAG{<64 hex>}` on a match. The secret is derived from
`LAB_USER_SECRET`, so a value from another instance will not validate.

## Getting Started

1. Probe the query — send `region=APAC`, `region=EMEA`, `region=' -- `. The
   endpoint stays a black box even when the SQL fails.
2. Recall that Oracle **cannot stack** two `SELECT` statements the way MySQL or
   PostgreSQL can — no `; DROP TABLE …` in a normal query context. That
   constrains what shape your injection can take.
3. What Oracle package would let a query cause a **side effect** you can
   observe from outside the database, without ever needing the response body?

**CVE analog family.** Application roles that hold `UTL_HTTP` / `UTL_INADDR` /
`DBMS_LDAP` privileges are a recurring finding on Oracle-backed enterprise
stacks — the classic Chris Anley "Hackproofing Oracle" work plus modern OOB
research (Vozec, GossiTheDog). **CWE-89 → CWE-918 (SSRF via injected DB side
effect).** No vendor code is reproduced.
