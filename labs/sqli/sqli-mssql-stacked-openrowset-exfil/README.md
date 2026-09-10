# Stacked Queries + OPENROWSET BULK File Exfiltration on MSSQL

> Track: `sqli` · Difficulty: **expert** · ~50 min · Free hints.
>
> **Heavy-tier lab.** MSSQL Server 2022 needs ~1.5 GB image and >512 MB RAM,
> so this lab runs in the project's nightly **heavy-nightly** CI matrix, not on
> every PR. Locally: `docker compose up` as usual (all posture rules are
> identical to the standard tier — only the resource budget is larger).

## Scenario

`Acme Asset Inventory` is an internal asset-tracking system backed by
MSSQL Server 2022. Its `GET /assets?category=<c>` route runs a SQL query
using string concatenation:

```sql
SELECT COUNT(*) FROM assets WHERE category = '<c>'
```

Three things kill every "read data out of the response" strategy:

1. **No result echo** — the handler normalises the response to
   `{"ok": true, "message": "found N assets"}`. Rows never reach the client.
2. **No error text** — every exception collapses into
   `{"ok": false, "error": "server error"}`.
3. **No timing** — random ~100 – 600 ms jitter is added to every response.

But the application connects to MSSQL as **SA** (sysadmin), and the ODBC
driver sends the full SQL batch — including any semicolon-separated
statements you inject. MSSQL, unlike Oracle, evaluates **every** statement
in the batch. This is the stacked-queries primitive.

A separate endpoint, `GET /notices`, reads from the `notices` table — a
legitimate company-notices feed. That table is your data channel.

## Objective

Exfiltrate `secrets.mssql_secret` (32 lowercase hex characters, unique per
container) via stacked-query injection and submit:

```
POST /solve   {"secret":"<32 hex>"}
```

`/solve` compares your submission constant-time against the stored value and
returns `FLAG{<64 hex>}` on a match.

## Getting Started

1. Probe the query — send `category=Laptops`, `category=Monitors`,
   `category=' -- `. The endpoint stays a black box.
2. MSSQL supports **stacked queries**: what happens if you inject
   `'; SELECT 1; --`? It does not error, and MSSQL ran both statements.
3. Can you INSERT data from one table into another as a side effect of the
   stacked batch? Where would you read the result?

**Teaching note.** On Windows MSSQL, the classic post-exploitation move is
`xp_cmdshell` for OS command execution. On Linux MSSQL, `xp_cmdshell` is
unavailable (kernel limitation). The alternative for file reads is
`OPENROWSET(BULK '/path', SINGLE_CLOB)` after enabling Ad Hoc Distributed
Queries via `sp_configure`. This lab's primary path uses stacked INSERT
for data-channel exfil; the OPENROWSET path is an advanced bonus.

**CWE-89.** Stacked-query injection is the most powerful SQL injection
variant — it turns a read-only vulnerability into write (INSERT/UPDATE/DELETE)
and configuration change (sp_configure) capability.
