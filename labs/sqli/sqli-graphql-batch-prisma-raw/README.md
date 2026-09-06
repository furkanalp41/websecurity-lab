# GraphQL Batch Aliases Feeding a Raw Prisma Sink

> Track: `sqli` · Difficulty: **expert** · ~40 min · Free hints.

## Scenario

"Field Reports" is an internal security-reporting API. It speaks GraphQL and is
built on the modern Node stack everyone reaches for: Apollo Server 4, TypeScript,
and Prisma talking to PostgreSQL. The team is careful — they use an ORM precisely
so they never have to hand-write SQL.

But one resolver needed a "search titles that contain X" feature, and Prisma's
type-safe query builder felt clumsy for a `LIKE`. So a developer dropped down to
raw SQL for "just this one query":

```graphql
type Query {
  searchReports(filter: String!): [Report!]!
}
```

```ts
const sql = "SELECT id, title FROM reports WHERE title LIKE '%" + filter + "%'";
const rows = await prisma.$queryRawUnsafe(sql);
```

`$queryRawUnsafe` runs whatever string you hand it — the `filter` argument is
pasted straight into the query. That is classic SQL injection (CWE-89), wearing an
ORM's clothes.

There is a second ingredient that makes this lab bite harder than a normal blind
injection. GraphQL lets a **single** HTTP request carry **many aliased copies** of
the same field:

```graphql
query {
  a: searchReports(filter: "x") {
    id
  }
  b: searchReports(filter: "y") {
    id
  }
  c: searchReports(filter: "z") {
    id
  }
}
```

Each alias runs the resolver again. So one request can fire hundreds of probes.
There is no query-depth or complexity limit, and a `/metrics` endpoint even reports
how many times the resolver has run so you can watch the amplification.

## Objective

The database holds a `secrets` table with a single column, `batch_flag`: a
**40-character** lowercase-hex string, regenerated fresh for your instance on every
boot. It lives in a different table from `reports`, and no query returns it
directly.

1. Confirm `searchReports.filter` is injectable and behaves as a **boolean
   oracle** (a probe returns >= 1 report row iff your injected condition is true).
2. Use that oracle to read `secrets.batch_flag` one character at a time —
   batching many probes per request so the whole extraction is a handful of
   round-trips, not thousands.
3. `POST /solve` with JSON `{"flag": "<the 40-char secret>"}`. On an exact match
   the service returns your flag.

The flag looks like `FLAG{<64 hex characters>}` and is unique to your instance — a
flag copied from another machine will never validate on yours.

## Getting Started

1. Launch the lab and note the instance URL. The GraphQL endpoint is
   `POST /graphql` with a JSON body `{"query": "..."}` and content-type
   `application/json`.
2. Warm up:
   ```
   query { searchReports(filter: "a") { id title } }
   query { metrics { searchReportsCalls graphqlRequests } }
   ```
   Watch how `searchReportsCalls` jumps when you send several aliases in one
   request — that ratio is the batching amplification you will lean on.
3. Now make the search lie. Close the string literal in `filter`, `AND` a
   condition whose answer you know, and comment out the trailing `%'`. When you
   can flip the row count on demand, point the condition at `secrets.batch_flag`.
   Reveal the hints in order if you get stuck — they are free.

**CVE analog family.** Boolean-based **blind SQL injection** (CWE-89, OWASP
**A03:2021 – Injection**) reached through an ORM "raw" escape hatch, amplified by
**GraphQL alias/operation batching**. This mirrors a recurring bug-bounty pattern:
teams trust their ORM, reach for a raw method for one query, and reintroduce the
oldest flaw in the book — while GraphQL batching removes the request-count friction
that used to make blind extraction slow. See Prisma's own warnings about
`$queryRawUnsafe`, PortSwigger's blind-SQLi material, and Assetnote's research on
GraphQL batching amplification. No vendor code is reproduced here.
