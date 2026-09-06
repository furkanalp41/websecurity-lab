# Prisma $queryRaw Concatenation in a JSON API

> Track: `sqli` · Difficulty: **practitioner** · ~30 min · Free hints.

## Scenario

An internal "report service" is written in the modern TypeScript stack every team
seems to reach for: Fastify on top of Prisma, backed by PostgreSQL. Prisma has a
reputation for being _safe by default_ — its query builder parameterises
everything — so the team assumed injection was a solved problem.

Then a hurried developer needed a filter that the query builder didn't express
cleanly and reached for a raw escape hatch:

```ts
const sql = "SELECT id, title, status FROM reports WHERE status = '" + status + "'";
const rows = await prisma.$queryRawUnsafe(sql);
```

The endpoint is `POST /api/reports`, and it takes a JSON body:

```json
{ "filter": { "status": "open" } }
```

The `status` **value** from that JSON is concatenated straight into the SQL text.
The catch that everyone forgets: `$queryRawUnsafe` is **not** the tagged-template
`$queryRaw`. It does not parameterise anything — it runs the string you hand it,
verbatim. So this is a classic, first-class SQL injection wearing an ORM costume.

## Objective

There is a confidential `audit_logs` table. Exactly one of its rows has
`action = 'FLAG_ISSUE'`, sitting at a **random, non-guessable id** that changes
every time the lab starts. Use the injection to read that id out of the database,
then submit it:

```
POST /solve   { "id": <that id> }
```

On a match, `/solve` returns the flag (`FLAG{<64 hex>}`, unique to your instance).

## Getting Started

1. Launch the lab and open the instance URL. `GET /` prints the two endpoints.
2. Send a normal request and watch it work:

   ```
   POST /api/reports   {"filter":{"status":"open"}}
   ```

   You'll get back the matching report rows — and, helpfully for learning, the
   exact SQL string the server built.

3. Now think about where your `status` value lands in that SQL string. It is
   inside single quotes. What happens if your value contains a single quote?
   Verbose database errors are returned to help you tune the payload.
4. Reveal the hints in order if you get stuck. They are free.

**CVE analog family.** Raw-query escape hatches in "safe" ORMs are a recurring
**CWE-89 / OWASP A03:2021** source — Snyk's 2024 sweep found `$queryRawUnsafe`
misuse littered across public GitHub, and the same shape exists in every ORM that
offers a raw mode. No vendor code is reproduced here.
