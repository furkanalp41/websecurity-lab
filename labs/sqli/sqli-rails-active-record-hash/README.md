# Rails ActiveRecord Hash-Condition & ORDER BY Injection

> Track: `sqli` · Difficulty: **expert** · ~35 min · Free hints.

## Scenario

An incident-report API built with Rails 7.1 (API-only) exposes:

```
GET /reports?filter[status]=open&sort=<expr>
```

The team did the right thing with `filter` — it runs through strong parameters
and reaches ActiveRecord as a bound _hash condition_, so it is safe. But they
wanted "flexible sorting", and Rails 6.1+ deliberately refuses to drop an
unrecognised raw string into `ORDER BY` (it raises
`ActiveRecord::UnknownAttributeReference`) precisely to stop SQL injection. Rather
than build an allowlist, a developer reached for the escape hatch
`Arel.sql(params[:sort])` — which tells ActiveRecord "trust me, this is safe SQL".
It is not: your input now lands verbatim in `ORDER BY`.

## Objective

There is no endpoint that prints the secret. A `secrets.master_key` (16 lowercase
hex characters) exists in the database and is only ever _verified_, never echoed.
Recover it purely through the **ordering side channel** of the injectable `sort`
parameter, then `POST /solve` with `{"key":"<master_key>"}` to receive the flag
(`FLAG{<64 hex>}`, unique to your instance).

## Getting Started

1. Launch the lab and hit `/reports?sort=id%20asc` and `/reports?sort=id%20desc`.
   Notice the row order — and the first row — change with `sort`.
2. Try `sort=title` vs `sort=id`. The parameter clearly reaches `ORDER BY`. What
   happens if you put an _expression_ there instead of a column name?
3. A malformed expression returns `{"error":"query failed"}` with no stack trace —
   the app stays a black box. The only signal you get is **which row comes first**.
   Reveal the hints in order if you get stuck; they are free.

**CVE analog family.** `ORDER BY` / `order()` injection via a raw-SQL escape hatch
(`Arel.sql`, `.order(params[...])`) is a recurring **CWE-89 / OWASP A03:2021**
pattern in Rails apps. "We use an ORM" is not a defence when raw-SQL escape hatches
take untrusted input. No vendor code is reproduced here.
