# Django ORM Escape Hatch: .extra() Misuse

> Track: `sqli` · Difficulty: **expert** · ~40 min · Free hints.

## Scenario

"Catalogue Search" is an internal product-search service built by a team that
prides itself on using the Django ORM for everything — and everyone knows the
ORM parameterises queries for you, so SQL injection is a solved problem. Right?

Almost. One feature slipped through. The **advanced fuzzy search** at
`GET /search?q=<term>` needed a `LIKE '%term%'` filter, and rather than express
that through the ORM's field lookups, a developer reached for the escape hatch:

```python
Product.objects.extra(where=[f"title LIKE '%%{q}%%'"])
```

`QuerySet.extra()` takes **raw SQL strings**. Whatever you hand it is spliced
into the query verbatim — the ORM's parameterisation stops at the edge of that
string. The `%%` are just LIKE wildcards written the way the database driver
wants them; they are not a defence. The user's `q` is now inside your SQL.

## Objective

The catalogue itself is boring. Your target is Django's built-in `auth_user`
table. At startup the container creates a **superuser `root` with a random
password**, so its `pbkdf2_sha256$…` hash is unique to your instance. Exfiltrate
that exact hash through the search injection, then `POST /solve` with it (form
field `hash`). On an exact match the JSON response returns the flag
(`{"flag": "FLAG{<64 hex>}"}`, unique to your container).

## Getting Started

1. Launch the lab and open the instance URL. Try a normal search, e.g.
   `/search?q=mug`, and watch the results table fill in.
2. Now poke it: what happens with `/search?q='` ? Read the error — the app is
   deliberately chatty about database errors here to help you.
3. Figure out how many columns the results query selects, and which one is
   rendered where. You will need to line a `UNION SELECT` up with it.
4. Reveal the hints in order if you get stuck. They are free.

**CVE-analog family.** This is **SQL injection via an ORM escape hatch** —
**CWE-89 / OWASP A03:2021**. `QuerySet.extra()`, `Manager.raw()`, and `RawSQL()`
all take raw SQL and are recurring real-world sinks; Django has shipped several
advisories in the raw-SQL / `.extra()` / `.explain()` family (e.g.
CVE-2022-28347, CVE-2022-34265). "We use an ORM" is not a security control. No
vendor code is reproduced here.
