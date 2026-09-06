# WAF Bypass with MySQL Versioned Comments

> Track: `sqli` · Difficulty: **practitioner** · ~35 min · Free hints.

## Scenario

**Gizmo Bazaar** sells gadgets and cables, and its catalogue is searchable at
`/search?q=phone`. Behind the search box is the same old sin — the `q` value is
glued straight into a SQL `LIKE` clause:

```sql
SELECT name, price FROM products WHERE name LIKE '%<q>%'
```

The team knows the endpoint is dodgy, so they bolted a firewall in front of it:
`gizmo-waf`, a keyword filter modelled on ModSecurity with the OWASP Core Rule
Set. Before any query runs, it scans your raw input and returns **HTTP 403** if it
spots a SQL keyword — `SELECT`, `UNION`, `FROM`, `WHERE`, boolean operators, DML/DDL
verbs — or a comment marker (`-- `, `#`). When it blocks you it records the rule
that fired, and `GET /waf-log` will show you the last blocks so you can see exactly
what tripped.

The catch: the WAF matches keywords as **whole words**, but MySQL happily executes
keywords wrapped in **versioned comments** like `/*!50000SELECT*/`. The filter and
the database do not agree on what a keyword is — and that gap is the door.

## Objective

Somewhere in the database is a `secrets` table whose `waf_bypass_flag` column holds
a random per-instance value. Read that value **through the search box, without
tripping a single WAF rule**, then submit it to `/solve?flag=<value>` (the endpoint
also accepts `?token=<value>`). On a match the server returns the flag
(`FLAG{<64 hex>}`, unique to your instance); a wrong value returns HTTP 403.

The secret is generated fresh inside your container, so a value copied from someone
else's instance will never validate — you must extract _your_ secret.

## Getting Started

1. Launch the lab, open the instance URL, and run a normal search
   (`/search?q=phone`) to see the result format.
2. Try the obvious injection first: `/search?q=' UNION SELECT ...-- `. You will be
   blocked. Open `/waf-log` and read which rule IDs fired — this is your feedback
   loop for the rest of the lab.
3. Now ask the key question: _how do I get MySQL to run `UNION SELECT ... FROM`
   without ever writing those words where the regex can see them?_ Reveal the
   hints in order if you get stuck — they are free.

**CVE analog family.** Blocklist-based WAFs defeated by database-specific comment
and encoding tricks are a recurring theme in **CWE-89 / OWASP A03:2021 –
Injection** findings and in the OWASP CRS bypass literature. Versioned comments
(`/*! ... */`) are a MySQL-only feature routinely abused to slip keywords past
signature filters. No vendor code is reproduced here.
