# Column Discovery via ORDER BY on Blog Archive

> Track: `sqli` · Difficulty: **apprentice** · ~25 min · Free hints.

## Scenario

A small Postgres-backed blog exposes `/archive?sort=3`. The value is dropped into
an `ORDER BY` clause built by string concatenation, and the developer "assumed" it
is always a number — so there are no quotes around it. That single detail changes
everything: the usual `' OR '1'='1` payloads have no string literal to break out
of, but the `ORDER BY` position happily accepts a whole SQL _expression_. Database
errors are printed straight to the page.

## Objective

Work out that the `sort` value lands in an expression context, then coerce the
database into an error whose message contains the value of `current_user`. Submit
that value to `/solve?user=<value>` to get the flag (`FLAG{<64 hex>}`, unique to
your instance).

## Getting Started

1. Launch the lab and open the instance URL, then browse `/archive?sort=1`,
   `?sort=2`, `?sort=3` — the ordering changes, confirming `sort` reaches SQL.
2. Try `?sort='` — you will not get a clean break, because there is no quote to
   close. Ask instead: what _else_ can go where a column number goes?
3. Reveal the hints in order if you get stuck. They are free.

**CVE analog family.** Injection into an `ORDER BY` / non-string context is a
recurring **CWE-89 / OWASP A03:2021** pattern — see PortSwigger's ORDER BY lab and
the Postgres error-oracle write-ups. No vendor code is reproduced here.
