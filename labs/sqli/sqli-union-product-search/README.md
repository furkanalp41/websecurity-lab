# UNION-Based Extraction on Vintage Vinyl Store

> Track: `sqli` · Difficulty: **apprentice** · ~25 min · Free hints.

## Scenario

**Wax & Groove** is a tiny second-hand vinyl shop. Its catalogue is browsable at
`/search?category=jazz`, which lists the title, artist, and price of every
released record in that category. Behind the form is a single SQL query that the
developer assembled by gluing your `category` value straight into the middle of
the statement — no quotes minded, no parameters bound. When a query goes wrong,
the shop helpfully prints the raw MySQL error straight onto the page.

Somewhere in the same database is a table the shop never meant you to see. One of
its columns holds a random per-instance `secret`. If you can read that value, a
hidden endpoint will trade it for the flag.

## Objective

Read the `secret` value out of the `admin_notes` table through the search page,
then submit it to `/solve?token=<secret>`. On a match the server returns the flag
(`FLAG{<64 hex>}`, unique to your instance); a wrong token returns HTTP 403.

The secret is generated fresh inside your container, so a value copied from
someone else's instance will never validate — you must extract _your_ secret.

## Getting Started

1. Launch the lab and open the instance URL, then browse `/search?category=jazz`
   and `?category=rock` — the results change, confirming `category` reaches SQL.
2. Put a single quote in the value (`?category=jazz'`) and read what comes back.
   A server that prints a MySQL syntax error is almost always building that SQL
   by hand from your input.
3. Ask two questions in order: _how many columns does the visible query return_,
   and _what other table could I graft onto those columns_? Reveal the hints in
   order if you get stuck — they are free.

**CVE analog family.** UNION-based SQL injection that reads a second table is a
classic **CWE-89 / OWASP A03:2021 – Injection** pattern, compounded here by
verbose error disclosure (**CWE-209**). See PortSwigger's UNION-attack labs and
the long tail of CVEs where a search/filter parameter is concatenated into a
`SELECT`. No vendor code is reproduced here.
