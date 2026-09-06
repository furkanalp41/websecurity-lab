# Injection Inside LIMIT/OFFSET on Postgres

> Track: `sqli` · Difficulty: **practitioner** · ~30 min · Free hints.

## Scenario

**Streamline** is a tiny Postgres-backed activity feed. Its pagination endpoint,
`/feed?page=0&size=10`, builds the query by pasting both numbers straight into
the statement:

```
SELECT title, body FROM feed ORDER BY id LIMIT <size> OFFSET <page>
```

The developer "knows" `page` and `size` are always numbers, so there are no
quotes and no casts around them. That is the whole bug. There is no string
literal to escape here — so the reflexive `' OR '1'='1` payloads do nothing — but
the `LIMIT` and `OFFSET` positions accept a full SQL _integer expression_, and
the app prints Postgres errors back to you verbatim.

## Objective

Reach into the `users` table, read the **admin** row's `recovery_code` (a random
24-character value unique to your instance), and submit it to
`/solve?code=<value>` to receive the flag as JSON (`{"flag":"FLAG{<64 hex>}"}`).

The catch that makes this a _practitioner_ lab: the obvious `UNION SELECT` cannot
follow `LIMIT` in Postgres grammar. You will need the Postgres-correct technique
for pulling data out of a `LIMIT`/`OFFSET` context.

## Getting Started

1. Launch the lab and browse `/feed?page=0&size=10`, then `?page=2`, `?page=4` —
   the rows shift, confirming `page` reaches the `OFFSET` in the SQL.
2. Try `?page=abc` — you will see a Postgres error echoed straight to the page.
   Errors being verbose is a gift: it is your read channel.
3. Ask the real question: what can legally go where an `OFFSET` integer goes,
   besides a plain number?
4. Reveal the hints in order if you get stuck. They are free.

**CVE analog family.** Injection into a `LIMIT`/`OFFSET` (non-string, integer)
context is a recurring **CWE-89 / OWASP A03:2021** pattern, with the verbose
error read channel adding **CWE-209** — see PortSwigger's LIMIT-clause lab and
Postgres error-oracle write-ups. No vendor code is reproduced here.
