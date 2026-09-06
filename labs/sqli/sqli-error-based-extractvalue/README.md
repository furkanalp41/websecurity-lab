# Error-Based Extraction with EXTRACTVALUE

> Track: `sqli` · Difficulty: **apprentice** · ~25 min · Free hints.

## Scenario

**DeskFlow** is an internal helpdesk. Support staff filter the ticket queue at
`/tickets?assignee=alice`, which lists every ticket assigned to that person. The
developer built the query by gluing your `assignee` value straight into the
middle of the SQL statement — no quotes minded, no parameters bound. When a query
goes wrong, DeskFlow prints the raw MySQL error into a friendly little banner so
staff can "screenshot it for IT".

That banner is the whole game. Unlike a UNION attack, you never need the results
to be _rendered as rows_ — you make the database **fail on purpose** and read the
answer out of its error message. Somewhere in the same schema is a `secrets`
table holding a random per-instance `api_key`. Read it and a hidden endpoint will
trade it for the flag.

## Objective

Extract the `api_key` value from the `secrets` table through the error banner on
`/tickets`, then submit it to `/solve` as a JSON body:

```
POST /solve
Content-Type: application/json

{"key": "<the api_key>"}
```

On a match the server returns the flag (`FLAG{<64 hex>}`, unique to your
instance); a wrong key returns HTTP 403. The key is generated fresh inside your
container, so a value copied from someone else's instance will never validate —
you must extract _your_ key.

## Getting Started

1. Launch the lab and browse `/tickets?assignee=alice` and `?assignee=bob` — the
   queue changes, confirming `assignee` reaches SQL.
2. Put a single quote in the value (`?assignee=alice'`) and read the banner. A
   server that prints a MySQL syntax error is almost always building that SQL by
   hand from your input.
3. Now think about _making the database talk through its errors_. MySQL has a
   family of functions that choke on malformed input and print the offending
   value back to you. Reveal the hints in order if you get stuck — they are free.

**CVE analog family.** Error-based SQL injection that reads data out of a
database error message is a classic **CWE-89 / OWASP A03:2021 – Injection**
pattern, compounded here by verbose error disclosure (**CWE-209**). See the long
tail of CVEs where a filter parameter is concatenated into a `SELECT` and the
driver error is reflected to the client. No vendor code is reproduced here.
