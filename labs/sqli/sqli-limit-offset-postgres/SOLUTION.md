# Solution — sqli-limit-offset-postgres

## What tipped you off

`/feed?page=N` shifts which rows come back, so `page` clearly reaches SQL — and it
lands in the `OFFSET` position, not inside a string. Sending `?page=abc` returns a
raw Postgres error instead of a clean page, which tells you two things at once:
your input is unquoted (a bare word is being parsed as SQL, not data) and the app
hands you the database's error text verbatim.

## The class of bug

SQL injection (CWE-89, OWASP A03:2021) in an **integer `LIMIT`/`OFFSET`
context**, paired with **verbose error exposure** (CWE-209). The value is not
inside quotes, so this is not "break out of a string literal" — it is "supply a
SQL expression where an integer was expected." The echoed error turns a type
failure into a data read channel.

## Vulnerability

`src/app.py`, `/feed`:

```python
size = request.args.get("size", "10")
page = request.args.get("page", "0")
sql = (
    "SELECT title, body FROM feed ORDER BY id "
    "LIMIT " + size + " OFFSET " + page
)
```

`size` and `page` are concatenated straight into the `LIMIT` and `OFFSET`
positions with no cast, no parameter binding, and no allowlist.

## Why it exists / Why the developer wrote it this way

Pagination is "obviously just numbers," so it is a classic place to skip
parameterization. It also _feels_ unbindable: you cannot always bind clause
fragments as parameters, and `LIMIT`/`OFFSET` look structural. The endpoint
passes every test where `page` and `size` really are integers, so the bug ships.

## Why UNION-after-LIMIT does NOT work here

This is the crux of the lab. The instinct after finding SQLi is `UNION SELECT`,
but Postgres grammar does not allow a set operation to follow `LIMIT`/`OFFSET`:

```
SELECT title, body FROM feed ORDER BY id LIMIT 10 UNION SELECT ...   -- syntax error
```

In the SQL grammar, `LIMIT` and `OFFSET` are _trailing_ clauses of a
`select_no_parens` — a `UNION` has to combine two complete queries and sits at a
higher level than the `ORDER BY`/`LIMIT`/`OFFSET` tail. Once you are past
`LIMIT`, the only place a `UNION` could go is _before_ it, wrapped in
parentheses, which you cannot reach by appending to the end. So the usual UNION
extraction is off the table, and stacked queries (`; SELECT ...`) do not work
either because the driver sends a single statement and there is nothing to
terminate.

## Why the OFFSET scalar-subquery error oracle IS the correct PG technique

Postgres allows an **arbitrary integer-valued expression** in the `LIMIT` and
`OFFSET` positions — including a parenthesised **scalar subquery**. That is fully
grammatical:

```sql
SELECT title, body FROM feed ORDER BY id
LIMIT 10 OFFSET (SELECT CAST(recovery_code AS integer) FROM users WHERE role='admin' LIMIT 1)
```

The planner must evaluate the `OFFSET` expression to know how many rows to skip,
so it runs the subquery. The subquery computes `CAST(recovery_code AS integer)`
for the admin row; `recovery_code` is a 24-char alphanumeric string, so the cast
fails **at evaluation time** and Postgres raises:

```
invalid input syntax for type integer: "<recovery_code>"
```

Postgres puts the _entire_ offending value in the message, untruncated, between
double quotes. Because `/feed` echoes the error verbatim, that value is now on
your screen. This is why the OFFSET scalar-subquery is the reliable Postgres
technique where UNION cannot reach.

## The mechanical exploit / Exploit walkthrough

1. Put the oracle subquery in `page` (the `OFFSET` position):

   ```
   GET /feed?page=(SELECT%20CAST(recovery_code%20AS%20integer)%20FROM%20users%20WHERE%20role='admin'%20LIMIT%201)&size=10
   -> 500 DB error: ... invalid input syntax for type integer: "Qk7f...<24 chars>" ...
   ```

2. Read the `recovery_code` out of the quotes in the error, then redeem it:

   ```
   GET /solve?code=Qk7f...   ->   200 {"flag":"FLAG{...}"}
   ```

`tests/exploit.py` performs exactly this — one request to leak, one to redeem —
and asserts the flag matches the HMAC-derived expected value. It is deterministic
and finishes in well under a second. The `LIMIT` position works identically
(`size=(SELECT ...)`), so probing either integer slot is a valid exercise. A
boolean variant — `OFFSET (SELECT CASE WHEN (<cond>) THEN 1 ELSE 1/0 END)` to
force a division-by-zero on a false branch — proves conditional control without
the verbose-error channel and is a good next step.

## Fix

Coerce pagination inputs to integers before they ever reach the query, and clamp
them to a sane range:

```python
try:
    size = min(max(int(request.args.get("size", "10")), 1), 100)
    page = max(int(request.args.get("page", "0")), 0)
except ValueError:
    size, page = 10, 0
# size and page are now plain ints; safe to bind or interpolate.
sql = text("SELECT title, body FROM feed ORDER BY id LIMIT :lim OFFSET :off")
rows = conn.execute(sql, {"lim": size, "off": page}).fetchall()
```

`int()` rejects anything that is not a number, so attacker input can never reach
the statement as code, and binding removes the concatenation entirely. Also stop
returning raw database errors to clients (log them server-side, show a generic
message) to close the CWE-209 read channel.
