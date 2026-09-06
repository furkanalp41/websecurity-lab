# Solution — sqli-boolean-blind-account-enum

<!-- Instructor/authoring reference. Students should try the hints first. -->

## What tipped you off

`POST /forgot` returns the exact same body for every username, which _looks_
enumeration-safe. But diff the whole response, not just the body: the
`X-Account-Exists` header flips between `true` and `false` depending on whether
the name exists. That is a one-bit side channel. The moment a server exposes a
reliable true/false signal that depends on your input, ask whether you can make
that bit depend on _anything you want_ — which is exactly what SQL injection buys
you when the input reaches the query as code.

## The class of bug

Two cooperating weaknesses:

- **Boolean-based blind SQL injection** — CWE-89, OWASP **A03:2021 – Injection**.
  There is no UNION output and no error text; the only channel is a single boolean
  per request. That is enough to read the database one comparison at a time.
- **Observable response discrepancy** — CWE-204. The `X-Account-Exists` header is
  the "conditional response" that carries the boolean out to the attacker. Without
  a differing observable, blind SQLi has nothing to read.

## Vulnerability

`src/app.py`, `POST /forgot`:

```python
sql = "SELECT 1 FROM users WHERE username = '" + username + "'"
...
rows = await pool.fetch(sql)
exists = len(rows) > 0
headers = {"X-Account-Exists": "true" if exists else "false"}
```

`username` comes straight from the JSON body and is concatenated into the query
with no parameterization, escaping, or allowlist. The row count then drives a
response header. `/solve`, by contrast, is written correctly with a bound
parameter (`WHERE username = $1`) — it is not injectable, which underlines that
the bug is the _concatenation_, not the database.

## Why the developer wrote it this way

The team had a real requirement — "don't reveal whether an account exists" — and
addressed it at the wrong layer. They normalised the **body** (identical message,
identical status) and felt done. The `X-Account-Exists` header was a debugging aid
that made local testing easier ("did my lookup hit?") and was never stripped
before release. Meanwhile the query itself was the oldest shortcut in the book:
gluing the username into a string reads naturally and works perfectly for every
normal username, so it survived code review. Constant bodies plus a leaky header
plus string-built SQL is a combination that each author thought was harmless on
its own.

## Why it exists

Blind SQLi is exploitable here purely because of the **observable discrepancy**:
the query result changes something the client can see (the header). Postgres
evaluates the injected `AND (...)` condition per row, so the presence or absence
of the `admin` row in the result set — and therefore the header — becomes a direct
readout of any predicate you attach. No error output and no data in the body are
needed; one deterministic bit per request is a complete read primitive.

## The mechanical exploit

The `username` value is placed inside a single-quoted literal, so the injection
template is: close the quote, `AND` your predicate against the already-matched
`admin` row, then comment out the trailing quote the app appends.

Confirm the oracle first (header, not body):

```
POST /forgot   {"username": "admin' AND (1=1)-- -"}   ->  X-Account-Exists: true
POST /forgot   {"username": "admin' AND (1=2)-- -"}   ->  X-Account-Exists: false
```

Now read one character. `substring(password_hash from N for 1)` is the Nth
character of the admin hash; `ascii(...)` turns it into a code point so the
comparison is collation-independent:

```
POST /forgot   {"username": "admin' AND (ascii(substring(password_hash from 1 for 1)) <= 64)-- -"}
```

`true` means "character 1 has code ≤ 64", `false` means "> 64". Binary-search the
code, and you pin down each character in ~7 requests instead of ~65.

## Exploit walkthrough

`tests/exploit.py` (stdlib only) does exactly this:

1. **Sanity-check the oracle** with `1=1` (expect `true`) and `1=2` (expect
   `false`) so a broken target fails loudly instead of silently.
2. **For positions 1..32**, binary-search the character over an ASCII-sorted
   bcrypt charset `"$./0123456789A-Za-z"`. The predicate sent each iteration is
   `ascii(substring(password_hash from <N> for 1)) <= <ord(candidate)>`; a `true`
   header moves the high bound down, `false` moves the low bound up. That is
   ~7 requests/character, ~224 total, a few seconds against localhost.
3. **Assemble** the 32-character prefix and `POST /solve {"prefix": "..."}`.
   `/solve` compares it to `admin.password_hash[:32]` and returns
   `{"flag": "FLAG{...}"}` on a match.
4. **Verify** the flag equals `FLAG{ hmac_sha256(LAB_USER_SECRET, "v1|<slug>") }`
   and print it on the last line.

A time-based variant (swap the header oracle for `... AND (CASE WHEN (<pred>) THEN
pg_sleep(1) ELSE 0 END)::text = ''`) proves the same read primitive when no
observable header exists — a good exercise, but slower.

## Fix

Bind the input as a parameter and delete the leaky header:

```python
row = await pool.fetchrow("SELECT 1 FROM users WHERE username = $1", username)
# No X-Account-Exists header; identical response for every request.
return JSONResponse({"message": "If an account exists, an email has been sent."})
```

With a bound parameter the driver ships `username` as a _value_, so
`admin' AND (...)-- -` is compared literally against the column and matches
nothing — the predicate never executes. Removing `X-Account-Exists` closes the
observable-discrepancy channel, and returning the identical response (same body,
status, headers, and timing) for existing and non-existing accounts is what
actually makes the endpoint enumeration-safe. If reset emails must be sent, do the
work asynchronously so response timing does not reintroduce the oracle.
