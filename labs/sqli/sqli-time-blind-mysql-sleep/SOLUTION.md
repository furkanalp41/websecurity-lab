# Solution — sqli-time-blind-mysql-sleep

<!-- Instructor/authoring reference. Students should try the hints first. -->

> **Deviations from `data/catalog.json` (all deliberate).**
>
> 1. **Stack.** The catalogue sketches a Node.js/Fastify + `mysql2` app behind an
>    nginx 1.27 reverse proxy. This lab uses the platform's established Python
>    stack — Flask + gunicorn + PyMySQL — and omits the proxy. A reverse proxy is
>    a transport detail that forwards the same `ref` parameter to the same
>    handler, so it changes nothing about the vulnerability, the payload, or the
>    fix, while keeping the image small and the hardening posture identical to the
>    other Python SQLi labs (app + a hardened non-root MySQL).
> 2. **Token size.** The catalogue specifies a **40-character** token exfiltrated
>    at "~1 second per bit". A serial time-based read of 40 chars runs for several
>    minutes — impossible under the platform's **<60s exploit** gate. This
>    instance stores a **16-character lowercase-hex** token
>    (`secrets.token_hex(8)`, 64 bits) and ships a **threaded** solver. The
>    injection payload and the binary-search oracle are byte-for-byte the same as
>    they would be for a 40-char token; only the character count (and therefore
>    the wall-clock) differs.
> 3. **/solve flag delivery.** The catalogue's `flag_hint` mentions `/solve`
>    exec'ing a `give_flag.sh` helper that reads `/flag.txt`. This lab instead
>    reads the flag file directly in Python (`open($FLAG_PATH)`), the safer,
>    established pattern across the platform — no shell process is spawned.

## What tipped you off

`/beacon?ref=...` always returns `204 No Content`: no body, no error, no header
that varies with your input. Every classic SQLi channel is dead — there is
nothing to read a result out of. That _absence_ is itself the clue. When a write
endpoint gives you no output but you suspect your input reaches SQL, the move is
to stop looking for data in the response and start looking at the **clock**: make
the query decide whether to pause, and time it.

A quick confirmation: fire two requests, one whose injected condition is always
true and one always false, and compare their latencies. If "true" is reliably
~0.6s slower, you have a working time oracle.

## The class of bug

SQL injection (**CWE-89**, OWASP **A03:2021 – Injection**) in a **single-quoted
string context inside an `INSERT ... VALUES` statement**, exploited as a
**time-based blind** read. Because the statement is a write with no visible
result set, there is no column to `UNION` into and no row echoed back — the only
exfiltration channel is an injected conditional `SLEEP()`.

## Vulnerability

`src/app.py`, `/beacon`:

```python
sql = (
    "INSERT INTO hits (referrer, ua) VALUES ('"
    + ref + "', '" + ua + "')"
)
```

`ref` (and the `User-Agent`) come straight from the request with no quoting,
escaping, parameterization, or allowlisting. The handler then swallows any error
and always returns `204`, so the database's behaviour is invisible **except** for
how long it takes.

## Why the developer wrote it this way

A fire-and-forget analytics beacon feels like the _safest_ endpoint in the app:
it returns nothing, it renders nothing, it "just logs a row". Concatenating the
referrer into an `INSERT` reads like a sentence and works for every value the
developer tested. Because there is no output, the usual injection alarm bells
(garbled pages, SQL errors) never ring — so the bug hides in plain sight. Silence
is mistaken for safety.

## Why it exists

The database cannot tell your _data_ from your _code_ once both arrive as one
concatenated string. A bound parameter would ship `ref` as a value that can only
ever be stored in the `referrer` column; concatenation instead lets a `'` end the
literal so everything after it is parsed as SQL. The `INSERT` context removes the
easy channels — no visible SELECT, no UNION — but it does **not** remove the
attacker's ability to make the server _spend time_, and time is a channel too.

## The mechanical exploit

The statement you are injecting into is:

```sql
INSERT INTO hits (referrer, ua) VALUES ('<ref>', '<ua>')
```

You control `<ref>`. The goal is to turn the second value (`ua`) into a scalar
subquery that conditionally sleeps:

```
ref = x',(SELECT IF((<condition>),SLEEP(0.6),0)))-- -
```

Substituted in, the server runs:

```sql
INSERT INTO hits (referrer, ua)
VALUES ('x',(SELECT IF((<condition>),SLEEP(0.6),0)))-- -', '<ua>')
```

Parenthesis-by-parenthesis:

- `'x'` — closes the `referrer` literal cleanly.
- `,(SELECT IF((<condition>),SLEEP(0.6),0))` — the `ua` value becomes a scalar
  subquery. `IF(cond, SLEEP(0.6), 0)` sleeps ~0.6s when `cond` is true, else
  returns `0` instantly.
- the final `)` — closes the `VALUES (...)` row (there are three closing parens:
  one for `IF`, one for the `SELECT` subquery, one for the row).
- `-- -` — a MySQL line comment (two dashes **and a space**) that neutralises the
  trailing `', '<ua>')` the code appends.

### Building the oracle

`<condition>` is any yes/no question. The one we need compares one character of
the token against a candidate ASCII code:

```
ASCII(SUBSTRING((SELECT beacon_token FROM secrets LIMIT 1), <pos>, 1)) >= <mid>
```

- **True** → the request sleeps ~0.6s.
- **False** → the request returns immediately.

Treat any response slower than **0.4s** as "true".

### Extracting the token

The token is 16 lowercase hex chars, charset `0123456789abcdef` (already sorted
ascending by ASCII code). For each position 1..16, **binary-search** the
character: ask `ASCII(...) >= ord(c)` for the midpoint `c` of the remaining
range, keep the half the answer points to, and converge in ~4 questions per
character. That is ~64 oracle requests total.

### Parallelising safely (and why the pool size matters)

`tests/exploit.py` runs the 16 per-position searches in a thread pool, which
cuts the wall-clock to ~10–15s. The pool is capped at **4 workers on purpose** —
the same number as the server's `gunicorn --workers 4`:

> If the client sent _more_ concurrent requests than the server can execute at
> once, a fast (FALSE) request would sit in the accept queue behind another
> request that is mid-`SLEEP`, and the client would clock that queue wait as
> latency — a **timing false positive**. Matching the client pool to the worker
> count guarantees every request lands on its own free worker, so FALSE stays
> genuinely fast and the 0.4s threshold cleanly separates the two cases. As a
> second layer, any _slow_ reading is re-confirmed with a second measurement and
> the minimum is taken: a genuine SLEEP is slow every time, whereas a FALSE that
> briefly queued behind one (or a one-off network hiccup) washes out.

### Winning

Once all 16 characters are recovered, submit the token:

```
POST /solve   {"token":"<16-hex token>"}   ->   200  FLAG{...}
```

`tests/exploit.py` performs exactly this with the standard library only, extracts
the token dynamically (it is random per container), and asserts the recovered
flag equals the HMAC-derived expected value. It finishes in well under 60s.

## Fix

Never concatenate input into SQL — bind it. With a placeholder, `ref` can only
ever be stored as data in the `referrer` column; the `'`, the subquery, and the
`SLEEP()` never reach the parser as code:

```python
sql = "INSERT INTO hits (referrer, ua) VALUES (%s, %s)"
with conn.cursor() as cur:
    cur.execute(sql, (ref, ua))   # ref/ua are values, never code
```

Bind the `User-Agent` the same way — headers are attacker-controlled input too.
Parameterisation closes the timing channel completely: there is no injected
`SLEEP()` to run, so no request can be made to pause. (Swallowing errors and
returning `204` was never the problem and is fine to keep; the vulnerability was
the string-built statement, not the quiet response.)
