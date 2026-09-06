# Solution — sqli-rails-active-record-hash

## What tipped you off

`/reports?sort=id asc` and `?sort=id desc` change which record is returned first,
so `sort` reaches `ORDER BY`. Column names like `title` work too. A bare
expression does something a column reference should not — the app either reorders
the rows or returns `{"error":"query failed"}`. That black-box "reorder vs error"
is enough to build a boolean oracle.

## The class of bug

SQL injection (CWE-89, OWASP A03:2021) via **ActiveRecord `order()` injection**.
`filter` is safe (strong-parameters hash condition, bound by the adapter). The
hole is `sort`:

`app/controllers/reports_controller.rb`

```ruby
def sort_clause
  raw = params[:sort].presence || "id asc"
  Arel.sql(raw)          # <-- disables Rails' raw-SQL ORDER BY protection
end
# ...
Report.where(filter_params).order(sort_clause).limit(50)
```

Rails 6.1+ would raise `UnknownAttributeReference` for a raw `ORDER BY` string;
`Arel.sql` is the "trust me" escape hatch that turns that protection off. With
attacker-controlled input inside it, the `ORDER BY` clause is injectable.

## Why the developer wrote it this way

You cannot bind a column identifier or a sort direction as a normal query
parameter — placeholders bind _values_, not SQL fragments — so "flexible sorting"
tempts developers into raw SQL. `Arel.sql(params[:sort])` makes the feature work
for `?sort=title desc` and passes every test where `sort` is a real column. It
also quietly re-enables injection.

## Building the oracle

`ORDER BY` accepts an arbitrary expression, including a `CASE` and a correlated
subquery. Order by `id` when a condition holds and by `-id` when it does not, and
the **first returned row flips** between the lowest-id and highest-id report:

```
sort = (CASE WHEN (<cond>) THEN reports.id ELSE -reports.id END) asc
```

- `<cond>` TRUE → `ORDER BY id ASC` → first row = lowest id.
- `<cond>` FALSE → `ORDER BY -id ASC` → first row = highest id.

So `first_row.id == min_id` is a clean boolean read of `<cond>`, with no error
channel and no data ever printed.

## The mechanical exploit / Exploit walkthrough

Learn the min/max first-row id (`sort=id asc` / `sort=id desc`), then binary-search
each character of `secrets.master_key` on its ASCII code via a correlated subquery:

```
cond = (SELECT ascii(substr(master_key,POS,1)) FROM secrets ORDER BY id LIMIT 1) >= VAL
GET /reports?sort=(CASE WHEN (cond) THEN reports.id ELSE -reports.id END) asc
```

`master_key` is 16 lowercase hex chars, so ~6 requests per character (binary search
over ASCII `'0'..'f'`) recovers the whole key in ~100 requests — a couple of seconds,
well under the 60s budget. Then:

```
POST /solve   {"key":"<16 hex chars>"}   ->   {"flag":"FLAG{...}"}
```

`tests/exploit.py` performs exactly this with the standard library only and asserts
the recovered flag equals the HMAC-derived expected value.

## Lab-vs-production deviation

`secrets.master_key` is a 16-char token (`SecureRandom.hex(8)`) rather than a long
credential, purely so the ordering-oracle extraction (one boolean per request)
finishes inside the platform's 60-second exploit budget. The technique is identical
for any length. `/solve` reads the flag file directly in Ruby (`File.read`); it does
**not** shell out to a `give-flag.sh`, which would hand an attacker a command
primitive — reading the file in-process is the safer established pattern here.

## Fix

Never pass untrusted input to `Arel.sql` / `order()`. Map the request to a fixed
allowlist of columns and directions:

```ruby
SORTABLE = { "id" => "id", "title" => "title", "status" => "status" }.freeze
col = SORTABLE.fetch(params[:sort_col], "id")
dir = params[:sort_dir] == "desc" ? "desc" : "asc"
Report.where(filter_params).order(col => dir).limit(50)  # identifiers from a trusted set
```

Because `col`/`dir` can only be server-chosen values, attacker input can no longer
reach the query as code.
