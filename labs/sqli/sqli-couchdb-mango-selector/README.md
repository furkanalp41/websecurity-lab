# CouchDB Mango Selector Injection

> Track: `sqli` · Difficulty: **practitioner** · ~30 min · Free hints.

## Scenario

A team ships a small "document vault" API on top of Apache CouchDB. Guests get a
private space: `POST /find` with a JSON body `{"filter": {...}}` searches _your_
documents and only yours. Behind the scenes the service queries CouchDB's Mango
`_find` endpoint on a database called `restricted`, and — to keep one guest from
reading another's files — it always applies a server-side access constraint,
`{"owner": "guest"}`, before running your query.

The developers thought of the `filter` as a way for you to _narrow_ your own
results: search by title, by date, whatever. What they did not think carefully
about is how your `filter` gets combined with their constraint. They merge the two
dictionaries and let your keys take precedence. In a document database, the query
_is_ a JSON object — so handing the client control over keys in that object hands
them control over the access rule itself.

Somewhere in `restricted` there is a document with `_id` `flag_holder`, owned by
`"system"`, that a guest is never supposed to see. Its `secret` field is the key
to the flag.

## Objective

Reach the `flag_holder` document even though your account is scoped to
`owner == "guest"`, read its `secret` field, and redeem it:

1. Send `POST /find` bodies and watch the `selector` the API echoes back — that
   shows you exactly how your `filter` and the server constraint combine.
2. Find an input that makes the effective selector match documents you do not own.
3. Pull `flag_holder.secret` out of the response and submit it to
   `GET /solve?secret=<value>`.

The service returns `FLAG{<64 hex characters>}`, unique to your instance — a flag
copied from another machine will never validate on yours.

## Getting Started

- Launch the lab and note the instance URL. All traffic is JSON over HTTP.
- Baseline it: `POST /find` with `{"filter": {}}`. You will get back your own
  guest documents and, helpfully, the `selector` that was actually run. Keep an
  eye on that echoed selector as you experiment — it is your window into the merge.
- CouchDB's Mango query language uses operators like `$eq`, `$gt`, `$lt`, `$or`,
  `$and`, and `$regex`. One of them, applied to the right key, quietly turns the
  owner constraint into a no-op. Reveal the hints in order if you get stuck — they
  are free.

**CVE analog family.** NoSQL / query-language injection (**CWE-943**, OWASP
**A03:2021 – Injection**) shows up whenever untrusted input is spliced into a
structured query — a MongoDB filter, a CouchDB Mango selector, an Elasticsearch
query DSL — instead of being treated as data. See the 2023 Sonar research on
CouchDB selector abuse and the broad family of "user-controlled query object"
access-control bypasses. No vendor code is reproduced here.
