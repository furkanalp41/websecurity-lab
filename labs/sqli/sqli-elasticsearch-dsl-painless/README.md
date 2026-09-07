# Elasticsearch DSL Injection to Cross-Index Read

> Track: `sqli` · Difficulty: **expert** · ~50 min · Free hints.
>
> **Heavy-tier lab.** Elasticsearch 8.15 needs ~1.2 GB image and >512 MB RAM, so
> this lab runs in the project's nightly **heavy-nightly** CI matrix, not on
> every PR. Locally: launch with `docker compose up` as usual (all posture rules
> are identical to the standard tier — only the resource budget is larger).

## Scenario

`Acme LogSearch` is an internal log-search UI. Its `POST /search` endpoint takes
a JSON body and forwards it into Elasticsearch's `_search` DSL. The developer
sensibly scoped the URL to `index: "logs"` — but then reached for JavaScript's
object-spread to merge the caller's body over the request options:

```js
await es.search({ index: 'logs', ...body });
```

Object-spread has right-side precedence: a body-level `index` key overwrites the
`"logs"` scope. Whoever sends the body picks the index. And there is another
index in the cluster — `.credentials` — that stores every service's access
tokens, gated only by "the app never touches it".

## Objective

Read `secret_key` from `.credentials/flag`, then submit it:

```
POST /solve   {"secret_key":"<value>"}
```

`/solve` compares your submission (constant-time) against the stored value and
returns `FLAG{<64 hex>}` on a match. The `secret_key` is unique to your
container (derived from `LAB_USER_SECRET`); a value from another instance will
not validate.

## Getting Started

1. Send `POST /search` with `{"query":{"match_all":{}}}`. You get log entries
   — proof the app forwards your body into ES `_search` verbatim.
2. What ES features does that body accept? What clause could redirect the search
   to a _different_ index?
3. What Elasticsearch DSL key is the app itself passing into `es.search(...)`
   next to your body? What happens if you put the same key in your body too?

## Note on Painless

The catalog name hints at "Painless script_fields". Painless 8.x runs in a
strict sandbox — no `java.io`, no `Runtime`, no cross-index reads from within a
script. So the DSL-injection primitive (cross-index via body-level `index`) is
the intended path; a Painless snippet is offered as a companion way to shape
what a script_fields block returns, but the sandbox doesn't grant network/file
access. See SOLUTION.

**CVE analog family.** Untrusted JSON forwarded into a search DSL that widens
the effective scope is the shape of the 2020 Snyk ES-DSL-injection research and
the spirit of **CVE-2015-1427** (Elasticsearch Groovy sandbox escape, updated
for the 8.x Painless era). **CWE-943 → CWE-89 sibling.** No vendor code
reproduced.
