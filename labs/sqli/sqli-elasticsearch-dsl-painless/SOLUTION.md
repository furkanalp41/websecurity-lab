# Solution — sqli-elasticsearch-dsl-painless

> **OWASP:** A03:2021-Injection · **CWE:** CWE-943 (Improper Neutralisation of
> Special Elements in Data Query Logic — the NoSQL/DSL sibling of CWE-89) ·
> **CVE analog:** Snyk 2020 ES DSL injection research and the spirit of
> CVE-2015-1427 (Groovy sandbox escape) updated for Painless — abstracted, no
> vendor code reproduced.

## What tipped you off

`POST /search` with `{"query":{"match_all":{}}}` returns log rows — the body is
forwarded into ES `_search` verbatim. That is not "safe because
match_all"; that is a full DSL sink. And the `.credentials` index is right there
in the same cluster, gated only by the app choosing to search `logs`.

## The class of bug

DSL injection (CWE-943). `src/server.mjs`:

```js
await es.search({ index: 'logs', ...body });
```

JavaScript object-spread has right-side precedence: **anything the caller puts
in `body.index` overwrites the intended `logs` scope**. The app assumed "spread
merges", but spread is really "later wins". So `{index: ".credentials", ...}`
sails through and searches the credentials index instead.

## Getting the exploit

```
POST /search    {"index": ".credentials", "query": {"match_all": {}}}
```

Response:

```
{"ok":true,"took":3,"hits":{"total":{"value":1,"relation":"eq"},
  "hits":[{"_index":".credentials","_id":"flag",
           "_source":{"secret_key":"<32 hex>","note":"..."}}]}}
```

Then:

```
POST /solve   {"secret_key":"<32 hex>"}
```

`tests/exploit.py` does exactly this (stdlib only) and finishes in ~100 ms.

## About Painless (and the catalog's aspirational framing)

The catalog title mentions "script_fields Painless". In Elasticsearch 8.x,
Painless runs in a strict allow-list sandbox — no `java.io.File`, no
`Runtime.exec`, no client access, no cross-index read. Painless in a
`script_fields` block can compute a value from the CURRENT document's `_source`
and `doc[]`, and it can echo `params.*` values the request supplied. So a
Painless snippet on a `logs` query cannot read `.credentials` by itself. The
sandbox is by design.

That is why this lab's intended primitive is DSL-body injection at the _index
scope_ rather than a Painless capability. A Painless `script_fields` block is
still an ALTERNATIVE way to shape response fields (see vectors below), but the
scope-widening is the load-bearing step.

## Why it isn't RCE

Painless refuses `new java.io.File("/etc/passwd")` and `Runtime.getRuntime()`
at compile time (verified — you get `compile error`). The Elasticsearch container
is also on an `internal: true` no-egress network, so any exfil would be blind.
This lab is `risk: low`; the taught primitive is data-scope injection, not
command execution.

## Alternative payload vectors

1. **URL-index override via body** (used by the exploit) —
   `{"index":".credentials","query":{"match_all":{}}}`.
2. **Wildcard scope** — `{"index":".*","query":{"match_all":{}}}` returns docs
   from every dot-prefixed index, useful when you don't know the exact target.
3. **Painless `script_fields` for field extraction on the widened result** —
   once your query is against `.credentials`, add
   `"script_fields":{"leak":{"script":{"lang":"painless","source":"params[\"_source\"].secret_key"}}}`
   to force the field even if the app had tried to filter `_source`. (It doesn't
   here, but this is a natural fallback.)

## Heavy-tier note

Elasticsearch is a JVM engine with a 1.2 GB image and >512 MB RAM demand — well
past the standard PR-gate budget (300 MB, 512m). This lab declares
`resource_tier: heavy` in `meta.json` and runs in the nightly
`heavy-nightly` matrix instead. Every other guarantee is identical: non-root,
read-only rootfs, `cap_drop:ALL`, `no-new-privileges`, digest-pinned base,
loopback-only publishing, `internal: true` backend for the engine. The tier
flexes the numeric budget only.

## ES-specific hardening deviation

Elasticsearch needs `/usr/share/elasticsearch/config/` writable at startup for
its keystore, but the container's root filesystem is read-only. The compose
entrypoint copies the shipped config to a writable tmpfs (`/tmp/es-config`) and
sets `ES_PATH_CONF` to it — keeping the rootfs `read_only: true` (posture
requirement) while giving ES the writable config it needs. `/tmp` itself is
mounted with `exec` because JNA loads native libraries via `mmap+exec`.

## Fix

- **Do not spread caller-supplied bodies over search options.** Either accept
  only the fields you want (`{query: body.query}`) or wrap the body in a nested
  key (`body.query, body.aggs`) so `index` cannot ride along.
- **Validate the index scope server-side** with an allow-list of the indices
  the endpoint should ever see.
- **Isolate sensitive indices in a separate cluster or role** so an
  application role cannot search them at all, regardless of DSL cleverness.
