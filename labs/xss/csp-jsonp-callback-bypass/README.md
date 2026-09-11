# CSP Bypass via JSONP Endpoint in Allowlist

> Track: `xss` · Difficulty: **expert** · ~45 min · Free hints.

## Scenario

**Vaultboard** is a notes app. Its search page reflects the `?q=` term into the
page **with no HTML escaping** — so you can inject arbitrary markup. The developers
know this and decided to contain it with a **Content-Security-Policy** instead of
encoding the output:

```
Content-Security-Policy: default-src 'self';
  script-src 'self' http://accounts-trusted:8080;
  style-src 'self' 'unsafe-inline'; img-src * data:; connect-src *;
  base-uri 'none'; object-src 'none'
```

Try the obvious payloads and the CSP holds: because `script-src` has **no
`'unsafe-inline'`**, a reflected `<script>…</script>` never runs, and a reflected
`<img src=x onerror=…>` never fires — inline script and inline event handlers are
both forbidden. The HTML injection is real, but it looks inert.

The bot that reviews reported pages is a headless-Chromium admin that logs in
(`/internal/bot-login`) and visits any path you queue through `POST /report`,
carrying its **non-HttpOnly** `session` cookie.

## Objective

Look again at `script-src`. It allowlists a second origin —
`http://accounts-trusted:8080`, the "accounts" widget host — so Vaultboard can
embed its script. That host exposes a **JSONP** endpoint:

```
GET http://accounts-trusted:8080/api/jsonp?callback=<name>
        →  <name>({"authenticated": false, ...})      (Content-Type: application/javascript)
```

It echoes the `callback` name **verbatim** into an executable position. A
`<script src>` pointing at that host is **allowed by the CSP** (the host is on the
allowlist) — and the JSONP endpoint turns your `callback` value into code that
runs in Vaultboard's origin. Use it to steal the admin's cookie and beacon it to
the in-lab collector:

```
http://collector:9000/report?c=<document.cookie>
```

The collector is on an internal, **egress-dropped** network. Read what it
captured via `GET /oob/received`, then submit the session:

```
POST /solve   {"c":"<32 hex>"}
```

`/solve` returns `FLAG{<64 hex>}` when it matches the admin session.

## Getting Started

1. Confirm the CSP first. Inject `<script>alert(1)</script>` and an
   `<img src=x onerror=alert(1)>` — nothing happens. Read the CSP response header:
   what does `script-src` permit, and what does it forbid?
2. `script-src` lists a host besides `'self'`. Visit that host directly. Endpoints
   that wrap JSON in a caller-named function (`callback=foo` → `foo({...})`) are
   **script gadgets** — they emit whatever you name as executable JavaScript.
3. You cannot run inline script, but you **can** load a script from an allowlisted
   host. Point a `<script src>` at the JSONP endpoint and make the callback your
   payload. It executes in Vaultboard's origin, where the admin cookie lives.

**CWE-79 / CWE-829 (Inclusion of Functionality from an Untrusted Control Sphere).
OWASP A03:2021 – Injection.** The fix — audit the `script-src` allowlist (a host
with a JSONP/AngularJS/user-content gadget is as good as `'unsafe-inline'`), prefer
nonces/hashes — is in `SOLUTION.md`.

## Note on the stack

The catalogued scenario is a Flask target plus a Node/Express mock trusted host
behind nginx. This lab keeps the **Flask** target and implements the mock
allowlisted host as a tiny **stdlib JSONP service** (the JSONP gadget is
framework-independent — it is just "reflect the callback name into executable
position"). See `SOLUTION.md` for the deviation note.
