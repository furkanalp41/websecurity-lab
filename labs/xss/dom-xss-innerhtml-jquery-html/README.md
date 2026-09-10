# DOM XSS via jQuery .html() on location.hash

> Track: `xss` · Difficulty: **apprentice** · ~30 min · Free hints.

## Scenario

**Gridly** is a tabbed dashboard. Its client-side router renders the current tab
from the URL fragment, on load and on every `hashchange`:

```js
$('#panel').html(decodeURIComponent(location.hash.slice(1) || 'home'));
```

`.html()` sets `innerHTML`. The fragment is client-side only (never sent to the
server), so this is a **DOM-based** XSS — source `location.hash`, sink jQuery
`.html()`.

The admin bot visits any path you submit to `POST /report` while holding its
`session` cookie, which is **not** `HttpOnly`.

## Objective

Deliver a fragment payload that runs in the admin bot's browser, reads its
`document.cookie`, and beacons the `session` value to the in-lab collector
(`http://collector:9000/report?c=…`). Read it back through `GET /oob/received`
and submit it:

```
POST /solve   {"c":"<32 hex>"}
```

## Getting Started

1. Navigate `/#<b>hi</b>` — your markup is rendered into `#panel`, not shown as
   text. `.html()` parsed it as HTML.
2. `innerHTML` won't run a bare `<script>`. What HTML element runs JavaScript the
   instant it is parsed, without a script tag?
3. Your code runs in the admin's browser with their cookie in scope. Read it and
   send it somewhere you can see.

**CWE-79 (Improper Neutralization of Input During Web Page Generation),
DOM-based variant. OWASP A03:2021 – Injection.** The fix — `.text()` instead of
`.html()`, or sanitise untrusted input before insertion — is in `SOLUTION.md`.

> Note: this lab pins **jQuery 3.7.1** (current), not the catalog's aspirational
> 3.4.1. The taught flaw is the app's own `.html(untrusted)` misuse — identical
> on every jQuery version — and shipping a non-CVE'd jQuery keeps the CI Trivy
> gate honest (no vulnerable component that could hand out an unintended path).
