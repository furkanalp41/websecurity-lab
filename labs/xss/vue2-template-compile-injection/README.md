# Vue 2 Runtime Template Compilation Injection (Vue.compile)

> Track: `xss` · Difficulty: **expert** · ~40 min · Free hints.

## Scenario

**WidgetHub** lets customers submit a custom "widget template". Staff preview the
latest one on an admin dashboard, which compiles it **at runtime**:

```js
var tpl = document.getElementById('w').textContent; // hidden div; textContent decodes the entities
var compiled = Vue.compile(tpl); // Vue 2.7 runtime compiler
new Vue({ el: '#app', render: compiled.render, staticRenderFns: compiled.staticRenderFns });
```

`Vue.compile()` turns your template into a render function. Its `{{ … }}`
expressions run in the component's scope — and Vue 2 compiles expressions to
`with(this){ … }`, so `constructor.constructor` reaches the JavaScript `Function`
constructor. Compiling an untrusted template is **client-side template
injection** (CSTI): full script execution, no `<script>` needed.

The template is embedded in a hidden `<div>` HTML-escaped, so you cannot break out
at the HTML level — but `textContent` decodes the entities before `Vue.compile`
sees them, so your raw template reaches the compiler.

## Objective

The admin bot loads `GET /admin/dashboard` (admin-only) every couple of seconds
with its `session` cookie. Deliver a widget template that runs in the admin's
browser, fetches the admin-only `GET /me` (which returns the admin token only to
the admin cookie), and beacons it to `http://collector:9000/report`. Read it back
via `GET /oob/received`, then:

```
POST /solve   {"c":"<32 hex>"}
```

You cannot read `/me` or `/admin/dashboard` yourself (both are 403 without the
cookie) — the CSTI must fire in the bot.

## Getting Started

1. Post a benign widget (`<span>hi {{ 1+1 }}</span>`) and note the dashboard is
   admin-only. Your `{{ 1+1 }}` proves expressions evaluate.
2. From a Vue expression, how do you reach arbitrary JavaScript? (Think about
   `constructor`.)
3. Your code runs as the admin. What can you now `fetch` that you couldn't
   before?

**CWE-79 (Improper Neutralization of Input During Web Page Generation) via
client-side template injection. OWASP A03:2021 – Injection.** The fix — never
compile user-supplied templates; use the runtime-only build and render user data
as text — is in `SOLUTION.md`.
