# AngularJS 1.7.2 Client-Side Template Injection (sandbox-less)

> Track: `xss` · Difficulty: **expert** · ~45 min · Free hints.

## Scenario

**Checkout Confirm** is the order-confirmation page of a small shop. It greets
the customer by name, taken from the `?name=` query parameter:

```html
<div ng-app>
  <p>Order confirmed for <b>YOUR-NAME-HERE</b>. Thank you for shopping with us.</p>
</div>
```

The developer did the "right" thing for reflected XSS: the name is **HTML-escaped**
before it is written into the page, so `<script>` comes back as inert
`&lt;script&gt;`. Injecting a tag or an event handler is dead on arrival.

But look at that wrapper: `<div ng-app>`. The page is bootstrapped with
**AngularJS 1.7.2** (`<script src="/vendor/lib.min.js">`). AngularJS **compiles**
everything inside an `ng-app` region and evaluates any `{{ ... }}` interpolation
it finds in the text — and it does so on the **decoded** DOM, after the browser
has already turned your escaped `&quot;`/`&#x27;` back into real quotes. Escaping
HTML does nothing to the `{{ }}` grammar.

Worse: **AngularJS 1.6 removed the expression sandbox**. In 1.5-and-earlier the
`{{ }}` evaluator tried (and repeatedly failed) to block access to `Function`,
`constructor`, `window`, and friends. 1.6+ dropped that pretence entirely, so a
`{{ constructor.constructor("…")() }}` gadget reaches the `Function` constructor
and runs arbitrary JavaScript. This is **client-side template injection (CSTI)**,
and this lab ships the end-of-life 1.7.2 build on purpose — that sandbox-less
version **is** the vulnerability.

You are not the victim. The interesting target is the shop's **admin**, a
headless-Chromium bot that:

- **visits any path you submit** through `POST /report` (the "report this page to
  our staff" feature), every couple of seconds, and
- does so **carrying the admin's `session` cookie** — which, through a second
  misconfiguration, is **not** marked `HttpOnly`, so `document.cookie` can read it.

## Objective

Make the admin bot's AngularJS instance evaluate a `{{ }}` gadget that steals its
`session` cookie and sends it to the in-lab collector:

```
http://collector:9000/report?c=<the admin cookie>
```

The collector sits on an internal, **egress-dropped** network — a stolen cookie
can reach it but never the real internet. Read what it captured through the app's
proxy:

```
GET /oob/received
```

then submit the recovered session value:

```
POST /solve   {"c":"<32 hex>"}
```

`/solve` returns `FLAG{<64 hex>}` when the value matches the session the admin bot
currently holds.

## Getting Started

1. Request `/?name=<b>hi</b>` and view source. Your `<b>` comes back **escaped**
   (`&lt;b&gt;`) — tag injection is blocked. Now request `/?name={{7*7}}` and
   look at the rendered page in a browser: AngularJS prints `49`. The `{{ }}`
   grammar survives escaping.
2. You can't read the admin's cookie from your own browser — you need _their_
   browser to run your code. What feature hands the admin a URL of your choosing?
3. AngularJS 1.6+ has no expression sandbox. A `{{ }}` expression can reach the
   `Function` constructor and run any JS, with `document.cookie` in scope.

**CWE-79 (Improper Neutralization of Input During Web Page Generation).** The real
fix is not "escape harder" — it is to keep untrusted data out of the
Angular-compiled region entirely. See `SOLUTION.md`.

## A note on the stack

The catalog concept for this lesson is a static AngularJS site. This lab is
**re-platformed to Flask** (per the project's Hybrid stack policy) so it fits the
shared XSS-track harness: one Flask app that reflects `?name=`, serves the
vendored framework at `/vendor/lib.min.js`, exposes the `/report` queue and the
backend-gated `/internal/*` endpoints, and drives the same `@websec-lab/xss-verifier`
victim bot and stdlib OOB collector as every other XSS lab. Only the transport
changed; the taught flaw — CSTI in a sandbox-less AngularJS `{{}}` context — is
identical.
