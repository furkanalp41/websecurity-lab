# Reflected XSS in a JavaScript String Literal

> Track: `xss` · Difficulty: **apprentice** · ~30 min · Free hints.

## Scenario

**QuickCart** is a checkout page. When you apply a promo code it echoes the code
back — but not into the page body. It reflects it into an **inline `<script>`**,
concatenated into a single-quoted JavaScript string:

```js
var promo = '<YOUR-PROMO-HERE>';
document.getElementById('promo').innerText = promo;
```

The server does "sanitise" the value first — it strips every `<` and `>`. That
looks reasonable, and it would block the obvious `<script>` payload in an HTML
body. But here your input is already **inside a script**, in a string literal.
Angle brackets are irrelevant in that context; what ends a JavaScript string is a
**single quote**, and quotes (and backslashes) are passed through untouched.

This is the taught flaw: **an HTML-only filter is the wrong encoder for a
JavaScript-string context.** Neutralising `<` and `>` does nothing when the
injection point is a JS string.

## Objective

You are not the victim. The interesting target is the shop's **admin**,
represented by a headless-Chromium bot that:

- **visits any path you submit** through `POST /report` (the "report a checkout
  link to staff" feature), every couple of seconds, and
- does so **carrying the admin's `session` cookie**.

There is an identity endpoint, `GET /api/whoami`. To an ordinary request it
returns `{"user":"guest"}`. To a request that already carries the admin session
cookie it returns the admin token:

```json
{ "user": "admin", "token": "<32 hex>" }
```

Make the admin bot's browser break out of the JS string, call `/api/whoami` with
its own cookie (a same-origin credentialed `fetch`), and beacon the JSON to the
in-lab collector:

```
http://collector:9000/report?w=<the whoami JSON>
```

The collector sits on an internal, **egress-dropped** network — an exfiltrated
token can reach it but never the real internet. Read what it captured through the
app's proxy:

```
GET /oob/received
```

then submit the recovered token:

```
POST /solve   {"c":"<32 hex>"}
```

`/solve` returns `FLAG{<64 hex>}` when the token matches the session the admin
bot currently holds.

## Getting Started

1. Confirm the sink and the context. Request `/?promo=abc` and **view source** —
   your value sits between two single quotes inside a `<script>`. Now try
   `/?promo=a'b` — the quote comes back **unescaped**, so you can end the string.
2. Confirm the filter is HTML-only. `/?promo=<i>` comes back with the angle
   brackets **gone** — proof the "sanitiser" is an HTML strip that does nothing
   to a quote.
3. You can't read the admin's cookie or token from your own browser — you need
   _their_ browser to run your code. What feature hands the admin a URL of your
   choosing? And once your JS runs in their session, what can a same-origin
   `fetch('/api/whoami', {credentials:'include'})` see that you cannot?

**CWE-79 (Improper Neutralization of Input During Web Page Generation).** The
real fix — context-aware output encoding — and why the angle-bracket blacklist
was never enough are discussed in `SOLUTION.md`.
