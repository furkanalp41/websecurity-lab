# Reflected XSS in Search Results

> Track: `xss` · Difficulty: **apprentice** · ~25 min · Free hints.

## Scenario

**Book Nook** is a vintage bookshop. Its search page echoes the `?q=` parameter
straight into the results heading:

```html
<h2>Results for <em>YOUR-QUERY-HERE</em></h2>
```

The template that renders this was switched from Jinja2's default
(autoescape **on**) to autoescape **off** "so rich snippets render" — the
canonical reflected-XSS footgun. Whatever you put in `q` becomes live HTML.

You are not the victim, though. The interesting target is the shop's **admin**,
represented by a headless-Chromium bot that:

- **visits any path you submit** through `POST /report` (the "report a page to
  staff" feature), every couple of seconds, and
- does so **carrying the admin's `session` cookie** — which, through a second
  misconfiguration, is **not** marked `HttpOnly`, so `document.cookie` can read
  it.

## Objective

Make the admin bot's browser run a payload that steals its `session` cookie and
sends it to the in-lab collector:

```
http://collector:9000/report?c=<the admin cookie>
```

The collector sits on an internal, **egress-dropped** network — a stolen cookie
can reach it but never the real internet. Read what it captured through the
app's proxy:

```
GET /oob/received
```

then submit the recovered session value:

```
POST /solve   {"c":"<32 hex>"}
```

`/solve` returns `FLAG{<64 hex>}` when the value matches the session the admin
bot currently holds.

## Getting Started

1. Confirm the sink: request `/?q=<b>hi</b>` and view source — your tags are
   reflected **unescaped**.
2. You can't read the admin's cookie from your own browser — you need _their_
   browser to run your code. What feature hands the admin a URL of your
   choosing?
3. A payload that runs in the admin's browser has `document.cookie` in scope.
   How do you get that value out to a host you can read?

**CWE-79 (Improper Neutralization of Input During Web Page Generation).** The
two independent fixes — contextual output encoding **and** an `HttpOnly` session
cookie — are discussed in `SOLUTION.md`.
