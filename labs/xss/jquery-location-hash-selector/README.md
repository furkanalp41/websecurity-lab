# DOM XSS via jQuery `$(location.hash)` Selector-to-Constructor

> Track: `xss` · Difficulty: **practitioner** · ~35 min · Free hints.

## Scenario

**HelpDesk** is a legacy help-centre page. To make section deep-links work, it
"scrolls to a section" by handing the URL fragment straight to jQuery on load:

```js
var t = decodeURIComponent(location.hash.slice(1));
if (t) {
  $(t);
}
```

The author's mental model was `$("#billing")` — _select_ the element with that
id. But jQuery's `$()` is overloaded. When the string you give it **looks like
HTML** (it starts with `<...>`), jQuery does not select anything — it
**constructs** the elements the string describes. So a fragment like:

```
#<img src=x onerror=ALERT>
```

builds a brand-new `<img>` element. Its `src=x` is a broken URL, so the browser
fires the element's `onerror` handler — your JavaScript, running in the visitor's
page, with no injection into the server's HTML at all.

This page ships the catalog-pinned **jQuery 3.4.1**. Versions **< 3.5** are
looser still about what counts as "HTML to construct" (leading whitespace and
more), which is exactly why the selector-vs-HTML boundary is so easy to cross
here — and why this quirk is the lesson.

You are not the victim, though. The interesting target is the site's **admin**,
represented by a headless-Chromium bot that:

- **visits any path you submit** through `POST /report` — including its
  `#fragment`, which the browser keeps client-side and feeds to `location.hash`
  — every couple of seconds, and
- does so **carrying the admin's `session` cookie**, which (a second
  misconfiguration) is **not** marked `HttpOnly`, so `document.cookie` can read
  it.

## Objective

Make the admin bot's browser construct an element whose handler steals its
`session` cookie and beacons it to the in-lab collector:

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

`/solve` returns `FLAG{<64 hex>}` when the value matches the session the admin
bot currently holds.

## Getting Started

1. Confirm the sink: view source at `/`. The inline script passes
   `location.hash.slice(1)` directly to `$()`. What does `$("<b>hi</b>")` do that
   `$("#hi")` does not?
2. You can't read the admin's cookie from your own browser — you need _their_
   browser to run your code. What feature hands the admin a URL (with a fragment)
   of your choosing?
3. A bare `<script>` inserted this way won't run, but an element with an event
   handler that fires **on load** will. Which tag reliably fires without a click?

**CWE-79 (Improper Neutralization of Input During Web Page Generation).** The
real fix — never pass untrusted input to `$()` — plus jQuery ≥ 3.5 and an
`HttpOnly` cookie are discussed in `SOLUTION.md`.
