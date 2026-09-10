# Stored XSS via iframe srcdoc (Bleach allowlist misconfig)

> Track: `xss` · Difficulty: **practitioner** · ~35 min · Free hints.

## Scenario

**NoteWall** is a small notes app. Anyone can post a "rich note", and the server
is careful: it never stores raw HTML. Every note body is run through
[Bleach](https://bleach.readthedocs.io/) — a real, allowlist-based HTML sanitizer
— before it is saved:

```python
bleach.clean(body, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS, strip=True)
```

The allowlist looks sensible — `p`, `b`, `em`, `a`, `ul`, `code`, … — but it has
one extra entry a well-meaning developer added "so notes can embed a small
rendered preview":

```python
ALLOWED_TAGS  = [..., "iframe"]
ALLOWED_ATTRS = { ..., "iframe": ["srcdoc", "width", "height"] }
```

That single line is the whole lesson. An allowlist vets tag and attribute
**names**. It has no idea that the _value_ of `srcdoc` is itself a complete HTML
document — one the browser will parse and run in a separate browsing context.

You are not the victim. The interesting target is the site's **admin**,
represented by a headless-Chromium bot that:

- loads a fixed internal page, **`GET /admin/feed`**, every couple of seconds,
  which renders every stored note as raw HTML, and
- does so **carrying the admin's `session` cookie** — which, through a second
  misconfiguration, is **not** marked `HttpOnly`, so `document.cookie` can read
  it.

You cannot load `/admin/feed` yourself: it is gated to the admin session and
returns `403` for everyone else. You have to plant a note the admin will render.

## Objective

Post a note whose sanitized HTML still runs JavaScript in the admin's browser,
steals its `session` cookie, and sends it to the in-lab collector:

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

## Endpoints

| method + path              | who        | purpose                                              |
| -------------------------- | ---------- | ---------------------------------------------------- |
| `POST /posts`              | public     | store a rich note (JSON `{body}` or form `body`)     |
| `GET  /admin/feed`         | admin only | renders every stored note as raw HTML (403 for you)  |
| `GET  /internal/bot-login` | bot only   | mints the admin `session` cookie (backend + BOT_KEY) |
| `GET  /oob/received`       | public     | proxy to the in-lab collector                        |
| `POST /solve`              | public     | exchange the stolen session for the flag             |
| `GET  /health`             | public     | liveness                                             |

## Getting Started

1. Post a harmless note and read the JSON back — the response echoes the stored,
   **sanitized** HTML. Try `<script>alert(1)</script>` (stripped), then try an
   `<iframe srcdoc="...">` and watch it survive.
2. `document.cookie` is scoped to whoever loads the page. Running a script in
   _your own_ browser gets you nothing — you need the **admin's** browser. What
   page does the bot load, and what does it render there?
3. A script inside `srcdoc` runs in an `about:srcdoc` document. Which origin does
   that document belong to — and therefore whose cookies does it see?

**CWE-79 (Improper Neutralization of Input During Web Page Generation), OWASP
A03:2021 – Injection.** The two independent fixes — remove `iframe`/`srcdoc` from
the allowlist **and** mark the session cookie `HttpOnly` — are discussed in
`SOLUTION.md`.

## Stack note

The published catalog entry for this lesson is re-platformed onto **Flask +
Bleach** (per the project's Hybrid re-platform policy), matching the other native
XSS labs in this track. The vulnerability — an HTML-sanitizer allowlist that
permits `<iframe srcdoc>` — is framework-independent; Bleach is the exact library
whose allowlist model the lesson turns on.
