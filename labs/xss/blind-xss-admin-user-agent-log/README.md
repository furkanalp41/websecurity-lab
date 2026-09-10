# Blind XSS via User-Agent in an Admin Log Panel

> Track: `xss` · Difficulty: **practitioner** · ~35 min · Free hints.

## Scenario

**OpsConsole** is an internal operations status site. Every public request is
logged: the site records the raw `User-Agent` header of each visitor into an
in-memory access log. Staff review recent traffic on an admin-only panel:

```
GET /admin/logs        (staff session required — 403 otherwise)
```

That panel renders each stored User-Agent into a table cell through a Jinja
environment with **autoescape switched off** ("so the raw UA string shows
verbatim"). Whatever markup arrived in a `User-Agent` header becomes live HTML
the moment an admin views the log — a stored, **blind** XSS.

It is _blind_ because the public site never echoes your User-Agent back to you:
`GET /` returns the same status page no matter what header you send. You get **no
feedback** that the payload landed. It lies dormant until the privileged admin
opens the log.

The admin here is a headless-Chromium bot that:

- loads `GET /admin/logs` every couple of seconds, and
- does so **carrying the admin `session` cookie** it was issued at login.

## Objective

There is no juicy cookie to read this time — the `session` cookie is only a
gate. The prize is the console's **API key**, served on another admin-only route:

```
GET /admin/apikey      (staff session required — returns the 32-hex key)
```

You cannot request it yourself (403). But JavaScript running **in the admin's
browser** can: a same-origin `fetch('/admin/apikey')` rides the admin's cookie
automatically. So make the admin's browser fetch the key and beacon it to the
in-lab collector:

```
http://collector:9000/report?k=<the api key>
```

The collector sits on an internal, **egress-dropped** network — the key can reach
it but never the real internet. Read what it captured through the app's proxy:

```
GET /oob/received
```

then submit the recovered key:

```
POST /solve   {"c":"<32 hex>"}
```

`/solve` returns `FLAG{<64 hex>}` when the value matches the admin key.

## Getting Started

1. There is no search box to poke — the sink is an HTTP **header**. What part of
   every request does a "visitor log" typically record? Send a `GET /` with a
   `User-Agent` you control.
2. You will see nothing come back — that is the point of _blind_ XSS. How do you
   confirm a payload fired when the vulnerable page is one you cannot even load?
   Make the payload phone home.
3. Your code runs in the admin's session. The interesting endpoint is admin-only,
   but a `fetch()` from the admin's own browser is authenticated. Read it, then
   send it somewhere you _can_ read.

**CWE-79 (Improper Neutralization of Input During Web Page Generation), blind
stored variant. OWASP A03:2021 – Injection.** The fix — contextual output
encoding on the log cell (and why an `HttpOnly` cookie would **not** have saved
you here) — is in `SOLUTION.md`.

## Note on the stack

The scenario this lab is drawn from is usually a FastAPI service that pushes
access-log lines into Redis and renders them in a Jinja log viewer. This lab
**re-platforms it to Flask with an in-process log buffer** — the lesson is the
blind-XSS-via-header sink plus the autoescape-disabled render, and the
FastAPI/Redis plumbing is incidental to it. See `SOLUTION.md` for the deviation
note.
