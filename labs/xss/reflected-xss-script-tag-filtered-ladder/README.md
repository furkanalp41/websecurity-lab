# Reflected XSS — Filter Bypass Ladder (blocked `<script>` tags)

> Track: `xss` · Difficulty: **practitioner** · ~30 min · Free hints.

## Scenario

**HelpDesk Lite** is a support-ticket form. Its preview page echoes the
`?subject=` parameter straight into a visible block on the page:

```html
<div class="subject">YOUR-SUBJECT-HERE</div>
```

The value is reflected with **no HTML escaping** — but this time there is a
"sanitiser" in front of it. Before reflecting, the app runs a **single-pass
substring blocklist**: it deletes, case-insensitively and in one left-to-right
pass, each of these four strings and nothing else:

```
<script      </script      javascript:      onerror=
```

Each token is stripped **once**; the result is **never re-scanned**, and no
output encoding runs afterwards. So `/?subject=<script>alert(1)</script>` comes
back neutered — but the blocklist is a **denylist**, and denylists fail open.
It never names the many other ways to run JavaScript.

You are not the victim, though. The interesting target is the desk's **admin**,
represented by a headless-Chromium bot that:

- **visits any path you submit** through `POST /report` (the "report a page to
  staff" feature), every couple of seconds, and
- does so **carrying the admin's `session` cookie** — which, through a second
  misconfiguration, is **not** marked `HttpOnly`, so `document.cookie` can read
  it.

## Objective

Get past the blocklist so that the admin bot's browser runs a payload which
steals its `session` cookie and sends it to the in-lab collector:

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

1. **Confirm the sink and the filter.** Request `/?subject=<b>hi</b>` and view
   source — your `<b>` tags reflect **unescaped** (the sink is raw). Now request
   `/?subject=<script>alert(1)</script>` — the `<script`/`</script` are gone.
   The filter is real, but narrow.
2. **Climb the ladder.** The blocklist blocks a _specific spelling_ of "run
   JavaScript", not the _capability_. Which tags/attributes execute code on
   **load** without a `<script>` tag and without `onerror`?
3. **Deliver to the admin.** Running a script in _your own_ browser gets you
   nothing — you need _their_ browser. `POST /report` hands the admin a URL of
   your choosing; a payload that fires on load can read `document.cookie` and
   beacon it out.

**CWE-79 (Improper Neutralization of Input During Web Page Generation) /
OWASP A03:2021 – Injection.** The real fix — an allowlist plus contextual output
encoding, not a bigger blocklist — is discussed in `SOLUTION.md`.
