# DOM XSS via location.hash into document.write

> Track: `xss` · Difficulty: **apprentice** · ~30 min · Free hints.

## Scenario

**Nimbus** is a static marketing microsite. On load, an inline script
personalises the greeting from the URL fragment:

```js
document.write('<h1>Welcome ' + decodeURIComponent(location.hash.slice(1)) + '</h1>');
```

The fragment (`#…`) is **never sent to the server** — it lives only in the
browser. So this is a pure **DOM-based** XSS: the source is `location.hash`, the
sink is `document.write`, and there is no server round-trip to sanitise it. Only
a browser can trigger it.

The admin bot visits any path you submit to `POST /report` while holding its
`session` cookie.

## Objective

The flag is at `GET /flag.txt` — but it is served **only** to a request carrying
the admin `session` cookie. You do not have that cookie, and the endpoint that
mints it (`/internal/bot-login`) is reachable only from the internal network. So
you cannot read `/flag.txt` directly.

But JavaScript you inject through the DOM XSS runs in the **admin bot's origin**.
A same-origin `fetch('/flag.txt')` from that context sends the bot's cookie for
you. Read the flag and exfiltrate it to the in-lab collector
(`http://collector:9000/report?f=…`), then read it back via `GET /oob/received`.

## Getting Started

1. Load `/#test` and view the result — "test" is written into the page via
   `document.write`. What if it were markup instead of text?
2. Modern browsers won't run a `<script>` inserted this way after load — but an
   element with an **event handler** (`<img src=x onerror=…>`) parsed via
   `document.write` runs fine.
3. Your JS runs as the admin. What same-origin resource can you now read that you
   couldn't before?

**CWE-79 (Improper Neutralization of Input During Web Page Generation),
DOM-based variant. OWASP A03:2021 – Injection.** The fix — assign to
`textContent`/`innerText`, or sanitise before insertion, and never `document.write`
untrusted input — is in `SOLUTION.md`.
