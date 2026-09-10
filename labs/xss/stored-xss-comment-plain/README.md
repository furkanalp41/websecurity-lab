# Stored XSS in Blog Comment Moderation

> Track: `xss` · Difficulty: **apprentice** · ~30 min · Free hints.

## Scenario

**The Bugle** is a small Django blog. Anyone can leave a comment; it is stored
and held **unapproved** until a staff member reviews it. The moderation queue at
`GET /admin/moderate` renders each pending comment — and the template does:

```django
<div class="body">{{ c.body|safe }}</div>
```

Django autoescapes template variables **by default**, which would have made this
safe. But a developer added `|safe` "to allow basic formatting", disabling the
escaping for the one field an attacker fully controls. That is **stored XSS**.

The staff member is an admin bot: it loads `GET /admin/moderate` every few
seconds while holding its `session` cookie (which is **not** `HttpOnly`).

## Objective

Post a comment whose body runs in the admin's browser when they moderate it, and
steal their `session` cookie to the in-lab collector
(`http://collector:9000/report?c=…`). Read it back via `GET /oob/received`, then:

```
POST /solve   {"c":"<32 hex>"}
```

You cannot load `/admin/moderate` yourself — it is admin-only (403 without the
cookie). That is the point of _stored_ XSS: you don't need to reach the page, you
plant a payload the admin will render for you.

## Getting Started

1. Post a normal comment and note that it says "queued for moderation" — you
   won't see it on the front page until approved.
2. The moderation page renders comment bodies as raw HTML. What element runs
   JavaScript the moment it is parsed?
3. Your payload executes in the admin's browser. What do you steal, and where do
   you send it?

**CWE-79 (Improper Neutralization of Input During Web Page Generation), stored
variant. OWASP A03:2021 – Injection.** The fix — drop `|safe` (let Django
autoescape) and set an `HttpOnly` session cookie — is in `SOLUTION.md`.
