# Classic Login Bypass on Legacy Guestbook

> Track: `sqli` · Difficulty: **apprentice** · ~20 min · No hints cost XP (they never do).

## Scenario

You have found the admin panel of an ageing intranet "guestbook" tool. It looks
like something a junior developer copy-pasted from a forum in 2004 and never
revisited — there is even a `TODO: fix later` comment left in the page source.
The panel gates a dashboard that prints an internal system flag, but only to a
logged-in administrator. You do not have the admin password, and nobody does:
the built-in `root` account was seeded with a random value at deploy time.

## Objective

Authenticate to `/admin/login` as an administrator **without** knowing any
password, then open `/admin/dashboard` and read the flag it prints inline.

The flag looks like `FLAG{<64 hex characters>}` and is unique to your instance —
a flag pasted from someone else's machine will never validate on yours.

## Getting Started

1. Launch the lab from the hub (or `labctl launch sqli/sqli-login-bypass-basic`)
   and open the instance URL — it lands on the login form.
2. Open your browser's devtools (or a proxy such as Burp) and watch the request
   the login form sends. Notice it is a plain `POST` with `username` and
   `password` fields.
3. Ask yourself what the server does with those two strings before it decides
   whether to let you in. If you get stuck, reveal the hints in order — they are
   free and they narrow one step at a time.

**CVE analog family.** Authentication bypass through SQL injection is a decades-old
class that still lands real bounties — think of the many CVEs tagged **CWE-89**
where a login form concatenates credentials straight into a query
(OWASP **A03:2021 – Injection**). This lab is the minimal, abstracted version of
that primitive; no vendor code is reproduced.
