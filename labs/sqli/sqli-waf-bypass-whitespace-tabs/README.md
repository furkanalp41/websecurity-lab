# Whitespace-Filter WAF Bypass Ladder

> Track: `sqli` · Difficulty: **practitioner** · ~30 min · Free hints.

## Scenario

The **Acme Intranet** staff directory lets anyone look a colleague up by their
numeric badge id at `/lookup?id=2`. After an intern once pasted `' OR '1'='1`
into the box, the security team bolted on a homegrown request filter with a
simple rule of thumb: _"injection keywords like `UNION SELECT` all need spaces —
so if we strip every space, we strip the attack."_

The filter (`waf_forward` in `src/app.py`) deletes `+`, folds the `%20` and `%09`
escapes it recognises into a space/tab, then strips every literal space and tab
before the value is glued into:

```
SELECT username, email FROM users WHERE is_admin=0 AND id=<id>
```

The `is_admin=0` guard keeps the boss's row (badge id `1`) out of ordinary
lookups. Their directory email is a random per-instance address — and if you can
read it back, a hidden endpoint will trade it for the flag.

To make the filter honest about itself, `/debug?id=<value>` prints the **exact
bytes** it forwards to the database, so you can verify a payload is space-free
before you send it.

## Objective

Read the hidden admin email (the row where `id=1`) through `/lookup`, despite the
whitespace filter, then submit it to `/solve?email=<value>`. On a match the
server returns the flag (`FLAG{<64 hex>}`, unique to your instance); a wrong
value returns HTTP 403.

The admin email is generated fresh inside your container, so a value copied from
someone else's instance will never validate — you must extract _yours_.

## Getting Started

1. Launch the lab and browse `/lookup?id=2`, `?id=3`, `?id=4` — the row changes,
   so `id` reaches SQL. Now try `?id=1`: nothing comes back. The admin is hidden,
   not absent.
2. This is a **numeric** context (`... id=<id>`), so you do not need a quote to
   break out — you need SQL _keywords_, and keywords need separators. Try the
   obvious `id=1 UNION SELECT ...` and watch it fail, then open `/debug?id=...`
   and see what the filter actually forwarded. Every space is gone.
3. Climb the ladder: if spaces, tabs, `%20`, `%09`, and `+` are all removed, what
   other bytes does MySQL accept _between tokens_? Reveal the hints in order if
   you get stuck — they are free.

**CVE analog family.** Blacklist-style WAFs that strip or reject whitespace are a
recurring real-world weakness: MySQL's `/**/` inline comments, raw newlines
(`%0a`), and parentheses all separate tokens without a single 0x20 byte. This is
**CWE-89 / OWASP A03:2021 – Injection**, exploited via filter evasion rather than
verbose errors. See PortSwigger's filter-bypass labs and the standard sqlmap
`space2comment` / `space2mysqlblank` tamper scripts. No vendor code is reproduced
here.
