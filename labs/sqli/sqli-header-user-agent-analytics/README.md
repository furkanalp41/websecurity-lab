# Stored SQLi Through the User-Agent Header

> Track: `sqli` · Difficulty: **practitioner** · ~35 min · Free hints.

## Scenario

**Pulse Metrics** is a tiny in-house analytics tool the marketing team bolted
onto their site. Its job is boring: on _every_ request it records the visitor's
`User-Agent` string into a MySQL table so the team can see which browsers and
crawlers show up. That write is done properly — the header is stored as a bound
parameter, quotes and all, and there is nothing to attack about the logging step
itself.

The interesting part is the **dashboard**. `GET /admin/insights` is billed as an
internal, localhost-only admin panel (here it is reachable directly through a
debug route so the lab can grade it). To build its per-browser breakdown, the
dashboard walks the distinct stored User-Agents and, for each one, re-counts its
hits by pasting the stored string straight into a `WHERE ua='…'` clause. In other
words: a value _you_ controlled on an earlier request gets spliced into SQL on a
completely different code path, at a completely different time.

Somewhere in the same database is a `settings` table with a random per-instance
`master_key`. If you can make the dashboard print that value, a hidden endpoint
will trade it for the flag.

## Objective

Store a UNION-based SQL injection payload **in your User-Agent header**, then load
`/admin/insights` so the dashboard executes it and discloses
`settings.master_key`. Submit that 32-hex value to `/solve?key=<value>` (GET or
POST) to receive the flag (`FLAG{<64 hex>}`, unique to your instance). A wrong key
returns HTTP 403.

The key is generated fresh inside your container, so a value copied from someone
else's instance will never validate — you must extract _your_ key.

## Getting Started

1. Launch the lab. Browse `/` (it confirms your visit and User-Agent are logged),
   then open `/admin/insights` to see the normal breakdown of seeded browsers.
2. Notice the two halves of the system: the **write** happens on every request
   (via your `User-Agent`); the **read** happens later on the dashboard. Ask
   yourself where your input could be treated as _code_ instead of _data_ — and
   it is not on the write.
3. Set a crafted `User-Agent` header on a request, then reload `/admin/insights`
   and watch what the "hit count" column does. Reveal the hints in order if you
   get stuck — they are free.

**CVE analog family.** A stored value that is safely inserted but later
concatenated into a query is the canonical **second-order / stored SQL injection**
pattern (**CWE-89 / OWASP A03:2021 – Injection**), and HTTP headers such as
`User-Agent` are a classic overlooked injection surface. See PortSwigger's
"SQL injection in the User-Agent HTTP header" lab and the long tail of
analytics/logging pipelines that trusted stored request metadata. No vendor code
is reproduced here.
