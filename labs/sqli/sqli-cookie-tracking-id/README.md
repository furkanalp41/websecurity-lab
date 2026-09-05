# SQL Injection Hidden in a Tracking Cookie

> Track: `sqli` · Difficulty: **apprentice** · ~25 min · Hints are free (they always are).

## Scenario

"Groove Depot" is a tiny promotional microsite for a record shop. The first time
you land on it, the server drops a `TrackingId` cookie so it can remember you and
show a personalised welcome banner on your next visit. Behind the scenes, that
cookie is fed into a database lookup that decides which banner to render.

The developer treated the cookie as a trusted, machine-generated token — after
all, _the server_ set it, so who would ever change it? Everything the site does
with your input travels through the URL and the visible forms, so a tester who
only pokes at query-string parameters will find nothing. The interesting surface
is the one nobody thinks to touch.

Somewhere in the same database sits an `internal_config` table with a
`license_key` the site never means to expose. There is a maintenance endpoint,
`/solve`, that hands back an internal system flag — but only to a caller who can
present that exact license key.

## Objective

Recover the site's secret `license_key` (stored in `internal_config`, random and
unique to your running instance), then submit it to `GET /solve?license=<value>`
to read the flag.

The flag looks like `FLAG{<64 hex characters>}` and is unique to your instance —
a flag copied from anyone else's machine will never validate on yours.

## Getting Started

1. Launch the lab and open the instance URL (path `/`). Reload once and watch the
   `Set-Cookie: TrackingId=...` response header in devtools or a proxy such as
   Burp — that value is echoed back and clearly drives the banner shown.
2. Ask what the server _does_ with that cookie before it renders your banner. The
   URL is a dead end here; the injection lives somewhere requests usually treat as
   read-only.
3. Reveal the hints in order if you get stuck. They narrow one step at a time and
   never cost anything.

**CVE analog family.** Injecting SQL through a request header/cookie is the same
**CWE-89 / OWASP A03:2021 – Injection** class behind countless real bounties —
the classic example is PortSwigger's "SQL injection vulnerability in a cookie"
lab, and many production apps have shipped analytics cookies concatenated into
queries. No vendor code is reproduced here; the vulnerability class is abstracted.
