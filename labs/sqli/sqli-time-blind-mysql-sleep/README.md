# Time-Blind SQLi on a Silent Analytics Beacon

> Track: `sqli` · Difficulty: **practitioner** · ~35 min · Free hints.

## Scenario

**Pulse** is a minimalist analytics service. Every page-view is reported by
firing a tiny beacon:

```
GET /beacon?ref=https://example.com/landing
```

The server records the referrer and your `User-Agent`, then answers
`204 No Content` — an empty response with no body. It behaves identically no
matter what you send: same status, same (absent) body, same headers. There is no
search page, no error message, no reflected value. From the outside it looks
inert.

Under the hood, though, the beacon writes your input into a MySQL table with a
hand-assembled `INSERT` statement, gluing the `ref` value straight into the SQL
text. There is no `SELECT` you can see the output of and no `UNION` you can bolt
on — but the database will still _do what you tell it_, including taking its time.

Somewhere in the same schema is a table the service never meant you to reach. One
column holds a random per-instance token. Read it, and a hidden endpoint trades it
for the flag.

## Objective

Recover the `beacon_token` value from the `secrets` table through the `/beacon`
endpoint, then submit it:

```
POST /solve      Content-Type: application/json
{"token": "<the 16-hex token>"}
```

On a match the server returns the flag (`FLAG{<64 hex>}`, unique to your
instance); a wrong token returns HTTP 403.

The token is generated fresh inside your container, so a value copied from someone
else's instance will never validate — you must extract _your_ token.

## Getting Started

1. Launch the lab and hit `/beacon?ref=test`. Confirm it returns `204` with an
   empty body. Try a few values — nothing about the response changes. So what
   _could_ change?
2. There is exactly one observable an attacker can influence here: **how long the
   request takes**. If you can make the database pause on demand, that pause is a
   one-bit answer to any yes/no question you can phrase in SQL.
3. Think about the statement shape. This is a _write_ (`INSERT`), not a _read_.
   `UNION` and visible columns are off the table. What SQL construct lets you run
   a conditional `SLEEP()` as part of the value being inserted? Reveal the hints
   in order if you get stuck — they are free.

> **A note on token length.** The public catalogue describes a 40-character token
> extracted at roughly one second per bit. That is faithful to how these bugs feel
> in the wild, but a serial extraction of that size runs for minutes. To keep the
> automated solver inside the platform's 60-second budget, _this_ instance uses a
> 16-character hex token and a parallelised solver. The payload, the oracle, and
> the reasoning are exactly the same — only the number of characters (and thus the
> wall-clock) changes. See `SOLUTION.md`.

**CVE analog family.** Time-based blind SQL injection is a classic **CWE-89 /
OWASP A03:2021 – Injection** pattern. It is the technique of last resort — and
often the only one — against "silent" write endpoints (analytics beacons,
tracking pixels, logging sinks) that return nothing to the caller. See
PortSwigger's _Blind SQL injection with time delays_ lab and the long tail of
bounty reports against fire-and-forget analytics endpoints. No vendor code is
reproduced here.
