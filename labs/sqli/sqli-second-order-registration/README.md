# Second-Order SQL Injection via Stored Username

> Track: `sqli` · Difficulty: **practitioner** · ~35 min · Free hints.

## Scenario

"Referral Hub" is a tiny invite-tracking service. You can `POST /register` with a
username and password, log in, and view your own referral codes at
`GET /me/referrals`. The team was careful about SQL injection at the front door:
registration writes your account through the ORM, so poking quotes into the
signup form gets you nowhere — the value is safely parameterised and just stored
as-is.

The interesting part is what happens _later_. Somewhere downstream, your saved
username is read back out of the database and used to build another query. Data
that looked inert when it was written can wake up when it is read.

## Objective

Recover the `admin` account's per-instance `session_secret` (a 32-character hex
value that lives in a table you cannot query directly), then redeem it at
`GET /solve?secret=<value>` to receive the flag (`FLAG{<64 hex>}`, unique to your
container). You will need a valid session to reach the vulnerable page.

## Getting Started

1. Launch the lab and open the instance URL. Read the endpoint list on `/`.
2. Register an account and log in, then visit `/me/referrals`. Notice the page is
   built from a query keyed on _your username_.
3. Ask the key question: if the front-door INSERT is safe, where else does your
   stored username end up — and is it treated as data there too?
4. Reveal the hints in order if you get stuck. They are free.

**CVE-analog family.** This is **second-order (stored) SQL injection** —
**CWE-89 / OWASP A03:2021**, catalogued as OWASP WSTG-INPV-05. The pattern
recurs whenever input is neutralised (or trusted) at write time but concatenated
into SQL at read time. No vendor code is reproduced here.
