# Header SQLi to Session Forgery and File Exfil

> Track: `sqli` · Difficulty: **elite** · ~60 min · Free hints.

## Scenario

`Acme Transfer` is a managed file-transfer appliance. Like the real product it
homages (Progress MOVEit Transfer, CVE-2023-34362), it stamps an audit note from a
custom request header — here `X-siLock-Comment` — into a database-backed audit log.
That header value is concatenated straight into an `INSERT`, and the driver runs
multiple statements per call, so the audit log is a **stacked-query** injection
point.

The interesting target is not the audit log itself but the appliance's
**database-backed session store**. If you can inject a second statement, you can
write your own **admin session row** and skip authentication entirely.

## Objective

1. Forge a valid `sysadmin` session by injecting through `X-siLock-Comment`.
2. Use the forged session cookie to download the protected file
   `GET /files/download?path=confidential/flag.bin`.
3. Prove exfiltration: `POST /solve {"sha256":"<hex>"}` with the SHA-256 of the
   downloaded bytes. On a match you receive `FLAG{...}` (unique to your container).

The confidential file's contents are unique per instance, so you must actually
download it — a hash copied from someone else will not validate.

## Getting Started

1. Look at the request headers a transfer appliance trusts. `POST
/api/transfer/register` records `X-siLock-Comment`. Put a `'` in it and watch
   the audit insert break — the header reaches SQL.
2. `GET /files/download?path=confidential/flag.bin` returns `403` — it needs a
   valid admin session, and `/login` won't help you (you have no credentials).
   Where are sessions stored, and what could you do to that store from an
   injection that runs _more than one statement_?
3. Forge a row, present the cookie, download the file, hash it, submit. Reveal the
   hints in order if you get stuck.

**CVE analog family.** SQL injection that writes to a session/authentication store
(rather than only reading data) to bypass auth is the shape of **CVE-2023-34362
(MOVEit Transfer)** and similar appliance bugs — **CWE-89 → CWE-384 (session
fixation/forgery)**. No proprietary code is reproduced; only the chain shape.
