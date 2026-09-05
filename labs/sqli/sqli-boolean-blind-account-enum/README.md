# Boolean-Blind Extraction via a Reset Form Oracle

> Track: `sqli` · Difficulty: **practitioner** · ~30 min · Free hints.

## Scenario

A SaaS "account recovery" service exposes `POST /forgot`. Send it a JSON body
`{"username": "..."}` and it always answers with the same polite 200 response:

```json
{ "message": "If an account exists, an email has been sent." }
```

The developer was proud of that: the body is identical whether or not the account
exists, so — they reasoned — nobody can enumerate usernames. But the endpoint was
built in a hurry, and the query that checks the username is assembled by pasting
your input straight into a string. Worse, a "helpful" debugging header slipped
into production and quietly reports the result of that lookup. When the only
observable is a single true/false signal, you do not need the query to print
anything — you can _ask it questions_.

## Objective

Recognise the boolean oracle, confirm the `username` field is injectable, and use
that oracle to read data out of the database one bit at a time. Specifically:
reconstruct the **first 32 characters of the `admin` account's stored
`password_hash`**. Submit them to `/solve` as JSON `{"prefix": "<32 chars>"}` and
the service returns the flag.

The flag looks like `FLAG{<64 hex characters>}` and is unique to your instance —
a flag copied from another machine will never validate on yours.

## Getting Started

1. Launch the lab and note the instance URL. Everything happens over
   `POST /forgot` with a JSON body and a JSON content-type.
2. Send a request for a name you expect to exist (`admin`) and one you do not
   (`totally-not-real`). The body is identical both times — but compare the full
   response, headers included. Something differs. That difference is your oracle.
3. Once you trust the oracle, ask it a question whose answer you control, then a
   question whose answer the _database_ controls. Reveal the hints in order if you
   get stuck — they are free.

**CVE analog family.** Boolean-based **blind SQL injection** (CWE-89, OWASP
**A03:2021 – Injection**) combined with an **observable response discrepancy**
(CWE-204) is a staple of real bug-bounty reports: a login/reset/search endpoint
that leaks a single true/false bit per request, which an attacker escalates into
full data exfiltration. See PortSwigger's "Blind SQL injection with conditional
responses" and the large family of username-enumeration write-ups. No vendor code
is reproduced here.
