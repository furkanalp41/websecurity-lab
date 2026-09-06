# Solution — sqli-second-order-registration

## What tipped you off

Injecting at the registration form does nothing: quotes in the username are
stored literally and never break a query, because the INSERT is parameterised.
But `/me/referrals` renders a list that is clearly keyed on _your own username_ —
and the app never made you prove your username was "safe" SQL. That mismatch (the
value is validated/trusted nowhere, yet is obviously used to build a query
somewhere) is the signature of a **second-order** bug: the write is safe, the
read is not.

## The class of bug

SQL injection (CWE-89, OWASP A03:2021), specifically the **second-order / stored**
variant (OWASP WSTG-INPV-05). The tainted value takes a detour through the
database between the point where it enters the app (registration) and the point
where it is concatenated into SQL (the referrals page). Because source and sink
are in different requests and different code paths, input filtering at the source
gives a false sense of safety.

## Vulnerability

`src/app/views.py`, `/me/referrals`:

```python
username = request.user.username
query = "SELECT code, invited_email FROM referrals WHERE owner = '" + username + "'"
with connection.cursor() as cursor:
    cursor.execute(query)
    rows = cursor.fetchall()
```

The username was stored safely at `/register` via `User.objects.create_user(...)`
(a parameterised ORM INSERT), but here it is spliced raw into a `WHERE` clause.

## Why the developer wrote it this way

Two reasonable-sounding assumptions collided. First, "we use the ORM everywhere,
so we're safe from SQLi" — true for the INSERT, but this one report was written
with a hand-rolled `connection.cursor()` for a quick join the developer did not
want to model. Second, "`request.user.username` is our own data, not user
input" — it _feels_ trusted because it comes from the session and the auth
system, so it skips the mental "this is attacker-controlled" flag. Combined, the
raw query looks harmless in review: the value it interpolates "came from the
database," so surely it is clean.

## Why it exists

The username is attacker-chosen and stored verbatim (Django's `create_user`
does not run form/field validators, so any characters — quotes, spaces,
parentheses, comments — survive). Parameterisation at write time protects the
INSERT statement, but it does nothing to sanitise the _value_: it is stored
exactly as supplied. When that exact string is later concatenated into SQL, the
quotes and keywords it contains are finally interpreted as code. Second-order
injection exists precisely because "safely stored" is not the same as "safe to
concatenate."

## The mechanical exploit

Register a username that is a self-contained UNION payload sized to the referrals
query's two output columns (`code`, `invited_email`):

```
x' UNION SELECT session_secret, NULL FROM accounts WHERE username='admin'-- -
```

When `/me/referrals` splices it in, the executed statement becomes:

```sql
SELECT code, invited_email FROM referrals
WHERE owner = 'x' UNION SELECT session_secret, NULL FROM accounts WHERE username='admin'-- -'
```

`owner = 'x'` matches nothing, `-- -` comments out the trailing quote the sink
appends, and the `UNION` appends one row whose first column is the admin's
`session_secret`. The page renders it in the "code" position.

## Exploit walkthrough

1. `POST /register` with `username=<payload above>`, `password=<anything>`. The
   INSERT stores the payload verbatim (no error — it is dormant here).
2. `POST /login` with the same credentials to get a session cookie. (Auth also
   goes through the parameterised ORM, so the odd username logs in fine.)
3. `GET /me/referrals`. The stored username is re-spliced; the response now
   contains the 32-hex `session_secret` where a referral code would normally be.
4. Read the secret out of the HTML, then `GET /solve?secret=<value>` to receive
   the flag.

`tests/exploit.py` performs exactly this with `urllib` + `http.cookiejar` and
asserts the flag equals the HMAC-derived expected value. The register/login
views are `@csrf_exempt` purely so the stdlib client can POST without scraping a
CSRF token — that is a lab convenience, not part of the vulnerability.

## Fix

Never concatenate a value into SQL, regardless of where it came from. Bind it:

```python
username = request.user.username
with connection.cursor() as cursor:
    cursor.execute(
        "SELECT code, invited_email FROM referrals WHERE owner = %s",
        [username],
    )
    rows = cursor.fetchall()
```

Better still, use the ORM (`Referral.objects.filter(owner=username)`), which
parameterises by construction. The deeper lesson: treat every value as untrusted
at the point of use — "it came from our own database" is not a security property.
Parameterise at the sink, not (only) at the source.
