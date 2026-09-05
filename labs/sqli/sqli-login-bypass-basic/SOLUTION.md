# Solution — sqli-login-bypass-basic

<!-- Instructor/authoring reference. Students should try the hints first. -->

## What tipped you off

The login form takes two free-text fields and immediately makes an
authentication decision. When you submit a single quote (`'`) in the username,
the page returns a raw database error (`SQL error: ...`) instead of a clean
"invalid credentials" message. A server that leaks its SQL error to the client
is almost always building that SQL by hand from your input.

## The class of bug

This is **SQL injection** (CWE-89), specifically an **authentication bypass**.
It maps to OWASP **A03:2021 – Injection**. The application trusts attacker-
controlled strings as _code_ rather than _data_. Real-world analogs are
plentiful: countless login forms and admin panels have shipped this exact
pattern. See PortSwigger's "SQL injection vulnerability allowing login bypass"
and the OWASP WebGoat login examples for the canonical treatment, and the broad
family of **CWE-89** CVEs in login/authentication paths.

## Vulnerability

`admin/login.php` builds the query by string concatenation:

```php
$sql = "SELECT id, username, role FROM users WHERE username='" . $u . "' AND password='" . $p . "'";
```

`$u` and `$p` come straight from `$_POST` with no parameterisation, escaping, or
allowlisting. Anything you type inside the `username` field becomes part of the
SQL statement.

## Why it exists / Why the developer wrote it this way

String-concatenated SQL is the most "obvious" way to write a query if you have
never been bitten by injection. It reads like a sentence, it is easy to debug by
printing the string, and it works perfectly in every test where the input is a
normal username. The developer optimised for "make the happy path work now" and
left a literal `TODO: fix later`. Prepared statements feel like ceremony until
you understand that the database has no other way to tell your _data_ apart from
your _code_.

## The mechanical exploit / Exploit walkthrough

Send this as the `username` (password can be anything):

```
root'-- -
```

The query the server runs becomes:

```sql
SELECT id, username, role FROM users WHERE username='root'-- -' AND password='x'
```

The `'` closes the username literal; `--` starts a SQL comment so the rest of
the line (including the password check) is ignored. The query now selects the
`root` row unconditionally, the app reads its `role` column (`admin`), stores it
in your session, and redirects you to `/admin/dashboard`, which prints the flag.

A pure tautology such as `' OR '1'='1'-- -` also works but logs you in as
whichever row comes first; targeting `root'-- -` is cleaner and matches the
stated objective. The bundled `tests/exploit.py` performs exactly this and then
asserts the recovered flag equals the HMAC-derived expected value.

## Fix

Use a parameterised query and never interpolate input into SQL:

```php
$stmt = $db->prepare('SELECT id, username, role FROM users WHERE username = ? AND password = ?');
$stmt->execute([$u, $p]);
$row = $stmt->fetch(PDO::FETCH_ASSOC);
```

With bound parameters the driver sends your input as _values_, so `root'-- -`
is compared literally against the `username` column and matches nothing. Pair
this with hashed passwords (`password_hash`/`password_verify`) and generic
"invalid credentials" errors so the endpoint leaks neither structure nor state.
