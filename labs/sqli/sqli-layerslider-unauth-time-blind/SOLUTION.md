# Solution — sqli-layerslider-unauth-time-blind

> **OWASP:** A03:2021-Injection · **CWE:** CWE-89 · **CVE analog:** CVE-2024-2879
> (LayerSlider) — abstracted; the original plugin code is not reproduced.

## What tipped you off

`/wp-admin/admin-ajax.php?action=ls_get_popup_markup&id=1` returns markup, and it
is reachable with no cookie and no nonce — an unauthenticated `wp_ajax_nopriv_`
action. The response never changes (same 200, same body) no matter what you put
in `id`, which rules out UNION/error/boolean output channels. The one thing you
_can_ influence from outside is **response latency** — the signature of a
time-based blind injection.

## The class of bug

SQL injection (CWE-89) via the **`wpdb::prepare()` concatenation footgun**. The
handler builds:

`src/web/wp-admin/admin-ajax.php`

```php
$id = $_REQUEST['id'];               // attacker-controlled, e.g. "0 OR (...)"
$sql = $wpdb->prepare(
    "SELECT id, name, html FROM {$wpdb->prefix}ls_sliders WHERE id = $id AND flag_hidden = 0"
);
$wpdb->get_row($sql);                // result ignored: response never varies
```

`$id` is interpolated into the **format string** by PHP _before_ `prepare()` ever
sees it, and no `%d` placeholder + argument is passed. WordPress' `prepare()` only
substitutes and escapes the placeholder _arguments_ you give it; with none, it
returns the query verbatim. "We used `prepare()`" is not a defence when the
untrusted value was concatenated into the query text instead of bound.

## Getting past the baseline filter

The CRS-paranoia-1 homage (`src/lib/waf.php`) blocks loud tokens. The two that
matter:

- `SLEEP(` — matched by `/\bsleep\s*\(/i`. The pattern requires the keyword to be
  directly followed by optional **plain whitespace** and `(`. An inline comment
  is not whitespace to that regex, so `SLEEP/**/(` breaks the adjacency and slips
  through. MariaDB treats `/**/` as whitespace and allows it between a function
  name and its parenthesis, so the call still executes.
- Quoted strings / `OR '..'` and SQL line comments (`-- `, `#`) are flagged too.
  Encode `'admin'` as the hex literal `0x61646d696e` (no quotes) and keep the
  injected clause **balanced** so you never need a `-- ` terminator.

Neither `SELECT ... FROM` nor a subquery is blocked at this baseline, so a
sleeping subquery over `wp_users` sails through once the two tricks above are
applied.

## Building the oracle

Inject a conditional delay into the `WHERE` via a scalar subquery:

```
id = 0 OR (SELECT SLEEP/**/(0.6) FROM wp_users
           WHERE user_login=0x61646d696e AND (<condition>))
```

- `<condition>` TRUE → the admin row matches → the subquery runs `SLEEP` → the
  request pauses (~0.6s or more).
- `<condition>` FALSE → no row matches → no delay.

`0 OR (...)` keeps the statement valid inside `WHERE id = <payload> AND
flag_hidden = 0` with no comment needed. A response slower than a threshold means
"true".

## The mechanical exploit / Exploit walkthrough

Binary-search each character of `user_pass` on its ASCII code:

```
<condition> = ASCII(SUBSTRING(user_pass,POS,1)) >= VAL
```

`user_pass` is 16 lowercase hex chars (charset `0-9a-f`, ASCII-ascending, so `>=`
is monotonic — a clean binary search). ~4 requests per character recovers each of
the 16 positions. Then:

```
POST /solve   {"hash":"<16 hex chars>"}   ->   {"flag":"FLAG{...}"}
```

`tests/exploit.py` does exactly this with the standard library only. It:

- uses `SLEEP/**/(` and `0x61646d696e` to pass the filter;
- **parallelises** the binary search across the 16 positions with a small thread
  pool (kept well under Apache's worker count so a FALSE request never queues
  behind another request's SLEEP and clocks a false positive);
- treats an HTTP **429** (rate-limit) as "retry", never as a FALSE timing;
- re-measures any slow reading and takes the minimum, so a transient blip washes
  out while a real SLEEP stays high.

The whole run finishes in ~15-25s, comfortably under the 60s budget.

## Lab-vs-production deviation

- **16-hex `user_pass` instead of a phpass hash.** Real WordPress stores a
  ~34-char `$P$B...` phpass hash in `wp_users.user_pass`. Here it is a random
  16-char lowercase-hex token so a rate-limited, time-based extraction clears the
  platform's `<60s` exploit gate. The extraction technique is byte-for-byte
  identical at any length or charset (widen the per-character search space and it
  simply takes more requests).
- **App-level filter instead of ModSecurity + full CRS.** The catalogue sketched
  an "OWASP CRS 4.0 baseline WAF (paranoia 1)". This lab ships an application-
  level homage (`src/lib/waf.php`) modelled on the shape of the CRS 942xxx SQLi
  rules at paranoia 1: it flags the loud tokens and — like many real baseline
  deployments — misses inline-comment obfuscation. The bypass you practise
  (comment-break a function keyword, hex-encode a string) is a real, portable
  technique against production WAFs.
- **`/solve` reads the flag in-process.** It compares your submission against the
  bound admin secret and reads the flag file directly in PHP; it does not shell
  out to a `give-flag.sh`, which would hand an attacker a command primitive.
  Reading the file in-process is the safer established pattern across these labs.

## Alternative payload vectors

The injection point is a full `WHERE` expression, so any conditional-delay shape
works once it clears the filter:

1. **Subquery SLEEP** (used by the exploit): `0 OR (SELECT SLEEP/**/(t) FROM
wp_users WHERE user_login=0x61646d696e AND (<cond>))`.
2. **IF + SLEEP**: `0 OR IF((<cond>),SLEEP/**/(t),0)` — but note this evaluates
   per scanned row of `wp_ls_sliders`, multiplying the delay; the subquery form
   is cleaner.
3. **Heavy computation instead of SLEEP** (if `SLEEP` itself were fully banned):
   a correlated `RLIKE`/`REGEXP` bomb or repeated `MD5()` nesting produces a
   measurable delay without the `SLEEP` keyword.

## Fix

- Bind the value, never concatenate: `$wpdb->prepare("... WHERE id = %d ...",
$id)`. With a real placeholder + argument, `prepare()` casts/escapes it and the
  injection closes.
- Gate `wp_ajax_nopriv_*` actions with a capability/nonce check unless the data
  is genuinely public.
- Treat a WAF as defence-in-depth, not the control: a baseline ruleset is
  bypassable (as shown), so the parameterised query is what actually fixes the
  bug.
