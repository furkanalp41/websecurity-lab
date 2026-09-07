# Unauthenticated Time-Blind SQLi in a WP-Style Slider Plugin

> Track: `sqli` · Difficulty: **elite** · ~60 min · Free hints.

## Scenario

`Acme Marketing` runs a minimalist WordPress-style CMS with a marketplace
"slideshow" plugin (**LS Slider**, v7.9.11 — a homage to the LayerSlider plugin
behind CVE-2024-2879). The plugin renders popup markup through a classic
WordPress AJAX action:

```
GET /wp-admin/admin-ajax.php?action=ls_get_popup_markup&id=<id>
```

The action is registered for anonymous callers (`wp_ajax_nopriv_*`), so **no
login and no nonce** are required to reach it. The developer built the lookup
with `$wpdb->prepare()` and believed that made it safe. It did not: `id` is
concatenated into the query string and no `%d` placeholder binds it, so
`prepare()` returns the text untouched and `id` is parsed as SQL.

Two obstacles stand between you and the data:

1. **No output channel.** The action always answers `200 OK` with the _same_
   static markup — whether the row exists, the query errors, or your injected
   condition is true or false. The response body, status, and headers never vary
   with your payload.
2. **A baseline SQLi filter** (a CRS-4.0 paranoia-1 homage) sits in front of the
   query and blocks the loud tokens — `UNION SELECT`, a bare `SLEEP(`,
   `OR 1=1`, SQL line comments, `information_schema`. A per-IP **rate limiter**
   throttles bursts.

## Objective

Recover `wp_users.user_pass` for `user_login='admin'` (16 lowercase hex
characters in this instance) purely through the **timing side channel** of the
injectable `id` parameter, then:

```
POST /solve    {"hash":"<recovered value>"}    ->    {"flag":"FLAG{...}"}
```

The flag (`FLAG{<64 hex>}`) is unique to your container.

## Getting Started

1. Fire the action with a normal `id` and watch it return the same markup every
   time. Confirm the parameter reaches SQL: does `id=1` vs `id=2 OR 1=1` behave
   differently in any observable way? (It won't — except in _time_.)
2. Try the obvious `id=1 AND SLEEP(3)`. You'll be **blocked** by the security
   policy. Read the block message: which token tripped it, and how might you
   write the same primitive so the filter's pattern no longer matches?
3. Once you can make the request pause on command, phrase a yes/no question about
   one character of the admin hash, and read the answer off the clock. Then
   optimise: binary search per character, and probe several positions at once.
   Reveal the hints in order if you get stuck; they are free.

**CVE analog family.** Unauthenticated SQL injection through a WordPress plugin
AJAX action that misuses `$wpdb->prepare()` (concatenation instead of a bound
`%d`/`%s`) is the shape of **CVE-2024-2879 (LayerSlider)** and many sibling
plugin advisories — **CWE-89 / OWASP A03:2021**. No vendor code is reproduced
here; the shim is ~300 lines of original PHP.
