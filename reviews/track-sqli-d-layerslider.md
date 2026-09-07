# Review: batch/track-sqli-d-layerslider (PR #8) — PASS

**Auditor:** denetle (independent adversarial verification) · **Head:** c4d86ae · **Base:** main (86f1a03, clean ancestor)
**Lab:** `sqli-layerslider-unauth-time-blind` — first PHP/Apache/MariaDB lab, first WAF-bypass lab, elite. Abstracts CVE-2024-2879 (LayerSlider).

## Verdict: PASS — cleared to merge. No blocking findings; two cosmetic, non-blocking observations noted below.

## Scope
Clean: new lab dir + exactly three expected repo touchpoints (CHANGELOG.md, data/catalog.json Hybrid reconcile, docs/tracks/sqli.md). No scope leak.

## Live mechanism verification (the elite / novel surface)
- **WAF blocks the loud tokens (live, correct rule IDs):** bare `SLEEP(`→403/942160, `UNION SELECT`→403/942100, `information_schema`→403/942190, `OR 1=1`→403/942200.
- **Intended bypass executes:** `SLEEP/**/(0.6)` runs in MariaDB 11.4 — TRUE(1=1)=**1.20s** vs FALSE(1=2)=**0.003s**. The IGNORE_SPACE / comment-as-separator question is settled empirically: the comment is accepted between function name and paren. (Measured delay ≈2× the injected 0.6s — the uncorrelated subquery is evaluated more than once across the 3-row `wp_ls_sliders` scan; harmless, widens the oracle margin.)
- **Pure timing oracle confirmed:** TRUE ≡ FALSE ≡ baseline response body, both HTTP 200 — zero boolean/error/content channel. `get_row` swallows SQL errors; row is ignored.
- **Exploit recovers the REAL per-container secret:** DB ground truth `user_pass=ed71dfa3996db6ac` (read directly via docker exec) == exploit-recovered value (attempt 1). Flag `FLAG{95a9…657e}` == independently computed `hmac_sha256(key=LAB_USER_SECRET, "v1|"+slug)`. **exit 0 in 21.8s** (<60s). checker: solved.

## Security posture / infra (all green)
- Posture gate PASS on **both** containers: app `User=app`(10001), db `User=999:999`, read_only, cap_drop:ALL, no-new-privileges:true, pids_limit+mem_limit, app port loopback-only (127.0.0.1), **DB publishes no host port**, tmpfs datadirs (mysql uid 999).
- No baked flag: image fs export grep `FLAG{` = 0, `flag.txt` absent from image; flag lives only on `/var/lib/lab` tmpfs at runtime. entrypoint derives via HMAC and `unset LAB_USER_SECRET` before Apache starts.
- Image 26.4 MB (<300). Dockerfile alpine digest-pinned, single-stage (no build step), non-root USER.
- trivy two-call: **library HIGH,CRITICAL = 0** (no vendored deps), **os CRITICAL = 0** (alpine 3.20.10). gitleaks: 38 commits, no leaks.

## Repo gates (all exit 0)
catalog drift-lint (19 implemented; catalog tech_stack now byte-matches meta after Hybrid reconcile) · map · typecheck (5 workspace projects) · format:check · dockerfile digest-pin (19) · meta.json schema-valid (draft 2020-12), id==dir==slug.

## Docs / pedagogy
SOLUTION: 8 WHY-sections, 3 payload vectors (subquery SLEEP / IF+SLEEP / heavy-compute), OWASP A03:2021 + CWE-89 + CVE-2024-2879, fix rationale (bind `%d`, gate `wp_ajax_nopriv_*`, WAF is defence-in-depth), all three deviations documented (16-hex user_pass, app-level CRS homage, in-process `/solve`). Hints 1-3 progressive. Catalog reconcile honestly corrected the stale `give-flag.sh` flag_hint to the real `POST /solve {hash}` mechanism.

## Non-blocking observations (courtesy — not backlog items)
- OBS-1 `src/lib/waf.php:31-32`: comment says "fold case so keyword casing tricks alone do not evade", but `$v` is not lowercased; case-insensitivity is (correctly) provided by the `/i` regex flag. Behaviour is right; only the comment is slightly misleading.
- OBS-2 `SOLUTION.md` / `hints/3.md`: injected `SLEEP/**/(0.6)` measures ~1.2s live (subquery evaluated >1×). Already hedged as "~0.6s or more"; no change needed.
