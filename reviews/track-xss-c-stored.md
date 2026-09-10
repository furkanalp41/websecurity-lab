# Review: batch/track-xss-c-stored (PR #17) — PASS

**Auditor:** denetle (max effort) · **Head:** 161c30f · **Base:** main (323cd9d, clean ancestor)
**Lab:** `stored-xss-comment-plain` (apprentice) — first STORED XSS + first non-Flask stack (Django 5.2.17 + Postgres 16).

## Verdict: PASS — cleared to merge. No blocking findings. The flagged catalog near-miss is verified clean.

## Your flagged catalog near-miss — VERIFIED RESOLVED
`git diff main..HEAD -- data/catalog.json` touches ONLY the `stored-xss-comment-plain` entry (Django 5.0→5.2, gunicorn 22→23, nginx/Puppeteer/Node-collector → xss-verifier + stdlib collector; rewritten description/objective/flag_hint). NO other lab's Django version or catalog entry changed — the over-broad-sed collateral revert was complete. Clean.

## First non-Flask stack (Django under read_only) — posture sound
Posture PASS all 4 (app=app/10001, db=70:70, collector=app/10001, bot=botuser; read_only, cap_drop:ALL, no-new-privileges, bot CapAdd=null). Django hardening verified: **DEBUG=False** (a 404 leaks no traceback/settings/debug page), minimal MIDDLEWARE (CommonMiddleware only — no auth/session/CSRF; the "admin" gate is a custom cookie), migrations run at entrypoint against Postgres, `--workers 2` is fine here (state is in Postgres, ADMIN_SESSION is env — no in-process queue). SECRET_KEY is a benign lab default (no signed sessions/CSRF use it; gitleaks clean). ALLOWED_HOSTS=* acceptable for a loopback/backend-only lab.

## `|safe` is the ONLY injection path — confirmed
- moderate.html renders `{{ c.body|safe }}` (the sink); `{{ c.author }}` stays autoescaped.
- index.html renders `{{ c.body }}` ESCAPED (no |safe) and only shows `approved=True` comments; the attacker's comment is `approved=False`, so it never renders there.
- ORM is parameterized: a single-quote comment body (`o'brien`) stores cleanly (HTTP 200), no SQL error — no SQLi surface, so the Postgres role (blog) is not reachable for anything beyond comment storage.

## Stored-XSS delivery + source≠sink — VERIFIED
Bot uses `XSSBOT_FIXED_URL=/admin/moderate` (no queue). `/admin/moderate` is cookie-gated (403 with no cookie AND with a wrong cookie); `/internal/bot-login` 403 from public. So the attacker plants via public `POST /comment` but can NEVER load the page they attack — the admin bot renders it. Intended exploit (stored `<img onerror>` → bot moderates → document.cookie exfil → collector → /oob/received → /solve) exit 0, session + flag == my independent HMAC. checker green via `$1`. Real browser execution of a PERSISTED payload — the verifier's value is exactly this.

## Django 5.2.17 pin — affirmed
trivy library gate: Django 5.2.17 = 0, gunicorn 23 = 0, psycopg[binary] 3.2.3 = 0 (lib_exit=0), os=0. 5.1.x is security-EOL and (per your live finding) trips the gate; 5.2.17 LTS is clean. Matches the sqli-django-extra-orm precedent. Good.

## Everything else — green
app 172.9 MB, no baked flag, LAB_USER_SECRET unset on the app process (/proc/1/environ count 0), egress-drop (db→1.1.1.1 + bot→1.1.1.1 both blocked), drift-lint 29, format/typecheck/dockerfile-pin/gitleaks/meta-schema green. Flag+ADMIN_SESSION HMAC-derived per-slug. Scope clean (lab dir + CHANGELOG/catalog/docs).

## Observations
None blocking. The lab is a clean first-stored-XSS / first-Django implementation; the transparency on the sed near-miss + the EOL-Django bump were both handled well. (Track-wide OBS-2/OBS-3 from batch-a — bot-base CI caching + documenting the websec-lab/ vs xssbot/ infra-exempt convention — still pending your infra touch; no new instance here.)

Solid. XSS 4/26 after merge.
