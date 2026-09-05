# Review — `arch-000-r1` (re-review)

- **Reviewer:** denetle (AUDITOR)
- **Reviewed commit:** `93b5e1575e9a30ea8072b0fdcb8ebfa69becb33b` (`build/arch-000`; one fix commit atop the merged r0 review `ffe3923`)
- **Prior:** `reviews/arch-000.md` — `pass_with_findings` on `405fa79`
- **Verdict:** ✅ **`pass`**

All 3 `must_fix`, all 5 `nice_to_have`, and all three actioned answers were independently re-verified locally (not read off the evidence). The delta is a single clean commit; the one reference lab was re-run end-to-end (no regression).

## must_fix — verified closed

| ID | Fix | How I verified | Result |
|---|---|---|---|
| **MF-1** posture gate | `scripts/check-posture.sh`, wired in `docker-lab-matrix` right after `compose up --wait` | Ran it on the good sample (**all checks green, exit 0**); ran it on a **root/writable/uncapped** container → **6 FAILs, exit 1**; ran it on a hardened-but-`0.0.0.0`-published container → caught (`HostIp:"0.0.0.0"`) → **FAIL, exit 1** | ✅ gate genuinely fails bad containers |
| **MF-2** digest-pin | `scripts/check-dockerfiles.sh` + standalone `dockerfile-lint` job | Negative test: unpinned `FROM alpine:3.20` → **FAIL exit 1**; pinned + multi-stage alias back-ref → **pass exit 0** | ✅ |
| **MF-3** hub strict | all 7 flags in `hub/tsconfig.json` | grepped all 7 present; **`pnpm --filter hub run typecheck` → exit 0** (flags don't break the hub) | ✅ |

## nice_to_have + answers — verified

- **NTH-1** landing copy now "541 labs" (page.tsx:5 and :62). ✅
- **NTH-2** `build-catalog.ts` now `fail()`s on duplicate slugs (was `console.warn`). ✅ *(trivial: the file's top-of-module docstring still says "Emits a loud WARNING (but does not fail)" — stale comment, cosmetic only.)*
- **NTH-3** tier ceilings recorded in CLAUDE.md (apprentice ≤10 / practitioner ≤30 / expert ≤90 / elite ≤180 min). ✅
- **NTH-4** daemon `verifyClient` carries the ui-phase-2 Origin-exemption note. ✅
- **NTH-5 / Q3** template `entrypoint.sh` writes the flag then `unset LAB_USER_SECRET` before `exec`; confirmed **0 occurrences of `LAB_USER_SECRET` in PID1 env**, and the **exploit still lands** the correct HMAC flag. Comment correctly notes unset alone isn't enough for file-read-class tracks. ✅
- **Q4** both dup slugs uniqued per the approved mapping; catalog **541 total / 541 distinct**, old slugs gone; `build-map` now **541 nodes / 521 edges**. ✅
- **Q5** `docs/ux-hub-spec.json` carries an accurate `_supersede_notice`; **CLAUDE.md Non-goals unchanged** (only the resolved "known issues" entries updated). ✅

## Smoke / regression

Sample lab at r1 rebuilds and reports healthy; intended exploit lands in ~0.13–0.2 s with the correct flag; posture gate green; `main` still an ancestor of `build/arch-000`. No regression. My r0 review file is byte-identical to the version I pushed (restored after a `pnpm format` pass; `reviews/` added to `.prettierignore`).

## Disposition

`arch-000` is cleared to merge to `main`. Track work (Phase 1) may begin. The stale build-catalog docstring (NTH-2) is not blocking — sweep it into the first track batch or a chore commit.
