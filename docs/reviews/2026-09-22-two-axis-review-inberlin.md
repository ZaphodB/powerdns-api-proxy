# Two-axis code review — IN-Berlin branch, 2026-09-22

Scope: `git diff main...HEAD`, merge-base `18b4ca3` → HEAD `e061627` (45
commits, 52 files, +7411/-9). First whole-branch review since rounds 12-17.
318 unit tests green at review time.

Standards sources: none documented in the repo; tooling-enforced rules
(ruff, ruff-format, pyupgrade, mypy) skipped. Fowler smell baseline applied —
every Standards finding is a judgement call, none are hard violations.

Spec sources: `docs/api-contract.md`, `docs/authz-flow.md`, the original plan
(`jolly-cooking-glacier.md`, not in-repo), README "Zone metadata", plus later
owner decisions (owners get full control of owned zones; OIDC-only key
minting; `webui_source_ips` fail-closed; member metadata admin-only; register
not restricted to in-berlin.de).

Items fixed or refuted in `2026-07-25-two-axis-review-inberlin.md` were not
re-reported. Resolutions are listed at the end.

## Standards (12 judgement calls)

- **S1 Mysterious Name** — tn→user rename leftovers (not wire names):
  `router.py` `tn_filter` (245, 249); `middleware.py` `x_tn` (123 + uses);
  "TN key" docstrings `keys.py:19`, `middleware.py:96`.
- **S2 Duplicated Code** — `GenerationMismatch` → 409 handler ×4
  (`router.py` 101, 119, 181, 197); `DuplicateZoneOwner` → 422 ×2.
- **S3 Duplicated Code** — `journal_finalize(..., after_state=None,
  rollbackable=False)` ×4 in `journal.py` (639, 657, 668, 707).
- **S4 Duplicated Code** — current-generation SELECT + CAS repeated
  (`store.py` 117-122, 217, 303-309).
- **S5 Duplicated/dead code** — identity header list spelled out 3×
  in `middleware.py`; `IDENTITY_HEADERS` (:34) is unreferenced anywhere
  (verified). `request.client.host if request.client else …` ×3.
- **S6 Duplicated Code (minor)** — record shape in `rollback.py` 454/480;
  aiohttp GET-json block in `oidc.py` 310/334; `pdns` import + `server_id`
  boilerplate in 4 router handlers.
- **S7 Primitive Obsession** — journal status strings scattered;
  `ResolveBody.status: str` (`router.py:297`) hand-validated where
  `Literal["committed", "failed"]` would do.
- **S8 Repeated Switches** — `router.py` 343/393 branch on operation name
  for admin-only/lossy flags (belong in `OpSpec`); three shapes of role gate
  (`_require_exporter_or_admin`, inline :417, inline :587).
- **S9 Convention drift** — fork tests use `test_*.py`, upstream `*_test.py`;
  four test files named after reviewers (`test_{deepseek,hy3,kimi,sol}_review_round.py`)
  instead of behaviour.
- **S10 Stale comments** — `store.py:80` op list lacks `zone-metadata`;
  `settings.py` "If non-empty…" wording predates fail-closed (see P8).
- **S11** — `config.py:219` `except ZoneNotAllowedException: pass` redundant
  before bare `except Exception: pass` (verified).
- **S12** — `KNOWN_ROLES as KNOWN` alias (`settings.py:13`); untyped
  `settings`/`config` params (`runtime.py` 127, 154; `reload.py:345`).

## Spec (3 partial, 1 nothing new, 1 wrong, 5 doc drift)

### Missing / partial

- **P1** — plan D4: "raw header stored separately for forensics". Journal
  stores only canonical `user`/`actor`/`impersonator`/`webui_user`; raw
  `X-Teilnehmer` / `X-Impersonate-Teilnehmer` dropped after
  `canonical_user()` (`middleware.py` 182, 239).
- **P2** — plan §A: "pruned to 2 years via built-in daily task + incremental
  vacuum". No vacuum / `auto_vacuum` anywhere (verified): the DB file never
  shrinks and `inberlin_journal_db_bytes` never falls after a prune.
- **P3** — plan §A: "startup verifies snapshot/entry generation match".
  `load_mapping` (`store.py:216`) does no cross-check. Low risk — both are
  written in one transaction.

### Scope creep

- **P4** — only items already accepted in the 2026-07-25 review.

### Implemented but wrong

- **P5** — plan D4: "header from any other credential → 403 (never silently
  ignored/forwarded)". `X-Webui-User` on a static / tn-key / OIDC credential
  is silently ignored (read only on the webui path, verified); only
  `X-Teilnehmer` / `X-Impersonate-Teilnehmer` are refused. Stripped before
  forwarding, so low impact.

### Doc drift

- **P6** — `authz-flow.md:14,19` "`static` env with `act_as: true`" and
  `api-contract.md:8` "static env with `admin: true` capability": neither key
  exists; code uses `inberlin.environment_roles` (verified).
- **P7** — `api-contract.md:31` "`X-Impersonate-Teilnehmer` — ADM only", but
  a static admin env sending it gets 403 (`middleware.py:191`); authz-flow
  (OIDC admins only) matches the code, the contract is wrong.
- **P8** — `authz-flow.md` and `authz.py:12` still call member metadata an
  open decision (owner decided admin-only); `settings.py` comment on
  `webui_source_ips` contradicts fail-closed.
- **P9** — `api-contract.md` error shapes omit 422, 429, 502, 501; mapping
  PUT row omits `orphaned_overrides`.
- **P10** — `authz-flow.md` lists only `/proxy/v1/health` and `/` as
  auth-exempt; code also exempts `/health/pdns` and `/metrics`.

## Summary

Standards: 12 judgement calls, worst S5 (dead `IDENTITY_HEADERS` + header
list triplicated — the next header added will miss one copy). Spec: 10
findings, no security gap; worst P5 (plan's "never silently ignored" rule
broken for `X-Webui-User`).

## Resolution (same day)

| Finding | Commit | Result |
|---|---|---|
| P6–P10, S10 | `2a0e198` | Docs and comments corrected to match code and owner decisions |
| P5 | `31981e0` | `X-Webui-User` on static / tn-key / OIDC → 403 (behavior change) |
| P2 | `d535cb1` | `auto_vacuum=INCREMENTAL` (existing DBs converted by one VACUUM on open); prune runs `incremental_vacuum` |
| P1 | `7ce523e` | New journal column `raw_user_header` (added by `ALTER TABLE` on open); in list view |
| S1–S8, S11, S12 | `24d000e` | Refactors; one wire change: invalid resolve `status` → 422 (was 400) |
| P3 | — | Not fixed: snapshot and entries are written in one transaction, so a startup cross-check guards nothing that can happen |
| P4 | — | Nothing to do |
| S9 | — | Not fixed: renaming test files is churn with no behavior value |

Suite: 325 unit tests green after the last commit. Deploy-relevant: P5, P2
(first start runs a VACUUM on the state DB), P1 (schema migration), and the
resolve 422 — all need a redeploy of ans0 at a new `pdns_api_proxy_ref`.
