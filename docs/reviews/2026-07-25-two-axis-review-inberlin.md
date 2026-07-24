# Two-axis code review — IN-Berlin branch, 2026-07-25

Review of `git diff main...inberlin` (20 commits, 29 files, +4331/-3) along two
axes, run as parallel sub-agents per the code-review skill:

- **Standards** — repo-documented conventions (none exist — no
  CODING_STANDARDS/CONTRIBUTING/AGENTS.md, no README style section) plus the
  Fowler smell baseline; tooling-enforced classes (ruff, mypy, pyupgrade,
  black) skipped.
- **Spec** — conformance against `docs/api-contract.md` + `docs/authz-flow.md`.

All 16 findings were implemented in this branch (spec fixes TDD red/green,
standards refactors behavior-preserving with the suite green throughout).
197 unit tests pass, `pre-commit run --all-files` clean.

Resolution commits:

- `cbfd1ef` fix: spec-axis review findings (round 8)
- `08a08ee` refactor: standards-axis review findings (round 8)

## Spec findings (9) — all fixed

1. **Overrides endpoints dropped the contract's mandatory CAS** (contract
   lines 41-42: `If-Match: <generation>` on POST/DELETE). There was no CAS at
   all — an override could silently race an exporter full-replace.
   → POST/DELETE `/proxy/v1/overrides` now require If-Match (400 missing, 409
   stale) and override writes CAS-bump the shared mapping generation in the
   same store transaction (`Store._bump_generation`).
2. **TN environments granted cryptokey rights the spec never gave**
   (`authz.py` set `admin=True, cryptokeys=True`; authz-flow.md §4 grants
   zones + `subzones=True` only).
   → grants stripped. **Behavior change:** member zone create/delete and
   DNSSEC key management via `/api/v1` are now 403; the zone-delete rollback
   flow is admin-driven.
3. **GET /proxy/v1/mapping response shape diverged** (contract line 38:
   `{generation, applied_at, mapping}`; code returned `{generation, mapping,
   overrides}`, never surfacing the persisted `applied_at`).
   → contract shape restored; `applied_at` threaded store → MappingView →
   response. Overrides remain available via GET `/proxy/v1/overrides`.
4. **/journal/uncertain omitted live upstream state** (contract line 46).
   → response gains an `upstream` map: live zone JSON per affected zone,
   `null` when the zone is gone, `{"error": ...}` on fetch failure.
5. **Journal DB size gauge missing from /metrics** (contract lines 57-58;
   size was only in the `/proxy/v1/ready` JSON body).
   → `inberlin_journal_db_bytes` gauge via a Prometheus collector registered
   at import; resolves the runtime at scrape time, absent beats wrong.
6. **Zone-delete rollback not flagged as lossy** (contract lines 79-80:
   DNSSEC/catalog exclusion "flagged in response").
   → rollback response gains `lossy: true` + `lossy_detail` for zone-delete
   entries.
7. **webui act-as without X-Teilnehmer returned 403** (authz-flow.md line 40:
   missing header → 400). → 400.
8. **GET /keys field name** (contract line 49: `prefix`; code returned
   `key_prefix`). → `prefix` (DB column unchanged).
9. **Duplicate X-API-Key not rejected** (authz-flow.md line 21: duplicate
   identity headers → 400; only the X-* headers were checked).
   → duplicate `X-API-Key` and `Authorization` also → 400.

**Scope creep noted, deliberately kept** (additive, harmless):
`orphaned_overrides` in mapping PUT/PATCH responses, `display` in whoami,
per-IP auth-failure rate limiting beyond the specified caps.

**Verified correct by the reviewer:** register semantics (409/403/501,
concurrent-map 409, `mapping_generation: null`, journaled against User),
OIDC-only key minting (act-as/key → 403), TN-key exclusion from
journal/rollback, ready authz ADM/EXP/MET, journal fail-closed 503, rollback
drift/force/current-authz semantics, `{"error": ...}` error shape.

## Standards findings (7) — all fixed (judgement calls, no hard violations)

1. **Duplicated Code** — the journaled-execution shape (intent → zone lock →
   forward → finalize, uncertain on exception) existed 3× with drifting
   details (JournalMiddleware, rollback, register).
   → one `run_journaled()` in journal.py; callers pass `forward`,
   `status_of`, optional `before_intent` (rollback's drift check) and
   `rollback_of`; `None` return = intent failed → caller's own 503.
2. **Repeated Switches + Shotgun Surgery** on the operation literal
   (`rrset-patch`/`zone-create`/… switched on in classify, intent, finalize,
   build_rollback_request, and the router drift cascade).
   → `OPERATIONS` OpSpec table (secret / pre_get / rrset_diff / recreate /
   restore_from_before) drives intent+finalize; the drift cascade moved to
   `rollback.check_entry_drift` beside the inverse table. Adding an op = one
   table row + one inverse.
3. **Inconsistent union syntax** (`Optional[str]` vs `str | None` in adjacent
   signatures). → unified to `X | None` package-wide (pyupgrade --py310-plus).
4. **Duplicated token-hash logic** (sha512 in middleware with a function-level
   import, and keys._sha512). → one public `keys.sha512`; upstream
   `config.get_environment_for_token` left untouched (pre-existing).
5. **Middle Man** — `_identity_admin()` wrapped two helpers, used once.
   → inlined at `admin_reload`.
6. **Data Clumps / Primitive Obsession** — `journal_intent` took 5 Identity
   fields among 13 kwargs; `classify()` returned `dict[str, Any]`; role
   literals repeated across files.
   → `journal_intent(identity, ...)`; `classify()` returns `OpInfo`
   NamedTuple; role names are constants in `roles.py`.
7. **Mysterious Name** — internals said `tn` while the public surface says
   `user` (post-6136e76).
   → internals renamed (`canonical_user`, `zones_by_user`, `_require_user`,
   `Identity.effective_user`, `journal_user_ts` index, `user:{user}` env
   names). **Wire names unchanged:** `X-Teilnehmer`,
   `X-Impersonate-Teilnehmer`, `tn-key` kind, whoami `effective_teilnehmer`
   key, `max_keys_per_teilnehmer` setting.

## Deploy-relevant behavior changes

Webui/exporter clients must match the corrected contract before rollout:

- overrides POST/DELETE require `If-Match` (400/409)
- GET `/proxy/v1/mapping` shape is `{generation, applied_at, mapping}`
- member zone create/delete and cryptokeys are 403 (registrar + admin only)
- GET `/proxy/v1/keys` list uses `prefix`
- webui token without `X-Teilnehmer` and duplicate credential headers → 400
