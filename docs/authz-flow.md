# IN-Berlin fork — authentication & authorization flow

Pre-code design gate (review requirement). Every `/api/v1` and `/proxy/v1` request
passes through this exact sequence. Deviations are bugs.

## Credential classes

Exactly **one** credential class per request. More than one → `400 ambiguous
credentials`. None → `401`.

| class | transport | who |
|---|---|---|
| `static` | `X-API-Key` matching a YAML environment `token_sha512` | infra, admin, mapping-exporter, metrics, **webui** |
| `webui-act-as` | `static` env with `act_as: true` **+** `X-Teilnehmer: <name>` (+ optional `X-Webui-User`) | web UI acting for an htpasswd-authenticated Teilnehmer |
| `oidc` | `Authorization: Bearer <JWT>` (authentik access token) | admins now, Teilnehmer later |
| `tn-key` | `X-API-Key` matching a hashed per-Teilnehmer key in SQLite | member automation (ACME, octoDNS) |

`X-API-Key` lookup order: static env map first (config-defined, sha512), then
`tn-key` store. A `static` env without `act_as` carrying `X-Teilnehmer` or
`X-Impersonate-Teilnehmer` → `403` (never ignored). `tn-key` carrying either
header → `403`. Duplicate identity headers → `400`.

## Sequence (per request)

```
request
  │ 1. credential resolution (IdentityMiddleware)
  │    - collect: X-API-Key?, Authorization: Bearer?, X-Teilnehmer?,
  │      X-Impersonate-Teilnehmer?, X-Webui-User?
  │    - >1 credential class → 400; none → 401 (except /proxy/v1/health, /)
  │ 2. authentication
  │    - static: sha512(token) in config.token_env_map
  │    - tn-key: sha512(key) in api_key store (constant-time, prefix-indexed,
  │      not revoked)
  │    - oidc: validate JWT — exact iss, aud required, alg allowlist (RS256/ES256),
  │      exp/nbf ± skew 60s, JWKS cache (TTL, refresh-on-unknown-kid, single-flight)
  │ 3. identity construction (Identity object)
  │    - kind, actor (env name | canonical TN | oidc sub), display name,
  │      effective_teilnehmer, impersonator, webui_user, is_admin
  │    - webui-act-as: effective = canonicalize(X-Teilnehmer); missing header → 400
  │    - oidc admin (admin_group ∈ groups claim): may set X-Impersonate-Teilnehmer
  │      → effective = canonicalize(header); non-admin with header → 403
  │    - canonicalization of TN ids: lowercase, NFC
  │ 4. environment synthesis (authz.py) — only for TN-scoped identities
  │    - zones = mapping[effective_tn] + override grants for effective_tn
  │    - implicit subzones: each owned zone gets subzones=True
  │    - deny set: configured infra zones removed unconditionally
  │    - admins/static envs keep their YAML-defined environment
  │    - result: ephemeral ProxyConfigEnvironment in a request contextvar;
  │      patched get_environment_for_token() prefers the contextvar
  │ 5. per-endpoint authorization (upstream logic, unchanged)
  │    - zone extraction from pdns URL, upstream check_* functions
  │    - zone-ownership resolution for a zone Z:
  │        a. most-specific override grant on Z or ancestor (label-boundary) wins
  │        b. else longest label-suffix owned zone in mapping
  │        c. deny-set zones resolve to nobody
  │        (label-boundary = name == zone or name.endswith("." + zone) on
  │         canonicalized names — never raw string suffix)
  │ 6. journal intent (JournalMiddleware, mutating /api/v1 only)
  │    - pre-GET affected state from upstream
  │    - INSERT journal row status=pending (fail-closed: SQLite unwritable → 503,
  │      request NOT forwarded)
  │ 7. strip proxy identity headers; forward to pdns (upstream X-API-Key only)
  │ 8. finalize: post-GET authoritative after-state
  │    - success → status=committed ; post-GET/DB failure → status=uncertain
  ▼
response
```

## Secrets hygiene

Plaintext TN keys exist only in the mint response. Never in SQLite (hash only),
journal `raw_request`, logs, or tracebacks. Enforced by test.

## Later OIDC migration

`teilnehmer_identity` bridge table (canonical name ↔ OIDC `sub`) exists from day 1;
when Teilnehmer move to authentik, `sub` resolves through it to the same canonical
name — keys, journal, mapping unaffected.
