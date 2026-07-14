# IN-Berlin proxy API contract (v1)

The web UI and DB exporter code against this document. `/api/v1` remains
PowerDNS-API compatible; everything new lives under `/proxy/v1`.

## Auth classes

- **ADM** — OIDC Bearer with `admin_group`, or static env with `admin: true` capability
- **TN** — effective Teilnehmer: webui act-as (`X-Teilnehmer`) or personal API key
  (key capability set: `/api/v1` DNS ops + read/revoke own keys ONLY)
- **EXP** — static `mapping-exporter` env (capability: mapping endpoints only)
- **MET** — static metrics env

Impersonation: `X-Impersonate-Teilnehmer` — ADM only, journaled with both
identities. `X-Webui-User` — htpasswd login behind the webui token, journaled.

## Endpoints

| Method | Path | Auth | Notes |
|---|---|---|---|
| PUT | `/proxy/v1/mapping` | EXP/ADM | full replace `{"mapping": {"<tn>": ["zone."...]}}`; header `If-Match: <generation>` required, `409` mismatch; returns `{generation}` |
| PATCH | `/proxy/v1/mapping` | EXP/ADM | `{"add": {...}, "remove": {...}}`; `If-Match` required |
| GET | `/proxy/v1/mapping` | ADM | `{generation, applied_at, mapping}` |
| GET | `/proxy/v1/mapping/self` | TN | own zone list incl. override grants |
| GET | `/proxy/v1/overrides` | ADM | list |
| POST | `/proxy/v1/overrides` | ADM | `{zone, teilnehmer, note}`; `If-Match: <generation>` |
| DELETE | `/proxy/v1/overrides/{id}` | ADM | `If-Match` |
| GET | `/proxy/v1/journal` | TN/ADM | filters `zone,name,type,since,until,limit,offset`; `teilnehmer=` ADM-only (TN → 403) |
| GET | `/proxy/v1/journal/{id}` | TN/ADM | full entry incl. before/after, `rollbackable` |
| POST | `/proxy/v1/journal/{id}/rollback` | TN/ADM | `409` drift vs recorded after; body `{"force": true}` ADM-only; requires *current* authz on zone; returns new journal id |
| GET | `/proxy/v1/journal/uncertain` | ADM | pending/uncertain rows + live upstream state for reconciliation |
| POST | `/proxy/v1/journal/{id}/resolve` | ADM | finalize an uncertain row (`{"status": "committed"|"failed"}`), audited |
| GET | `/proxy/v1/keys` | TN | own keys: id, prefix, label, created_at, revoked_at |
| POST | `/proxy/v1/keys` | TN (session: act-as or OIDC; **not** a key) | `{label}` → `{id, key}` — plaintext exactly once |
| DELETE | `/proxy/v1/keys/{id}` | TN/ADM | revoke; TN only own |
| GET | `/proxy/v1/whoami` | any authenticated | `{kind, actor, effective_teilnehmer, is_admin, impersonator, webui_user}` |
| GET | `/proxy/v1/health` | none | liveness only, no internals |
| GET | `/proxy/v1/ready` | ADM/EXP/MET | upstream reachability, mapping generation, journal writability |
| POST | `/proxy/v1/admin/reload` | ADM | reload static YAML (= SIGHUP) |

Metrics stay on upstream's `/metrics` (basic auth, `metrics_proxy` env) plus
journal DB size gauge.

## Error shapes (proxy-originated)

PowerDNS-style body `{"error": "<detail>"}`:

- `400` ambiguous/duplicate credentials, malformed identity header, missing If-Match
- `401` no/invalid credential
- `403` credential class not allowed for endpoint/header, zone not owned, TN scope
- `409` mapping/override generation mismatch; rollback drift
- `503` journal unwritable (fail-closed; mutation NOT forwarded)

## `/api/v1` compatibility matrix

Forwarded and covered by tests: servers, zones CRUD, RRset PATCH, notify, rectify,
search-data, cryptokeys, tsigkeys (per upstream v1.11.1 surface). Proxy additions:
authz may `403` requests upstream would accept; mutating requests may `503`
(journal fail-closed). Headers: proxy strips `X-Teilnehmer`,
`X-Impersonate-Teilnehmer`, `X-Webui-User`, `Authorization` before forwarding;
upstream sees only the proxy's own `X-API-Key`. Response bodies/status codes
otherwise pass through unchanged. Cryptokey/tsigkey mutations are journaled
metadata-only (no payloads) and are not rollbackable. Zone delete is rollbackable
via recreate-from-export (DNSSEC/catalog state excluded — flagged in response).
