# IN-Berlin proxy API contract (v1)

The web UI and DB exporter code against this document. `/api/v1` remains
PowerDNS-API compatible; everything new lives under `/proxy/v1`.

## Auth classes

Static environments get their class from `inberlin.environment_roles`
(`{<env name>: [<role>...]}`, roles `admin` | `exporter` | `webui` | `metrics` |
`registrar`; unknown role names fail config load). A static env with no role
is a plain upstream environment, untouched by the extension.

- **ADM** — OIDC Bearer with `admin_group`, or a static env with role `admin`
- **TN** — effective User. Two sub-classes:
  - **TN-session** — webui act-as (`X-Teilnehmer`) or OIDC. Full member surface:
    DNS ops, journal read, rollback, key mint/list/revoke.
  - **TN-key** — a personal API key. Capability set is deliberately narrow:
    `/api/v1` DNS ops + list/revoke own keys ONLY. Journal read, rollback and
    key minting require a session (a compromised automation key must not be able
    to audit history, undo changes, or mint more keys). Endpoints below marked
    **TN-session** reject a `tn-key` with 403.
- **EXP** — static env with role `exporter` (capability: mapping endpoints only)
- **REG** — static env with role `registrar` (capability: `/proxy/v1/register` ONLY —
  create-only by construction: no `/api/v1`, no reads, no mutation of existing
  zones; pdns's unconditional 409 on duplicate zone create is the backstop).
  The registrable NAMESPACE is deliberately unrestricted: this endpoint serves
  the member-database/DENIC flow, where members register their own domains
  (any TLD), so constraining it to `in-berlin.de` would break its purpose. The
  deny lists, the mapping and pdns's duplicate-create 409 are the limits; the
  caller is trusted to decide WHICH name a member may have.
  Enforced by an explicit credential gate: REG, EXP and MET are refused on
  `/api/v1` with `403 credential not allowed on the PowerDNS API`, rather
  than relying on the environment having an empty zone list
- **MET** — static env with role `metrics`

Impersonation: `X-Impersonate-Teilnehmer` — OIDC admins only (a static admin
env sending it gets `403`), journaled with both identities. `X-Webui-User` — htpasswd login behind the webui token, journaled.

The webui act-as token is additionally **bound to configured source IPs**
(`webui_source_ips`): on the WireGuard overlay, cryptokey routing makes peer
source IPs unforgeable, so the token is unusable from any host but the UI
host even if leaked. **Fail-closed:** an empty `webui_source_ips` refuses the
act-as credential entirely (403) — the setting is a deploy requirement, not
an optional hardening. A global mutation rate cap applies across all act-as
traffic on top of per-member limits.

## Endpoints

| Method | Path | Auth | Notes |
|---|---|---|---|
| PUT | `/proxy/v1/mapping` | EXP/ADM | full replace `{"mapping": {"<tn>": ["zone."...]}}`; header `If-Match: <generation>` required, `409` mismatch; returns `{generation, orphaned_overrides}` |
| PATCH | `/proxy/v1/mapping` | EXP/ADM | `{"add": {...}, "remove": {...}}`; `If-Match` required; returns `{generation, orphaned_overrides}` |
| GET | `/proxy/v1/mapping` | ADM | `{generation, applied_at, mapping}` |
| GET | `/proxy/v1/mapping/self` | TN | own zone list incl. override grants |
| GET | `/proxy/v1/overrides` | ADM | list |
| POST | `/proxy/v1/overrides` | ADM | `{zone, user, note}`; `If-Match: <generation>` |
| DELETE | `/proxy/v1/overrides/{id}` | ADM | `If-Match` |
| GET | `/proxy/v1/journal` | TN-session/ADM | filters `zone,name,type,since,until,limit,offset`; `user=` ADM-only (TN → 403) |
| GET | `/proxy/v1/journal/{id}` | TN-session/ADM | full entry incl. before/after, `rollbackable` |
| POST | `/proxy/v1/journal/{id}/rollback` | TN-session/ADM | `409` drift vs recorded after; body `{"force": true}` ADM-only; requires *current* authz on zone; returns new journal id |
| GET | `/proxy/v1/journal/uncertain` | ADM | pending/uncertain rows + live upstream state for reconciliation |
| POST | `/proxy/v1/journal/{id}/resolve` | ADM | finalize an uncertain row (`{"status": "committed"|"failed"}`), audited |
| POST | `/proxy/v1/register` | REG/ADM | `201` on success. `{zone, user}` → create zone from configured template (kind + nameservers, SOA synthesized by pdns) + mapping entry, journaled against the User; `409` zone owned or exists upstream, `403` deny-set, `501` template unconfigured; returns `{zone, user, journal_id, mapping_generation}` (`mapping_generation: null` = zone created but mapping update failed — exporter heals; `409` "zone created but concurrently mapped to another User" = zone exists, mapping conflict needs resolution). Rolling back the zone-create (admin-only) deletes the zone but leaves the mapping entry — the next exporter full-replace heals it |
| GET | `/proxy/v1/keys` | TN | own keys: id, prefix, label, created_at, revoked_at |
| POST | `/proxy/v1/keys` | TN **OIDC session only** (admin impersonation now, member OIDC later; act-as and keys → 403) | `{label}` → `{id, key}` — plaintext exactly once. Act-as minting removed 2026-07-15 (luna review): a compromised UI host must not mint persistent per-member credentials |
| DELETE | `/proxy/v1/keys/{id}` | TN/ADM | revoke; TN only own |
| GET | `/proxy/v1/whoami` | any authenticated | `{kind, actor, effective_teilnehmer, is_admin, impersonator, webui_user}` |
| GET | `/proxy/v1/health` | none | liveness only, no internals |
| GET | `/proxy/v1/ready` | ADM/EXP/MET | upstream reachability, mapping generation, journal writability |
| POST | `/proxy/v1/admin/reload` | ADM | reload static YAML (= SIGHUP) |

Metrics stay on upstream's `/metrics` (basic auth, `metrics_proxy` env) plus
journal DB size gauge.

## Error shapes (proxy-originated)

PowerDNS-style body `{"error": "<detail>"}`:

- `400` ambiguous/duplicate credentials, conflicting identity headers (X-Teilnehmer + X-Impersonate-Teilnehmer), missing If-Match
- `401` no/invalid credential
- `403` credential class not allowed for endpoint/header, zone not owned, TN scope
- `404` unknown journal entry/override/key; extension disabled on `/proxy/v1`
- `409` mapping/override generation mismatch; duplicate override; rollback drift;
  entry not rollbackable/not pending; zone owned or exists (register); key limit;
  concurrent reload
- `422` mapping assigns one zone to two Users
- `429` rate limited (auth failures per IP, mutations per User, webui global cap)
- `501` registration template not configured
- `502` upstream unreachable/rejected during rollback drift check, rollback or
  register zone create
- `503` journal unwritable (fail-closed; mutation NOT forwarded); upstream
  unreachable where the proxy must verify state first (register)

Unauthenticated paths: `/`, `/proxy/v1/health`, `/health/pdns`, `/metrics`
(the last has its own HTTP Basic auth, see above).

## `/api/v1` compatibility matrix

Forwarded and covered by tests: servers, zones CRUD, RRset PATCH, notify, rectify,
search-data, cryptokeys, tsigkeys (per upstream v1.11.1 surface), plus zone
metadata (`/zones/<z>/metadata[/<kind>]`), which upstream does not route at all.
Metadata needs its own grant (`global_metadata`, or `metadata: true` on the zone)
and is journaled as `zone-metadata`, not rollbackable. Proxy additions:
authz may `403` requests upstream would accept; mutating requests may `503`
(journal fail-closed). Headers: proxy strips `X-Teilnehmer`,
`X-Impersonate-Teilnehmer`, `X-Webui-User`, `Authorization` before forwarding;
upstream sees only the proxy's own `X-API-Key`. Response bodies/status codes
otherwise pass through unchanged. Cryptokey/tsigkey mutations are journaled
metadata-only (no payloads) and are not rollbackable. Zone delete is rollbackable
via recreate-from-export (DNSSEC/catalog state excluded — flagged in response).
