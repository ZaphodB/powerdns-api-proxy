# IN-Berlin fork — configuration

The extension reads an `inberlin:` block from the same YAML file upstream loads
(`PROXY_CONFIG_PATH`). No block, or `enabled: false`, means the extension is off
and the proxy behaves exactly like upstream. Source of truth for every field:
`powerdns_api_proxy/inberlin/settings.py`.

The Teilnehmer→zone mapping is **not** configured here. It is pushed at runtime
with `PUT`/`PATCH /proxy/v1/mapping` and kept in the state database.

## Example

```yaml
pdns_api_url: "http://192.168.254.1:8081"
pdns_api_token: "<pdns api key>"
metrics_enabled: true
metrics_require_auth: true

environments:
  - name: webui
    token_sha512: "<sha512 hex, lowercase>"
    zones: []
  - name: exporter
    token_sha512: "..."
    zones: []
  - name: admin
    token_sha512: "..."
    global_read_only: false
    zones: []
  - name: registrar
    token_sha512: "..."
    zones: []
  - name: metrics
    token_sha512: "..."
    metrics_proxy: true
    zones: []

inberlin:
  state_db: /var/lib/pdns-api-proxy/state.sqlite
  environment_roles:
    webui: [webui]
    exporter: [exporter]
    admin: [admin]
    registrar: [registrar]
    metrics: [metrics]
  webui_source_ips: ["192.168.254.10"]
  deny_zones: [ns1.in-berlin.de, gitlab.in-berlin.de]
  deny_zones_exact: [in-berlin.de]
  registration:
    kind: Native
    nameservers: [ns1.in-berlin.de., ns2.in-berlin.de.]
  oidc:
    issuer: https://auth.example/application/o/dns/
    audience: dns-proxy
    admin_group: dns-admins
```

Member environments are never written here: they are synthesized per request
from the mapping (see `docs/authz-flow.md` §4).

## Fields

| Field | Default | Meaning |
|---|---|---|
| `enabled` | `true` | `false` turns the extension off with the block still present |
| `state_db` | `/var/lib/pdns-api-proxy/state.sqlite` | SQLite file for mapping, overrides, keys and journal |
| `environment_roles` | `{}` | `{<environment name>: [<role>...]}`. Roles: `admin`, `exporter`, `webui`, `metrics`, `registrar` (see `docs/api-contract.md` for what each may do). Unknown role names, and keys naming no configured environment, fail startup and reload. An environment with no role is a plain upstream environment |
| `webui_source_ips` | `[]` | Client IPs the `webui` token is accepted from. **Empty refuses the token entirely** (fail-closed): this is a deploy requirement |
| `deny_zones` | `[]` | Zones denied to members together with everything below them (infra namespaces) |
| `deny_zones_exact` | `[]` | Zones denied to members, subzones still allowed. For an apex members live under, e.g. `in-berlin.de` |
| `registration` | none | Template for `POST /proxy/v1/register`: `nameservers` (required), `kind` (`Native`). Absent → the endpoint answers `501` |
| `oidc` | none | Bearer-token login. `issuer`, `audience` required; `jwks_url` (discovered from the issuer if empty), `admin_group` (`dns-admins`), `username_claim` (`preferred_username`), `groups_claim` (`groups`), `algorithms` (`RS256`, `ES256`), `leeway_seconds` (60), `jwks_ttl_seconds` (3600) |
| `journal_retention_days` | `730` | Settled journal rows older than this are pruned daily (pending/uncertain rows are kept) |
| `upstream_server_id` | `localhost` | PowerDNS server id used for the proxy's own upstream calls |
| `max_keys_per_teilnehmer` | `10` | Active personal API keys per member |
| `rate_limit_auth_failures_per_minute` | `30` | Per client IP |
| `rate_limit_mutations_per_minute` | `120` | Per member (or per token for non-member credentials) |
| `rate_limit_webui_global_mutations_per_minute` | `600` | All webui act-as mutations combined |

Tokens are stored as sha512 hex digests, lowercase. Compute one without a
trailing newline: `printf %s "$TOKEN" | sha512sum`.

## Reload versus restart

`SIGHUP` or `POST /proxy/v1/admin/reload` re-reads the file. A config that fails
validation is refused as a whole and nothing changes. These fields are baked
into objects built at startup and **only change on restart**; a reload keeps
their running values and logs a warning: `state_db`, `oidc`, `deny_zones`,
`deny_zones_exact`, and the three `rate_limit_*` fields. `pdns_api_url` and
`pdns_api_token` also need a restart. Removing the `inberlin:` block does not
switch a running extension off. The INansible role restarts on every config
change for this reason.
