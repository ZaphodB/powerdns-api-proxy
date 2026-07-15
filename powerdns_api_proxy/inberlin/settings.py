"""Settings for the IN-Berlin extension, read from the `inberlin:` block of the
same YAML file upstream loads (PROXY_CONFIG_PATH). Absent block = extension off,
upstream behavior unchanged.
"""

import os
from functools import lru_cache
from pathlib import Path
from typing import Optional

from pydantic import BaseModel
from yaml import safe_load


class OIDCSettings(BaseModel):
    issuer: str
    audience: str
    jwks_url: str = ""  # derived from issuer discovery if empty
    admin_group: str = "dns-admins"
    username_claim: str = "preferred_username"
    groups_claim: str = "groups"
    algorithms: list[str] = ["RS256", "ES256"]
    leeway_seconds: int = 60
    jwks_ttl_seconds: int = 3600


class RegistrationSettings(BaseModel):
    """Template for /proxy/v1/register zone creation (registrar role).
    pdns synthesizes the SOA (default-soa-content) and NS rrsets from the
    nameservers list."""

    nameservers: list[str]
    kind: str = "Native"


class InBerlinSettings(BaseModel):
    enabled: bool = True
    state_db: str = "/var/lib/pdns-api-proxy/state.sqlite"
    oidc: Optional[OIDCSettings] = None
    deny_zones: list[str] = []
    # environment name -> roles (admin | exporter | webui | metrics | registrar)
    environment_roles: dict[str, list[str]] = {}
    # required for /proxy/v1/register; absent = registration disabled (501)
    registration: Optional[RegistrationSettings] = None
    journal_retention_days: int = 730
    upstream_server_id: str = "localhost"
    max_keys_per_teilnehmer: int = 10
    rate_limit_auth_failures_per_minute: int = 30
    rate_limit_mutations_per_minute: int = 120
    # Global cap across ALL act-as mutations (contains a compromised/buggy UI
    # backend; per-member limits are fairness, not a security boundary).
    rate_limit_webui_global_mutations_per_minute: int = 600
    # If non-empty, the webui act-as token is only accepted from these client
    # IPs. On the wg overlay, source IPs are enforced by cryptokey routing
    # (peers cannot spoof each other), so this binds the token to the UI host.
    webui_source_ips: list[str] = []


@lru_cache(maxsize=1)
def load_inberlin_settings(path: Optional[Path] = None) -> Optional[InBerlinSettings]:
    """Parse the `inberlin:` block from PROXY_CONFIG_PATH (or explicit path).

    Returns None when the block is absent or `enabled: false` — the extension
    is then fully off. Cached; reload.py clears via reset_settings_cache().
    """
    if not path:
        env_path = os.getenv("PROXY_CONFIG_PATH")
        if not env_path:
            return None
        path = Path(env_path)
    with open(path, encoding="utf-8") as f:
        data = safe_load(f) or {}
    block = data.get("inberlin")
    if not block:
        return None
    settings = InBerlinSettings(**block)
    return settings if settings.enabled else None


def reset_settings_cache() -> None:
    load_inberlin_settings.cache_clear()
