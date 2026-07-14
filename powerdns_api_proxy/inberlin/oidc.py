"""authentik OIDC access-token validation (docs/authz-flow.md §2).

JWKS cache: bounded TTL, refresh on unknown kid with single-flight, no
fallback to stale keys after a successful refresh, startup tolerant of JWKS
downtime (only OIDC requests fail while unreachable).
"""

import asyncio
import time
from typing import Any, Optional

import aiohttp
import jwt
from jwt import PyJWK

from powerdns_api_proxy.inberlin.settings import OIDCSettings
from powerdns_api_proxy.logging import logger


class OIDCValidator:
    def __init__(self, settings: OIDCSettings):
        self.settings = settings
        self._jwks: dict[str, PyJWK] = {}
        self._fetched_at: float = 0.0
        self._refresh_lock = asyncio.Lock()

    async def _jwks_url(self) -> str:
        """Configured jwks_url, or resolved via OIDC issuer discovery."""
        if self.settings.jwks_url:
            return self.settings.jwks_url
        discovery = self.settings.issuer.rstrip("/") + "/.well-known/openid-configuration"
        async with aiohttp.ClientSession() as session:
            async with session.get(discovery, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                resp.raise_for_status()
                data = await resp.json()
        return data["jwks_uri"]

    async def _refresh(self, force: bool = False) -> None:
        """Fetch JWKS and replace the key cache wholesale (no stale merge)."""
        async with self._refresh_lock:
            # single-flight collapse of concurrent refreshes, but an unknown-kid
            # refresh (force) must not be suppressed just because a TTL refresh
            # ran seconds ago — key rotation would 401 valid tokens for ~5s.
            if not force and time.monotonic() - self._fetched_at < 5:
                return
            url = await self._jwks_url()
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    resp.raise_for_status()
                    data = await resp.json()
            keys: dict[str, PyJWK] = {}
            for k in data.get("keys", []):
                if k.get("use") not in (None, "sig"):
                    continue
                try:
                    key = PyJWK(k)
                except Exception:
                    continue
                if k.get("kid"):
                    keys[k["kid"]] = key
            self._jwks = keys
            self._fetched_at = time.monotonic()
            logger.info(f"JWKS refreshed, {len(keys)} signing keys")

    async def _key_for(self, kid: str) -> Optional[PyJWK]:
        """Signing key for kid; refreshes on TTL expiry or unknown kid."""
        if kid in self._jwks:
            stale = time.monotonic() - self._fetched_at > self.settings.jwks_ttl_seconds
            if stale:
                await self._refresh()
            return self._jwks.get(kid)
        # unknown kid: force a refresh (bypasses the TTL single-flight window),
        # then look again — collapse handled by the refresh lock re-check.
        await self._refresh(force=True)
        return self._jwks.get(kid)

    async def validate(self, token: str) -> dict[str, Any]:
        """Returns claims. Raises jwt exceptions / ValueError on any failure."""
        header = jwt.get_unverified_header(token)
        alg = header.get("alg")
        if alg not in self.settings.algorithms:
            raise ValueError(f"algorithm {alg} not allowed")
        kid = header.get("kid")
        if not kid:
            # authentik always sets kid; requiring it avoids ambiguous
            # arbitrary-key selection for a token without one.
            raise ValueError("token has no kid")
        key = await self._key_for(kid)
        if key is None:
            raise ValueError("no matching JWKS key")
        claims = jwt.decode(
            token,
            key,
            algorithms=self.settings.algorithms,
            audience=self.settings.audience,
            issuer=self.settings.issuer,
            leeway=self.settings.leeway_seconds,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
        return claims

    def is_admin(self, claims: dict[str, Any]) -> bool:
        """True iff the configured admin_group is in the groups claim (deny-if-absent)."""
        groups = claims.get(self.settings.groups_claim)
        if not isinstance(groups, list):
            return False
        return self.settings.admin_group in groups
