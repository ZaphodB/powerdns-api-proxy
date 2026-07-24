"""authentik OIDC access-token validation (docs/authz-flow.md §2).

JWKS cache: bounded TTL, refresh on unknown kid with single-flight, no
fallback to stale keys after a successful refresh, startup tolerant of JWKS
downtime (only OIDC requests fail while unreachable).
"""

import asyncio
import time
from typing import Any

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
        discovery = (
            self.settings.issuer.rstrip("/") + "/.well-known/openid-configuration"
        )
        async with (
            aiohttp.ClientSession() as session,
            session.get(discovery, timeout=aiohttp.ClientTimeout(total=10)) as resp,
        ):
            resp.raise_for_status()
            data = await resp.json()
        return data["jwks_uri"]

    async def _refresh(self) -> None:
        """Fetch JWKS and replace the key cache wholesale (no stale merge)."""
        async with self._refresh_lock:
            # Unconditional single-flight cooldown: a refresh <5s ago already
            # has the current key set, so re-fetching for an unknown kid is
            # pointless — and forged kids in unverified JWT headers must not
            # be able to drive unlimited fetches at the IdP. Cost: a token
            # signed with a just-rotated key may 401 for up to 5s (retry
            # succeeds).
            if time.monotonic() - self._fetched_at < 5:
                return
            # stamp BEFORE the fetch: a failing IdP must not disable the
            # cooldown, or forged-kid spam degrades into back-to-back
            # fetch attempts (10s timeout each) while the IdP is down
            self._fetched_at = time.monotonic()
            url = await self._jwks_url()
            async with (
                aiohttp.ClientSession() as session,
                session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp,
            ):
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
            logger.info(f"JWKS refreshed, {len(keys)} signing keys")

    async def _key_for(self, kid: str) -> PyJWK | None:
        """Signing key for kid; refreshes on TTL expiry or unknown kid."""
        if kid in self._jwks:
            stale = time.monotonic() - self._fetched_at > self.settings.jwks_ttl_seconds
            if stale:
                await self._refresh()
            return self._jwks.get(kid)
        # unknown kid: refresh (subject to the 5s cooldown) and look again.
        await self._refresh()
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
