"""Identity resolution + journal middleware (docs/authz-flow.md).

IdentityMiddleware runs first (added last), resolves exactly one credential
class into an Identity + synthesized environment (contextvars), and rejects
ambiguous or forbidden combinations. JournalMiddleware wraps mutating /api/v1
requests with the write-ahead journal.
"""

import json
import time
from collections import defaultdict, deque
from typing import Optional

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from powerdns_api_proxy.config import load_config
from powerdns_api_proxy.inberlin.authz import (
    environment_for_admin,
    environment_for_teilnehmer,
)
from powerdns_api_proxy.inberlin.identity import (
    Identity,
    current_environment,
    current_identity,
)
from powerdns_api_proxy.inberlin.journal import JournalCapture, classify
from powerdns_api_proxy.inberlin.keys import verify_key
from powerdns_api_proxy.inberlin.names import canonical_tn
from powerdns_api_proxy.inberlin.runtime import get_runtime
from powerdns_api_proxy.logging import logger

IDENTITY_HEADERS = (
    "x-teilnehmer",
    "x-impersonate-teilnehmer",
    "x-webui-user",
    "authorization",
)

_PUBLIC_PATHS = ("/proxy/v1/health", "/", "/health/pdns", "/metrics")


def _error(status: int, detail: str) -> JSONResponse:
    """PowerDNS-style error body {"error": detail}."""
    return JSONResponse({"error": detail}, status_code=status)


class RateLimiter:
    """Sliding-window (60s) in-memory limiter. Buckets: auth failures per
    client IP, mutations per effective TN/token, and one global webui bucket
    capping all act-as mutations combined."""

    def __init__(
        self,
        failures_per_minute: int,
        mutations_per_minute: int,
        webui_global_mutations_per_minute: int = 600,
    ):
        self.limits = {
            "auth": failures_per_minute,
            "mutation": mutations_per_minute,
            "webui-global": webui_global_mutations_per_minute,
        }
        self.events: dict[tuple[str, str], deque] = defaultdict(deque)

    def hit(self, bucket: str, key: str) -> bool:
        """Records an event; returns True if over limit."""
        now = time.monotonic()
        q = self.events[(bucket, key)]
        q.append(now)
        while q and q[0] < now - 60:
            q.popleft()
        return len(q) > self.limits[bucket]


class IdentityMiddleware(BaseHTTPMiddleware):
    """Resolve exactly one credential class into an Identity + environment.

    Order: X-API-Key (static env → webui act-as / plain static, else TN key)
    XOR Bearer (OIDC admin / impersonation / bridged Teilnehmer). Ambiguous or
    disallowed header combinations are rejected, never precedence-resolved.
    Sets the identity/environment contextvars for the request and strips all
    proxy identity headers before the upstream forward.
    """

    async def dispatch(self, request: Request, call_next):
        runtime = get_runtime()
        if runtime is None:
            return await call_next(request)

        path = request.url.path
        if not (path.startswith("/api/v1") or path.startswith("/proxy/v1") or path.startswith("/info")):
            return await call_next(request)
        if path in _PUBLIC_PATHS:
            return await call_next(request)

        api_key = request.headers.get("x-api-key")
        bearer = None
        auth_header = request.headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            bearer = auth_header[7:].strip()
        x_tn = request.headers.get("x-teilnehmer")
        x_imp = request.headers.get("x-impersonate-teilnehmer")
        x_webui_user = request.headers.get("x-webui-user")

        for h in ("x-teilnehmer", "x-impersonate-teilnehmer", "x-webui-user"):
            if len(request.headers.getlist(h)) > 1:
                return _error(400, f"duplicate {h} header")

        if x_tn and x_imp:
            # reject-not-precedence-resolve: no credential class accepts both
            return _error(400, "ambiguous identity headers: X-Teilnehmer and X-Impersonate-Teilnehmer")
        if api_key and bearer:
            return _error(400, "ambiguous credentials: X-API-Key and Bearer")
        if not api_key and not bearer:
            return _error(401, "Unauthorized")

        limiter: RateLimiter = getattr(request.app.state, "inberlin_limiter", None) or RateLimiter(
            runtime.settings.rate_limit_auth_failures_per_minute,
            runtime.settings.rate_limit_mutations_per_minute,
            runtime.settings.rate_limit_webui_global_mutations_per_minute,
        )
        request.app.state.inberlin_limiter = limiter

        identity: Optional[Identity] = None
        environment = None

        config = load_config()
        if api_key:
            static_env = _static_env_for_token(config, api_key)
            if static_env is not None:
                roles = runtime.env_roles(static_env.name)
                if "webui" in roles and x_tn:
                    allowed = runtime.settings.webui_source_ips
                    client_ip = request.client.host if request.client else None
                    if allowed and client_ip not in allowed:
                        logger.warning(
                            f"webui act-as token used from unauthorized source {client_ip}"
                        )
                        return _error(403, "webui token not valid from this source")
                    identity = Identity(
                        kind="webui-act-as",
                        actor=static_env.name,
                        effective_teilnehmer=canonical_tn(x_tn),
                        webui_user=x_webui_user,
                        roles=roles,
                    )
                    environment = environment_for_teilnehmer(
                        identity.effective_teilnehmer, runtime.mapping.view
                    )
                elif x_tn or x_imp:
                    return _error(403, "identity headers not allowed for this credential")
                else:
                    identity = Identity(
                        kind="static",
                        actor=static_env.name,
                        is_admin="admin" in roles,
                        roles=roles,
                    )
                    environment = static_env
            else:
                tn = await verify_key(runtime.store, api_key)
                if tn is None:
                    if limiter.hit("auth", request.client.host if request.client else "?"):
                        return _error(429, "rate limited")
                    return _error(401, "Unauthorized")
                if x_tn or x_imp:
                    return _error(403, "identity headers not allowed for API keys")
                identity = Identity(
                    kind="tn-key", actor=tn, effective_teilnehmer=tn
                )
                environment = environment_for_teilnehmer(tn, runtime.mapping.view)
        else:
            if runtime.oidc is None:
                return _error(401, "OIDC not configured")
            try:
                claims = await runtime.oidc.validate(bearer)
            except Exception as e:
                logger.info(f"OIDC validation failed: {e}")
                if limiter.hit("auth", request.client.host if request.client else "?"):
                    return _error(429, "rate limited")
                return _error(401, "Unauthorized")
            is_admin = runtime.oidc.is_admin(claims)
            sub = claims["sub"]
            username = claims.get(runtime.settings.oidc.username_claim, sub)
            if x_tn:
                return _error(403, "X-Teilnehmer not allowed with OIDC")
            if x_imp:
                if not is_admin:
                    return _error(403, "impersonation requires admin group")
                identity = Identity(
                    kind="oidc", actor=sub, display=username,
                    effective_teilnehmer=canonical_tn(x_imp),
                    impersonator=sub, is_admin=True,
                )
                environment = environment_for_teilnehmer(
                    identity.effective_teilnehmer, runtime.mapping.view
                )
            elif is_admin:
                identity = Identity(
                    kind="oidc", actor=sub, display=username, is_admin=True
                )
                environment = environment_for_admin(identity)
            else:
                # Non-admin OIDC = future Teilnehmer SSO. Resolve the stable
                # `sub` through the teilnehmer_identity bridge — never trust the
                # mutable username claim as an authorization identity. Until a
                # member is explicitly bridged, Teilnehmer OIDC is not enabled.
                tn = await runtime.store.teilnehmer_for_sub(sub)
                if tn is None:
                    return _error(403, "Teilnehmer SSO not enabled for this account")
                identity = Identity(
                    kind="oidc", actor=sub, display=username, effective_teilnehmer=tn
                )
                environment = environment_for_teilnehmer(tn, runtime.mapping.view)

        token_id = identity.actor
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            mut_key = identity.effective_teilnehmer or token_id
            if limiter.hit("mutation", mut_key):
                return _error(429, "rate limited")
            if identity.kind == "webui-act-as" and limiter.hit("webui-global", "webui"):
                return _error(429, "rate limited (webui global)")

        id_token = current_identity.set(identity)
        env_token = current_environment.set(environment)
        try:
            # Strip proxy-only identity headers so they can never leak upstream
            # (defense-in-depth; PDNSConnector builds its own header set anyway),
            # and ensure X-API-Key exists for creds that didn't carry one — the
            # upstream endpoints require the header, its value is ignored (the
            # environment comes from the contextvar).
            _strip = {b"x-teilnehmer", b"x-impersonate-teilnehmer",
                      b"x-webui-user", b"authorization"}
            headers = [(k, v) for k, v in request.scope["headers"]
                       if k.lower() not in _strip]
            if not any(k.lower() == b"x-api-key" for k, _ in headers):
                headers.append((b"x-api-key", b"inberlin-contextvar"))
            request.scope["headers"] = headers
            return await call_next(request)
        finally:
            current_identity.reset(id_token)
            current_environment.reset(env_token)


def _static_env_for_token(config, token: str):
    """Static environment whose sha512 matches the presented token, or None."""
    import hashlib
    digest = hashlib.sha512(token.encode()).hexdigest()
    return config.token_env_map.get(digest)


class JournalMiddleware(BaseHTTPMiddleware):
    """Wrap journal-relevant /api/v1 mutations: intent before forward
    (fail-closed 503), finalize after; uncertain on in-flight exceptions."""

    async def dispatch(self, request: Request, call_next):
        runtime = get_runtime()
        if runtime is None:
            return await call_next(request)
        info = classify(request.method, request.url.path)
        if info is None:
            return await call_next(request)
        identity = current_identity.get()
        if identity is None:
            return await call_next(request)

        body = None
        body_bytes = await request.body()
        if body_bytes:
            try:
                body = json.loads(body_bytes)
            except json.JSONDecodeError:
                body = None

        from powerdns_api_proxy.proxy import pdns  # circular at import time
        capture = JournalCapture(
            runtime, pdns, identity, request.method, request.url.path, info, body
        )
        # Serialize intent → forward → finalize per zone: overlapping writes to
        # the same zone would capture stale before/after states (see
        # Runtime.zone_lock).
        async with runtime.zone_lock(capture.zone_name()):
            try:
                await capture.intent(
                    rollback_of=getattr(request.state, "rollback_of", None)
                )
            except Exception:
                logger.exception("journal intent failed — refusing mutation (fail-closed)")
                return _error(503, "journal unavailable, mutation refused")

            try:
                response = await call_next(request)
            except BaseException:
                # The mutation may already have reached pdns; never leave the row
                # pending. Mark it uncertain for admin reconciliation, then re-raise.
                await capture.mark_uncertain()
                raise
            await capture.finalize(response.status_code)
            return response
