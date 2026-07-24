"""Identity resolution + journal middleware (docs/authz-flow.md).

IdentityMiddleware runs first (added last), resolves exactly one credential
class into an Identity + synthesized environment (contextvars), and rejects
ambiguous or forbidden combinations. JournalMiddleware wraps mutating /api/v1
requests with the write-ahead journal.
"""

import json
import time
from collections import defaultdict, deque

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from powerdns_api_proxy.config import load_config
from powerdns_api_proxy.inberlin.authz import (
    environment_for_admin,
    environment_for_user,
)
from powerdns_api_proxy.inberlin.identity import (
    Identity,
    current_environment,
    current_identity,
)
from powerdns_api_proxy.inberlin.journal import JournalCapture, classify, run_journaled
from powerdns_api_proxy.inberlin.keys import sha512, verify_key
from powerdns_api_proxy.inberlin.names import canonical_user
from powerdns_api_proxy.inberlin.runtime import get_runtime
from powerdns_api_proxy.inberlin.roles import ADMIN, WEBUI
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
    client IP, mutations per effective User/token, and one global webui bucket
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
    XOR Bearer (OIDC admin / impersonation / bridged User). Ambiguous or
    disallowed header combinations are rejected, never precedence-resolved.
    Sets the identity/environment contextvars for the request and strips all
    proxy identity headers before the upstream forward.
    """

    async def dispatch(self, request: Request, call_next):
        runtime = get_runtime()
        if runtime is None:
            return await call_next(request)

        path = request.url.path
        if not (
            path.startswith("/api/v1")
            or path.startswith("/proxy/v1")
            or path.startswith("/info")
        ):
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

        for h in (
            "x-api-key",
            "authorization",
            "x-teilnehmer",
            "x-impersonate-teilnehmer",
            "x-webui-user",
        ):
            if len(request.headers.getlist(h)) > 1:
                return _error(400, f"duplicate {h} header")

        if x_tn and x_imp:
            # reject-not-precedence-resolve: no credential class accepts both
            return _error(
                400,
                "ambiguous identity headers: X-Teilnehmer and X-Impersonate-Teilnehmer",
            )
        if api_key and bearer:
            return _error(400, "ambiguous credentials: X-API-Key and Bearer")
        if not api_key and not bearer:
            return _error(401, "Unauthorized")

        limiter: RateLimiter = getattr(
            request.app.state, "inberlin_limiter", None
        ) or RateLimiter(
            runtime.settings.rate_limit_auth_failures_per_minute,
            runtime.settings.rate_limit_mutations_per_minute,
            runtime.settings.rate_limit_webui_global_mutations_per_minute,
        )
        request.app.state.inberlin_limiter = limiter

        identity: Identity | None = None
        environment = None

        config = load_config()
        if api_key:
            static_env = _static_env_for_token(config, api_key)
            if static_env is not None:
                roles = runtime.env_roles(static_env.name)
                if WEBUI in roles:
                    # The shared UI token is act-as ONLY: without X-Teilnehmer it
                    # must never fall through to the plain static environment,
                    # and its source-IP binding applies to every use — a stolen
                    # token from a foreign host gets nothing, headers or not.
                    allowed = runtime.settings.webui_source_ips
                    client_ip = request.client.host if request.client else None
                    if allowed and client_ip not in allowed:
                        logger.warning(
                            f"webui act-as token used from unauthorized source {client_ip}"
                        )
                        return _error(403, "webui token not valid from this source")
                    if not x_tn:
                        return _error(400, "webui act-as requires X-Teilnehmer")
                    user_value = canonical_user(x_tn)
                    identity = Identity(
                        kind="webui-act-as",
                        actor=static_env.name,
                        effective_user=user_value,
                        webui_user=x_webui_user,
                        roles=roles,
                    )
                    environment = environment_for_user(user_value, runtime.mapping.view)
                elif x_tn or x_imp:
                    return _error(
                        403, "identity headers not allowed for this credential"
                    )
                else:
                    identity = Identity(
                        kind="static",
                        actor=static_env.name,
                        is_admin=ADMIN in roles,
                        roles=roles,
                    )
                    environment = static_env
            else:
                user = await verify_key(runtime.store, api_key)
                if user is None:
                    if limiter.hit(
                        "auth", request.client.host if request.client else "?"
                    ):
                        return _error(429, "rate limited")
                    return _error(401, "Unauthorized")
                if x_tn or x_imp:
                    return _error(403, "identity headers not allowed for API keys")
                identity = Identity(kind="tn-key", actor=user, effective_user=user)
                environment = environment_for_user(user, runtime.mapping.view)
        else:
            if runtime.oidc is None or runtime.settings.oidc is None:
                return _error(401, "OIDC not configured")
            if bearer is None:
                return _error(401, "Unauthorized")
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
                user_value = canonical_user(x_imp)
                identity = Identity(
                    kind="oidc",
                    actor=sub,
                    display=username,
                    effective_user=user_value,
                    impersonator=sub,
                    is_admin=True,
                )
                environment = environment_for_user(user_value, runtime.mapping.view)
            elif is_admin:
                identity = Identity(
                    kind="oidc", actor=sub, display=username, is_admin=True
                )
                environment = environment_for_admin(identity)
            else:
                # Non-admin OIDC = future User SSO. Resolve the stable
                # `sub` through the user_identity bridge — never trust the
                # mutable username claim as an authorization identity. Until a
                # member is explicitly bridged, User OIDC is not enabled.
                user = await runtime.store.user_for_sub(sub)
                if user is None:
                    return _error(403, "User SSO not enabled for this account")
                identity = Identity(
                    kind="oidc", actor=sub, display=username, effective_user=user
                )
                environment = environment_for_user(user, runtime.mapping.view)

        # Request-time §5 ownership gate for zone-addressed /api/v1 requests
        # (terra-pro round 9 HIGH): the synthesized env grants owned zones
        # with subzones=True, which upstream matching extends to ALL
        # descendants — it cannot express carve-outs. owner_of() re-resolves
        # the addressed zone (deny set → most-specific override → longest
        # owned suffix), so an override carve-out or deny-set descendant
        # under an owned parent stays unreachable. Zone list responses may
        # still show carved-out descendant names — accepted: delegation
        # names are public in DNS anyway.
        if identity.effective_user is not None and path.startswith("/api/v1"):
            zone_ref = await _addressed_zone(request, path)
            if zone_ref is not None and (
                runtime.mapping.view.owner_of(zone_ref) != identity.effective_user
            ):
                return _error(403, "zone not owned")

        token_id = identity.actor
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            mut_key = identity.effective_user or token_id
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
            _strip = {
                b"x-teilnehmer",
                b"x-impersonate-teilnehmer",
                b"x-webui-user",
                b"authorization",
            }
            headers = [
                (k, v) for k, v in request.scope["headers"] if k.lower() not in _strip
            ]
            if not any(k.lower() == b"x-api-key" for k, _ in headers):
                headers.append((b"x-api-key", b"inberlin-contextvar"))
            request.scope["headers"] = headers
            return await call_next(request)
        finally:
            current_identity.reset(id_token)
            current_environment.reset(env_token)


def _static_env_for_token(config, token: str):
    """Static environment whose sha512 matches the presented token, or None."""
    return config.token_env_map.get(sha512(token))


async def _addressed_zone(request: Request, path: str) -> str | None:
    """Zone a /api/v1 request addresses: path segment after /zones/, or the
    body `name` on a zone-collection POST. None when no single zone is
    addressed (zone list, servers, search). Unparseable values pass through
    as-is — owner_of() canonicalization resolves them to no owner, which
    fails closed."""
    parts = path.strip("/").split("/")
    if "zones" not in parts:
        return None
    zi = parts.index("zones")
    if len(parts) > zi + 1:
        return parts[zi + 1]
    if request.method == "POST":
        try:
            body = json.loads(await request.body())
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
        if isinstance(body, dict) and isinstance(body.get("name"), str):
            return body["name"]
    return None


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
        if not isinstance(body, dict):
            # A top-level array/scalar is never a valid pdns body; capture
            # code assumes dict-or-None. Upstream rejects the request itself.
            body = None

        from powerdns_api_proxy.proxy import pdns  # circular at import time

        capture = JournalCapture(
            runtime, pdns, identity, request.method, request.url.path, info, body
        )
        response = await run_journaled(
            capture,
            runtime.zone_lock(capture.zone_name()),
            lambda: call_next(request),
            status_of=lambda r: r.status_code,
        )
        if response is None:
            return _error(503, "journal unavailable, mutation refused")
        return response
