"""Request identity model and contextvars shared between middleware and the
patched upstream environment lookup (docs/authz-flow.md §3)."""

from contextvars import ContextVar
from dataclasses import dataclass
from typing import Literal

from powerdns_api_proxy.models import ProxyConfigEnvironment

IdentityKind = Literal["static", "webui-act-as", "oidc", "tn-key"]


@dataclass
class Identity:
    kind: IdentityKind
    actor: str  # env name | canonical User | oidc sub
    display: str = ""
    effective_user: str | None = None  # canonical
    impersonator: str | None = None  # oidc sub of admin, if impersonating
    webui_user: str | None = None  # htpasswd login behind the webui token
    is_admin: bool = False
    roles: tuple[str, ...] = ()

    @property
    def is_session(self) -> bool:
        """True for interactive sessions (act-as / OIDC): journal read + rollback.

        Key minting is stricter still — OIDC only (router checks kind directly).
        """
        return self.kind in ("webui-act-as", "oidc")


current_identity: ContextVar[Identity | None] = ContextVar(
    "inberlin_identity", default=None
)
current_environment: ContextVar[ProxyConfigEnvironment | None] = ContextVar(
    "inberlin_environment", default=None
)
