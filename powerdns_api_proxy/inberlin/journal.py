"""Journal capture around mutating /api/v1 requests (docs/authz-flow.md §6-8).

Write-ahead state machine: intent row (pending) BEFORE forwarding, fail-closed
503 if the store is unwritable; post-GET after-state; finalize committed /
failed / uncertain. Cryptokey/tsigkey bodies are never stored.
"""

import json
import re
from typing import Any, Optional

from powerdns_api_proxy.inberlin.identity import Identity
from powerdns_api_proxy.inberlin.names import canonical_zone
from powerdns_api_proxy.inberlin.runtime import Runtime
from powerdns_api_proxy.logging import logger
from powerdns_api_proxy.pdns import PDNSConnector

_ZONE_PATH = re.compile(r"^/api/v1/servers/(?P<server>[^/]+)/zones(?:/(?P<zone>[^/]+))?(?P<rest>/.*)?$")
_MUTATING = {"POST", "PUT", "PATCH", "DELETE"}

SECRET_OPS = {"crypto", "tsig"}


def classify(method: str, path: str) -> Optional[dict[str, Any]]:
    """Returns {operation, server_id, zone_id} for journal-relevant requests."""
    if method not in _MUTATING:
        return None
    m = _ZONE_PATH.match(path)
    if not m:
        if re.match(r"^/api/v1/servers/[^/]+/tsigkeys", path):
            return {"operation": "tsig", "server_id": path.split("/")[4], "zone_id": None}
        return None
    server, zone, rest = m.group("server"), m.group("zone"), m.group("rest") or ""
    if zone is None:
        return {"operation": "zone-create", "server_id": server, "zone_id": None}
    if "/cryptokeys" in rest:
        return {"operation": "crypto", "server_id": server, "zone_id": zone}
    if rest in ("/notify", "/rectify"):
        return {"operation": "other", "server_id": server, "zone_id": zone}
    if method == "PATCH":
        return {"operation": "rrset-patch", "server_id": server, "zone_id": zone}
    if method == "DELETE":
        return {"operation": "zone-delete", "server_id": server, "zone_id": zone}
    return {"operation": "zone-meta", "server_id": server, "zone_id": zone}


async def fetch_zone(pdns: PDNSConnector, server_id: str, zone_id: str) -> Optional[dict]:
    """Full zone incl. rrsets; None if the zone does not exist."""
    resp = await pdns.get(f"/api/v1/servers/{server_id}/zones/{zone_id}")
    if resp.status == 404:
        return None
    if resp.status != 200:
        raise RuntimeError(f"upstream zone fetch failed: {resp.status}")
    return json.loads(await resp.text())


def rrsets_by_key(zone: Optional[dict]) -> dict[tuple[str, str], dict]:
    if not zone:
        return {}
    return {
        (canonical_zone(r["name"]), r["type"]): r
        for r in zone.get("rrsets", [])
    }


def affected_rrset_keys(body: Optional[dict]) -> list[tuple[str, str]]:
    if not body:
        return []
    return [
        (canonical_zone(r["name"]), r["type"])
        for r in body.get("rrsets", [])
        if isinstance(r, dict) and "name" in r and "type" in r
    ]


def diff_rrsets(
    keys: list[tuple[str, str]],
    before: dict[tuple[str, str], dict],
    after: dict[tuple[str, str], dict],
) -> list[tuple[str, str, Optional[str], Optional[str]]]:
    rows = []
    for name, rtype in keys:
        b = before.get((name, rtype))
        a = after.get((name, rtype))
        rows.append(
            (name, rtype, json.dumps(b) if b else None, json.dumps(a) if a else None)
        )
    return rows


class JournalCapture:
    """Per-request capture; created by the middleware for journal-relevant
    requests after identity resolution."""

    def __init__(
        self,
        runtime: Runtime,
        pdns: PDNSConnector,
        identity: Identity,
        method: str,
        path: str,
        info: dict[str, Any],
        body: Optional[dict],
    ):
        self.runtime = runtime
        self.pdns = pdns
        self.identity = identity
        self.method = method
        self.path = path
        self.info = info
        self.body = body
        self.journal_id: Optional[int] = None
        self._before_zone: Optional[dict] = None
        self._keys: list[tuple[str, str]] = []

    @property
    def operation(self) -> str:
        return self.info["operation"]

    def _zone_name(self) -> str:
        if self.info["zone_id"]:
            return canonical_zone(self.info["zone_id"])
        if self.operation == "zone-create" and self.body and self.body.get("name"):
            return canonical_zone(self.body["name"])
        return "."

    async def intent(self, rollback_of: Optional[int] = None) -> None:
        """Pre-GET + insert pending row. Raises on store failure (fail-closed)."""
        server, zone_id = self.info["server_id"], self.info["zone_id"]
        before_state: Optional[str] = None
        if zone_id and self.operation in ("rrset-patch", "zone-delete", "zone-meta"):
            self._before_zone = await fetch_zone(self.pdns, server, zone_id)
            if self.operation == "rrset-patch":
                self._keys = affected_rrset_keys(self.body)
                before_map = rrsets_by_key(self._before_zone)
                before_state = json.dumps(
                    {f"{n}|{t}": before_map.get((n, t)) for n, t in self._keys}
                )
            else:
                before_state = json.dumps(self._before_zone)
        raw = None
        if self.operation not in SECRET_OPS and self.body is not None:
            raw = json.dumps(self.body)
        self.journal_id = await self.runtime.store.journal_intent(
            teilnehmer=self.identity.effective_teilnehmer,
            actor=self.identity.actor,
            actor_kind=self.identity.kind,
            impersonator=self.identity.impersonator,
            webui_user=self.identity.webui_user,
            zone=self._zone_name(),
            method=self.method,
            path=self.path,
            operation=self.operation,
            raw_request=raw,
            before_state=before_state,
            rollback_of=rollback_of,
        )

    async def finalize(self, status_code: int) -> None:
        assert self.journal_id is not None
        if status_code >= 400:
            await self.runtime.store.journal_finalize(
                self.journal_id, status="failed", status_code=status_code,
                after_state=None, rollbackable=False,
            )
            return
        try:
            server, zone_id = self.info["server_id"], self.info["zone_id"]
            after_state: Optional[str] = None
            rrset_rows: list[tuple[str, str, Optional[str], Optional[str]]] = []
            rollbackable = False
            if self.operation == "rrset-patch" and zone_id:
                after_zone = await fetch_zone(self.pdns, server, zone_id)
                rrset_rows = diff_rrsets(
                    self._keys, rrsets_by_key(self._before_zone), rrsets_by_key(after_zone)
                )
                rollbackable = True
            elif self.operation == "zone-delete":
                rollbackable = self._before_zone is not None
            elif self.operation == "zone-create":
                created = await fetch_zone(self.pdns, server, self._zone_name())
                after_state = json.dumps(created) if created else None
                rollbackable = created is not None
            await self.runtime.store.journal_finalize(
                self.journal_id, status="committed", status_code=status_code,
                after_state=after_state, rollbackable=rollbackable, rrsets=rrset_rows,
            )
        except Exception:
            logger.exception(f"journal finalize failed for entry {self.journal_id}")
            try:
                await self.runtime.store.journal_finalize(
                    self.journal_id, status="uncertain", status_code=status_code,
                    after_state=None, rollbackable=False,
                )
            except Exception:
                logger.exception("could not even mark journal entry uncertain")
