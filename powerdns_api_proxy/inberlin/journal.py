"""Journal capture around mutating /api/v1 requests (docs/authz-flow.md §6-8).

Write-ahead state machine: intent row (pending) BEFORE forwarding, fail-closed
503 if the store is unwritable; post-GET after-state; finalize committed /
failed / uncertain. Cryptokey/tsigkey bodies are never stored.
"""

import asyncio
import json
import re
from collections.abc import Awaitable, Callable
from typing import NamedTuple, TypeVar

from powerdns_api_proxy.inberlin.identity import Identity
from powerdns_api_proxy.inberlin.names import canonical_zone
from powerdns_api_proxy.inberlin.runtime import Runtime
from powerdns_api_proxy.logging import logger
from powerdns_api_proxy.pdns import PDNSConnector

_ZONE_PATH = re.compile(
    r"^/api/v1/servers/(?P<server>[^/]+)/zones(?:/(?P<zone>[^/]+))?(?P<rest>/.*)?$"
)
_MUTATING = {"POST", "PUT", "PATCH", "DELETE"}


class OpInfo(NamedTuple):
    """classify() result: what a mutating /api/v1 request means for the journal."""

    operation: str
    server_id: str
    zone_id: str | None


class OpSpec(NamedTuple):
    """Per-operation journal behavior. Adding an operation means adding a row
    to OPERATIONS (plus its inverse in rollback.py) — not hunting if-cascades
    across capture, finalize, rollback, and drift code."""

    secret: bool = False  # body never journaled (crypto/tsig)
    pre_get: bool = False  # intent fetches the before-zone
    rrset_diff: bool = False  # before/after captured as a scoped rrset diff
    recreate: bool = False  # finalize re-fetches the created zone
    restore_from_before: bool = False  # rollbackable iff the before-zone existed


OPERATIONS: dict[str, OpSpec] = {
    "rrset-patch": OpSpec(pre_get=True, rrset_diff=True),
    "zone-create": OpSpec(recreate=True),
    "zone-delete": OpSpec(pre_get=True, restore_from_before=True),
    "zone-meta": OpSpec(pre_get=True),
    # Zone metadata (/zones/<z>/metadata...). Journaled but not rollbackable:
    # the before-state the journal captures is zone-shaped, and a metadata
    # inverse would need the prior kind values. build_rollback_request()
    # raises NotRollbackable for it, which is the honest answer.
    "zone-metadata": OpSpec(),
    "crypto": OpSpec(secret=True),
    "tsig": OpSpec(secret=True),
    "other": OpSpec(),
}


def classify(method: str, path: str) -> OpInfo | None:
    """Returns OpInfo for journal-relevant requests, else None."""
    if method not in _MUTATING:
        return None
    m = _ZONE_PATH.match(path)
    if not m:
        if re.match(r"^/api/v1/servers/[^/]+/tsigkeys", path):
            return OpInfo("tsig", path.split("/")[4], None)
        return None
    server, zone, rest = m.group("server"), m.group("zone"), m.group("rest") or ""
    if zone is None:
        return OpInfo("zone-create", server, None)
    if "/cryptokeys" in rest:
        return OpInfo("crypto", server, zone)
    # Must precede the DELETE branch: without it, deleting one metadata kind
    # classifies as a zone deletion and its rollback recreates the zone.
    if rest == "/metadata" or rest.startswith("/metadata/"):
        return OpInfo("zone-metadata", server, zone)
    if rest in ("/notify", "/rectify"):
        return OpInfo("other", server, zone)
    if method == "PATCH":
        return OpInfo("rrset-patch", server, zone)
    if method == "DELETE":
        return OpInfo("zone-delete", server, zone)
    return OpInfo("zone-meta", server, zone)


async def fetch_zone(pdns: PDNSConnector, server_id: str, zone_id: str) -> dict | None:
    """Full zone incl. rrsets; None if the zone does not exist."""
    resp = await pdns.get(f"/api/v1/servers/{server_id}/zones/{zone_id}")
    if resp.status == 404:
        return None
    if resp.status != 200:
        raise RuntimeError(f"upstream zone fetch failed: {resp.status}")
    return json.loads(await resp.text())


def rrsets_by_key(zone: dict | None) -> dict[tuple[str, str], dict]:
    """Zone rrsets indexed by (canonical name, type); {} for a missing zone."""
    if not zone:
        return {}
    return {(canonical_zone(r["name"]), r["type"]): r for r in zone.get("rrsets", [])}


def affected_rrset_keys(body: dict | None) -> list[tuple[str, str]]:
    """(name, type) keys a PATCH body touches — scopes the before/after diff."""
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
) -> list[tuple[str, str, str | None, str | None]]:
    """journal_rrset rows (name, type, before_json, after_json) for the touched keys."""
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
        info: OpInfo,
        body: dict | None,
    ):
        self.runtime = runtime
        self.pdns = pdns
        self.identity = identity
        self.method = method
        self.path = path
        self.info = info
        self.body = body
        self.journal_id: int | None = None
        self._before_zone: dict | None = None
        self._keys: list[tuple[str, str]] = []

    @property
    def operation(self) -> str:
        return self.info.operation

    @property
    def _spec(self) -> OpSpec:
        return OPERATIONS[self.operation]

    def zone_name(self) -> str:
        """Canonical zone for the journal row; '.' when undeterminable."""
        if self.info.zone_id:
            return canonical_zone(self.info.zone_id)
        if self._spec.recreate and self.body and self.body.get("name"):
            return canonical_zone(self.body["name"])
        return "."

    async def intent(self, rollback_of: int | None = None) -> None:
        """Pre-GET + insert pending row. Raises on store failure (fail-closed)."""
        server, zone_id = self.info.server_id, self.info.zone_id
        spec = self._spec
        before_state: str | None = None
        if zone_id and spec.pre_get:
            self._before_zone = await fetch_zone(self.pdns, server, zone_id)
            if spec.rrset_diff:
                self._keys = affected_rrset_keys(self.body)
                before_map = rrsets_by_key(self._before_zone)
                before_state = json.dumps(
                    {f"{n}|{t}": before_map.get((n, t)) for n, t in self._keys}
                )
            else:
                before_state = json.dumps(self._before_zone)
        raw = None
        if not spec.secret and self.body is not None:
            raw = json.dumps(self.body)
        self.journal_id = await self.runtime.store.journal_intent(
            self.identity,
            zone=self.zone_name(),
            method=self.method,
            path=self.path,
            operation=self.operation,
            raw_request=raw,
            before_state=before_state,
            rollback_of=rollback_of,
        )

    async def mark_uncertain(self) -> None:
        """Best-effort: flag the pending row uncertain when the request errored
        after intent (mutation may or may not have reached pdns)."""
        if self.journal_id is None:
            return
        try:
            await self.runtime.store.journal_finalize(
                self.journal_id,
                status="uncertain",
                status_code=None,
                after_state=None,
                rollbackable=False,
            )
        except Exception:
            logger.exception(
                f"could not mark journal entry {self.journal_id} uncertain"
            )

    async def finalize(self, status_code: int) -> None:
        """Post-GET after-state and settle the row: failed (4xx), uncertain
        (5xx — the mutation may have applied before the error), committed,
        or uncertain if the post-GET/store write itself fails."""
        assert self.journal_id is not None
        if 400 <= status_code < 500:
            await self.runtime.store.journal_finalize(
                self.journal_id,
                status="failed",
                status_code=status_code,
                after_state=None,
                rollbackable=False,
            )
            return
        if status_code >= 500:
            # A 5xx is as ambiguous as a transport error: pdns may have
            # applied the change before failing. Surface for reconciliation.
            await self.runtime.store.journal_finalize(
                self.journal_id,
                status="uncertain",
                status_code=status_code,
                after_state=None,
                rollbackable=False,
            )
            return
        try:
            server, zone_id = self.info.server_id, self.info.zone_id
            spec = self._spec
            after_state: str | None = None
            rrset_rows: list[tuple[str, str, str | None, str | None]] = []
            rollbackable = False
            if spec.rrset_diff and zone_id:
                after_zone = await fetch_zone(self.pdns, server, zone_id)
                rrset_rows = diff_rrsets(
                    self._keys,
                    rrsets_by_key(self._before_zone),
                    rrsets_by_key(after_zone),
                )
                rollbackable = True
            elif spec.restore_from_before:
                rollbackable = self._before_zone is not None
            elif spec.recreate:
                created = await fetch_zone(self.pdns, server, self.zone_name())
                after_state = json.dumps(created) if created else None
                rollbackable = created is not None
            await self.runtime.store.journal_finalize(
                self.journal_id,
                status="committed",
                status_code=status_code,
                after_state=after_state,
                rollbackable=rollbackable,
                rrsets=rrset_rows,
            )
        except Exception:
            logger.exception(f"journal finalize failed for entry {self.journal_id}")
            try:
                await self.runtime.store.journal_finalize(
                    self.journal_id,
                    status="uncertain",
                    status_code=status_code,
                    after_state=None,
                    rollbackable=False,
                )
            except Exception:
                logger.exception("could not even mark journal entry uncertain")


T = TypeVar("T")


# Strong refs keep the settle tasks alive until done (a bare create_task
# result can be garbage-collected mid-flight).
_background_tasks: set[asyncio.Task] = set()


def _settle_in_background(coro: Awaitable[None], label: str) -> None:
    """Run a journal-settling DB write as its own task, outside the request's
    (possibly cancelled) scope, and log if it fails."""
    task = asyncio.ensure_future(coro)
    _background_tasks.add(task)

    def _done(t: asyncio.Task) -> None:
        _background_tasks.discard(t)
        if not t.cancelled() and t.exception() is not None:
            logger.error(f"journal settle ({label}) failed: {t.exception()!r}")

    task.add_done_callback(_done)


async def _settle_after(intent_task: asyncio.Task, capture: "JournalCapture") -> None:
    """Wait out an in-flight intent write, then mark its row uncertain. Runs
    detached, so it survives the cancellation that triggered it."""
    try:
        await intent_task
    except Exception:
        return  # intent failed -> no row to settle
    await capture.mark_uncertain()


async def drain_settles(timeout: float = 5.0) -> None:
    """Wait for in-flight settle writes at shutdown, so no row is left pending
    by a store closed out from under a detached task."""
    pending = list(_background_tasks)
    if not pending:
        return
    done, still_running = await asyncio.wait(pending, timeout=timeout)
    if still_running:
        logger.error(
            f"{len(still_running)} journal settle task(s) unfinished at shutdown; "
            "their rows stay pending for reconciliation"
        )


async def run_journaled(
    capture: JournalCapture,
    lock: asyncio.Lock,
    forward: Callable[[], Awaitable[T]],
    *,
    status_of: Callable[[T], int],
    rollback_of: int | None = None,
    before_intent: Callable[[], Awaitable[None]] | None = None,
) -> T | None:
    """The one journaled-execution shape (docs/authz-flow.md §6-8), shared by
    JournalMiddleware, rollback, and register:

        intent row (fail-closed) → forward → finalize, serialized per zone
        (overlapping writes would capture stale before/after states);
        uncertain on in-flight exceptions.

    before_intent runs inside the lock just before the intent row — rollback's
    drift check lives there (a concurrent write between check and apply would
    be silently clobbered otherwise). Exceptions from it propagate.

    Returns forward()'s response, or None when the journal intent failed —
    the caller surfaces its own 503 (middleware returns a response, routers
    raise HTTPException)."""
    async with lock:
        if before_intent is not None:
            await before_intent()
        # Own task: the INSERT runs in a threadpool and cannot be cancelled, so
        # a disconnect mid-intent would otherwise write the row and lose the
        # id with it (hy3 round 11b). The task completes either way; if we were
        # cancelled, settle it once the id exists.
        intent_task = asyncio.ensure_future(capture.intent(rollback_of=rollback_of))
        try:
            # shield: a cancel of this request must not abort the in-flight
            # insert, or the row lands with its id lost to us.
            await asyncio.shield(intent_task)
        except Exception:
            logger.exception("journal intent failed (fail-closed)")
            return None
        except BaseException:
            _settle_in_background(_settle_after(intent_task, capture), "intent")
            raise
        try:
            resp = await forward()
            status = status_of(resp)
        except BaseException:
            # The mutation may already have reached pdns; never leave the row
            # pending. A client disconnect cancels this task, and under
            # anyio's level-based cancellation an inline await here would be
            # re-cancelled before the DB write lands (gemini round 10) — so
            # settle the row outside the cancelled scope, then re-raise.
            # status_of() is inside the try for the same reason: it runs after
            # the mutation landed.
            _settle_in_background(capture.mark_uncertain(), "mark_uncertain")
            raise
        fin = asyncio.ensure_future(capture.finalize(status))
        try:
            await fin
        except BaseException:
            # Client walked away or the finalize write itself failed. Stop the
            # (separate) finalize task and settle the row out-of-scope;
            # journal_finalize only transitions pending/uncertain rows by id,
            # so whichever write lands last cannot downgrade a committed row.
            fin.cancel()
            _settle_in_background(capture.mark_uncertain(), "finalize-failed")
            raise
    return resp
