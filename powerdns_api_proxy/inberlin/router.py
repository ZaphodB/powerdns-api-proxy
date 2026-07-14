"""/proxy/v1 router: mapping, overrides, journal, rollback, keys, identity,
health/ready, reload (docs/api-contract.md)."""

from typing import Optional

from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from powerdns_api_proxy.inberlin.identity import Identity, current_identity
from powerdns_api_proxy.inberlin.journal import JournalCapture, classify
from powerdns_api_proxy.inberlin.keys import generate_key
from powerdns_api_proxy.inberlin.names import canonical_tn, canonical_zone
from powerdns_api_proxy.inberlin.rollback import (
    NotRollbackable,
    build_rollback_request,
    check_drift,
)
from powerdns_api_proxy.inberlin.runtime import Runtime, get_runtime
from powerdns_api_proxy.inberlin.store import GenerationMismatch
from powerdns_api_proxy.logging import logger

router = APIRouter(prefix="/proxy/v1", tags=["IN-Berlin Proxy"])


def _runtime() -> Runtime:
    rt = get_runtime()
    if rt is None:
        raise HTTPException(404, "inberlin extension disabled")
    return rt


def _identity() -> Identity:
    identity = current_identity.get()
    if identity is None:
        raise HTTPException(401, "Unauthorized")
    return identity


def _require_admin(identity: Identity) -> None:
    if not identity.is_admin:
        raise HTTPException(403, "admin required")


def _require_exporter_or_admin(identity: Identity) -> None:
    if not (identity.is_admin or "exporter" in identity.roles):
        raise HTTPException(403, "exporter or admin required")


def _require_session_tn(identity: Identity) -> str:
    """Journal/rollback access needs a session (act-as or OIDC), never a key."""
    if identity.kind == "tn-key":
        raise HTTPException(403, "not available for API keys, use a session")
    return _require_tn(identity)


def _require_tn(identity: Identity) -> str:
    if not identity.effective_teilnehmer:
        raise HTTPException(403, "no effective Teilnehmer for this credential")
    return identity.effective_teilnehmer


def _require_generation(if_match: Optional[str]) -> int:
    if if_match is None:
        raise HTTPException(400, "If-Match header with current generation required")
    try:
        return int(if_match.strip('"'))
    except ValueError:
        raise HTTPException(400, "If-Match must be an integer generation")


# -- mapping ---------------------------------------------------------------

class MappingPut(BaseModel):
    mapping: dict[str, list[str]]


class MappingPatch(BaseModel):
    add: dict[str, list[str]] = {}
    remove: dict[str, list[str]] = {}


@router.put("/mapping")
async def put_mapping(body: MappingPut, if_match: Optional[str] = Header(None)):
    rt, identity = _runtime(), _identity()
    _require_exporter_or_admin(identity)
    expected = _require_generation(if_match)
    try:
        generation = await rt.mapping.replace(expected, body.mapping, identity.actor)
    except GenerationMismatch as e:
        raise HTTPException(409, f"generation mismatch, current is {e.current}")
    orphans = rt.mapping.orphaned_overrides()
    return {"generation": generation, "orphaned_overrides": orphans}


@router.patch("/mapping")
async def patch_mapping(body: MappingPatch, if_match: Optional[str] = Header(None)):
    rt, identity = _runtime(), _identity()
    _require_exporter_or_admin(identity)
    expected = _require_generation(if_match)
    try:
        generation = await rt.mapping.patch(
            expected, body.add, body.remove, identity.actor
        )
    except GenerationMismatch as e:
        raise HTTPException(409, f"generation mismatch, current is {e.current}")
    return {"generation": generation, "orphaned_overrides": rt.mapping.orphaned_overrides()}


@router.get("/mapping")
async def get_mapping():
    rt, identity = _runtime(), _identity()
    _require_admin(identity)
    view = rt.mapping.view
    return {
        "generation": view.generation,
        "mapping": {tn: sorted(zones) for tn, zones in view.zones_by_tn.items()},
        "overrides": view.overrides,
    }


@router.get("/mapping/self")
async def get_mapping_self():
    rt, identity = _runtime(), _identity()
    tn = _require_tn(identity)
    return {"teilnehmer": tn, "zones": sorted(rt.mapping.view.zones_for(tn))}


# -- overrides --------------------------------------------------------------

class OverrideCreate(BaseModel):
    zone: str
    teilnehmer: str
    note: Optional[str] = None


@router.get("/overrides")
async def list_overrides():
    rt, identity = _runtime(), _identity()
    _require_admin(identity)
    return {"overrides": await rt.store.list_overrides()}


@router.post("/overrides", status_code=201)
async def create_override(body: OverrideCreate):
    rt, identity = _runtime(), _identity()
    _require_admin(identity)
    zone = canonical_zone(body.zone)
    override_id = await rt.store.add_override(
        zone, canonical_tn(body.teilnehmer), identity.actor, body.note
    )
    await rt.mapping.reload_overrides()
    return {"id": override_id, "zone": zone}


@router.delete("/overrides/{override_id}")
async def delete_override(override_id: int):
    rt, identity = _runtime(), _identity()
    _require_admin(identity)
    if not await rt.store.delete_override(override_id):
        raise HTTPException(404, "override not found")
    await rt.mapping.reload_overrides()
    return {"deleted": override_id}


# -- journal ----------------------------------------------------------------

def _journal_row_public(row: dict) -> dict:
    return {
        k: row[k]
        for k in (
            "id", "ts", "status", "teilnehmer", "actor", "actor_kind",
            "impersonator", "webui_user", "zone", "method", "path",
            "operation", "status_code", "rollbackable", "rollback_of",
        )
        if k in row
    }


@router.get("/journal")
async def query_journal(
    zone: Optional[str] = None,
    name: Optional[str] = None,
    type: Optional[str] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    teilnehmer: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
):
    rt, identity = _runtime(), _identity()
    if identity.is_admin:
        tn_filter = canonical_tn(teilnehmer) if teilnehmer else None
    else:
        if teilnehmer is not None:
            raise HTTPException(403, "teilnehmer filter is admin-only")
        tn_filter = _require_session_tn(identity)
    rows = await rt.store.journal_query(
        teilnehmer=tn_filter,
        zone=canonical_zone(zone) if zone else None,
        name=canonical_zone(name) if name else None,
        rtype=type,
        since=since,
        until=until,
        limit=limit,
        offset=offset,
    )
    return {"entries": [_journal_row_public(r) for r in rows]}


@router.get("/journal/uncertain")
async def journal_uncertain():
    rt, identity = _runtime(), _identity()
    _require_admin(identity)
    pending = await rt.store.journal_query(status="pending", limit=500)
    uncertain = await rt.store.journal_query(status="uncertain", limit=500)
    return {"entries": [_journal_row_public(r) for r in pending + uncertain]}


@router.get("/journal/{journal_id}")
async def get_journal_entry(journal_id: int):
    rt, identity = _runtime(), _identity()
    entry = await rt.store.journal_get(journal_id)
    if entry is None:
        raise HTTPException(404, "journal entry not found")
    if not identity.is_admin and entry["teilnehmer"] != _require_session_tn(identity):
        raise HTTPException(404, "journal entry not found")  # no IDOR oracle
    return entry


class ResolveBody(BaseModel):
    status: str  # committed | failed


@router.post("/journal/{journal_id}/resolve")
async def resolve_journal_entry(journal_id: int, body: ResolveBody):
    rt, identity = _runtime(), _identity()
    _require_admin(identity)
    if body.status not in ("committed", "failed"):
        raise HTTPException(400, "status must be committed or failed")
    if not await rt.store.journal_resolve(journal_id, body.status, identity.actor):
        raise HTTPException(409, "entry not pending/uncertain")
    return {"id": journal_id, "status": body.status}


class RollbackBody(BaseModel):
    force: bool = False


@router.post("/journal/{journal_id}/rollback")
async def rollback_journal_entry(
    journal_id: int, request: Request, body: RollbackBody = RollbackBody()
):
    rt, identity = _runtime(), _identity()
    entry = await rt.store.journal_get(journal_id)
    if entry is None:
        raise HTTPException(404, "journal entry not found")
    if not identity.is_admin and entry["teilnehmer"] != _require_session_tn(identity):
        raise HTTPException(404, "journal entry not found")
    if entry["status"] != "committed" or not entry["rollbackable"]:
        raise HTTPException(409, "entry is not rollbackable")
    if body.force and not identity.is_admin:
        raise HTTPException(403, "force is admin-only")

    # current authz on the zone required (ownership may have changed)
    if not identity.is_admin:
        owner = rt.mapping.view.owner_of(entry["zone"])
        if owner != identity.effective_teilnehmer:
            raise HTTPException(403, "no current authorization on this zone")

    from powerdns_api_proxy.proxy import pdns
    server_id = rt.settings.upstream_server_id

    if entry["operation"] == "rrset-patch" and not body.force:
        drift = await check_drift(pdns, server_id, entry["zone"], entry["rrsets"])
        if drift:
            raise HTTPException(409, "state drifted: " + "; ".join(drift))
    if entry["operation"] == "zone-create" and not identity.is_admin:
        raise HTTPException(403, "zone deletion rollback is admin-only")

    try:
        method, suffix, payload = build_rollback_request(entry)
    except NotRollbackable:
        raise HTTPException(409, "entry is not rollbackable")

    path = f"/api/v1/servers/{server_id}" + suffix
    info = classify(method, path)
    assert info is not None
    capture = JournalCapture(rt, pdns, identity, method, path, info, payload)
    try:
        await capture.intent(rollback_of=journal_id)
    except Exception:
        logger.exception("journal intent failed for rollback (fail-closed)")
        raise HTTPException(503, "journal unavailable, rollback refused")

    resp = await pdns.request(method, path, payload=payload or {})
    await capture.finalize(resp.status)
    if resp.status >= 400:
        raise HTTPException(502, f"upstream rejected rollback: {resp.status}")
    return {"rolled_back": journal_id, "journal_id": capture.journal_id}


# -- keys ---------------------------------------------------------------------

class KeyCreate(BaseModel):
    label: Optional[str] = None


@router.get("/keys")
async def list_keys():
    rt, identity = _runtime(), _identity()
    tn = _require_tn(identity)
    return {"keys": await rt.store.list_keys(tn)}


@router.post("/keys", status_code=201)
async def create_key(body: KeyCreate):
    rt, identity = _runtime(), _identity()
    tn = _require_tn(identity)
    if not identity.is_session:
        raise HTTPException(403, "keys can only be minted from a session, not a key")
    if await rt.store.count_active_keys(tn) >= rt.settings.max_keys_per_teilnehmer:
        raise HTTPException(409, "key limit reached")
    plaintext, prefix, key_hash = generate_key()
    key_id = await rt.store.insert_key(tn, prefix, key_hash, body.label, identity.kind)
    return JSONResponse(
        {"id": key_id, "key": plaintext, "prefix": prefix}, status_code=201
    )


@router.delete("/keys/{key_id}")
async def revoke_key(key_id: int):
    rt, identity = _runtime(), _identity()
    scope = None if identity.is_admin else _require_tn(identity)
    if not await rt.store.revoke_key(key_id, scope):
        raise HTTPException(404, "key not found")
    return {"revoked": key_id}


# -- identity / ops -----------------------------------------------------------

@router.get("/whoami")
async def whoami():
    identity = _identity()
    return {
        "kind": identity.kind,
        "actor": identity.actor,
        "display": identity.display,
        "effective_teilnehmer": identity.effective_teilnehmer,
        "impersonator": identity.impersonator,
        "webui_user": identity.webui_user,
        "is_admin": identity.is_admin,
    }


@router.get("/health")
async def health():
    return {"status": "ok"}


@router.get("/ready")
async def ready():
    rt, identity = _runtime(), _identity()
    if not (identity.is_admin or (identity.kind == "static" and identity.roles)):
        raise HTTPException(403, "static or admin credential required")
    from powerdns_api_proxy.proxy import pdns
    upstream_ok = False
    try:
        resp = await pdns.get("/api/v1/servers")
        upstream_ok = resp.status == 200
    except Exception:
        pass
    journal_ok = await rt.store.writable()
    status = 200 if (upstream_ok and journal_ok) else 503
    return JSONResponse(
        {
            "upstream": upstream_ok,
            "journal_writable": journal_ok,
            "mapping_generation": rt.mapping.view.generation,
            "journal_db_bytes": await rt.store.db_size_bytes(),
        },
        status_code=status,
    )


@router.post("/admin/reload")
async def admin_reload():
    _identity_admin()
    from powerdns_api_proxy.inberlin.reload import reload_static_config
    reload_static_config()
    return {"reloaded": True}


def _identity_admin() -> Identity:
    identity = _identity()
    _require_admin(identity)
    return identity
