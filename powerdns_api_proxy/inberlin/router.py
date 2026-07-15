"""/proxy/v1 router: mapping, overrides, journal, rollback, register, keys,
identity, health/ready, reload (docs/api-contract.md)."""

import asyncio
import dataclasses
import sqlite3
from typing import Optional

from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from powerdns_api_proxy.inberlin.identity import Identity, current_identity
from powerdns_api_proxy.inberlin.journal import JournalCapture, classify, fetch_zone
from powerdns_api_proxy.inberlin.keys import generate_key
from powerdns_api_proxy.inberlin.names import (
    canonical_tn,
    canonical_zone,
    zone_is_or_under,
)
from powerdns_api_proxy.inberlin.rollback import (
    NotRollbackable,
    build_rollback_request,
    check_drift,
)
from powerdns_api_proxy.inberlin.runtime import Runtime, get_runtime
from powerdns_api_proxy.inberlin.store import GenerationMismatch, KeyLimitReached
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
    """Parse the mandatory If-Match CAS generation header (400 if absent/bad)."""
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
    try:
        override_id = await rt.store.add_override(
            zone, canonical_tn(body.teilnehmer), identity.actor, body.note
        )
    except sqlite3.IntegrityError:
        raise HTTPException(409, "override for this zone already exists")
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
    """List-view projection: metadata only, no before/after payloads."""
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
    """Inverse-apply a committed entry. Requires session (or admin), CURRENT
    authz on the zone, no drift vs the recorded after-state (force=admin).
    The rollback is itself journaled with rollback_of set."""
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
    # Per-zone serialization, same as JournalMiddleware. The drift check must
    # sit INSIDE the lock: a concurrent write between check and apply would
    # make the rollback silently clobber it.
    async with rt.zone_lock(canonical_zone(entry["zone"])):
        if entry["operation"] == "rrset-patch" and not body.force:
            try:
                drift = await check_drift(
                    pdns, server_id, entry["zone"], entry["rrsets"]
                )
            except RuntimeError:
                raise HTTPException(502, "upstream unavailable, cannot verify drift")
            if drift:
                raise HTTPException(409, "state drifted: " + "; ".join(drift))
        try:
            await capture.intent(rollback_of=journal_id)
        except Exception:
            logger.exception("journal intent failed for rollback (fail-closed)")
            raise HTTPException(503, "journal unavailable, rollback refused")

        try:
            resp = await pdns.request(method, path, payload=payload or {})
        except BaseException:
            # Same contract as JournalMiddleware: the mutation may have reached
            # pdns — never leave the intent row pending.
            await capture.mark_uncertain()
            raise
        await capture.finalize(resp.status)
    if resp.status >= 400:
        raise HTTPException(502, f"upstream rejected rollback: {resp.status}")
    return {"rolled_back": journal_id, "journal_id": capture.journal_id}


# -- registration -------------------------------------------------------------

class RegisterBody(BaseModel):
    zone: str
    teilnehmer: str


@router.post("/register", status_code=201)
async def register_zone(body: RegisterBody):
    """Create-only domain registration (registrar role or admin): new zone
    from the configured template + mapping entry for the Teilnehmer, both
    journaled. Existing zones are never touched — pdns rejects duplicate
    creates with an unconditional 409 (verified in auth-5.1.x ws-auth.cc),
    so this credential structurally cannot modify existing data."""
    rt, identity = _runtime(), _identity()
    if not (identity.is_admin or "registrar" in identity.roles):
        raise HTTPException(403, "registrar or admin required")
    reg = rt.settings.registration
    if reg is None:
        raise HTTPException(501, "registration not configured")
    zone = canonical_zone(body.zone)
    tn = canonical_tn(body.teilnehmer)
    view = rt.mapping.view
    for denied in view.deny_zones:
        if zone_is_or_under(zone, denied):
            raise HTTPException(403, "zone is on the deny list")
    if view.owner_of(zone) is not None:
        raise HTTPException(409, "zone already owned by a Teilnehmer")

    from powerdns_api_proxy.proxy import pdns
    server_id = rt.settings.upstream_server_id
    try:
        exists = await fetch_zone(pdns, server_id, zone)
    except RuntimeError:
        raise HTTPException(503, "upstream unavailable, cannot verify zone existence")
    if exists is not None:
        raise HTTPException(409, "zone already exists upstream")

    payload = {"name": zone, "kind": reg.kind, "nameservers": reg.nameservers}
    path = f"/api/v1/servers/{server_id}/zones"
    info = classify("POST", path)
    assert info is not None
    # Journal against the target Teilnehmer so the registration shows up in
    # their own journal history; actor stays the registrar credential.
    journal_identity = dataclasses.replace(identity, effective_teilnehmer=tn)
    capture = JournalCapture(rt, pdns, journal_identity, "POST", path, info, payload)
    # Per-zone serialization, same as JournalMiddleware.
    async with rt.zone_lock(zone):
        try:
            await capture.intent()
        except Exception:
            logger.exception("journal intent failed for register (fail-closed)")
            raise HTTPException(503, "journal unavailable, registration refused")
        try:
            resp = await pdns.request("POST", path, payload=payload)
        except BaseException:
            await capture.mark_uncertain()
            raise
        await capture.finalize(resp.status)
    if resp.status == 409:
        raise HTTPException(409, "zone already exists upstream")
    if resp.status >= 400:
        raise HTTPException(502, f"upstream rejected zone create: {resp.status}")

    generation = None
    conflicting_owner = None
    for _ in range(3):  # CAS retry: the exporter may push concurrently
        # Re-check ownership on every attempt: a concurrent exporter push may
        # have mapped the zone already — adding a second owner would break the
        # single-ownership invariant owner_of/rollback rely on.
        owner = rt.mapping.view.owner_of(zone)
        if owner == tn:
            generation = rt.mapping.view.generation  # already mapped, done
            break
        if owner is not None:
            conflicting_owner = owner
            break
        try:
            generation = await rt.mapping.patch(
                rt.mapping.view.generation, {tn: [zone]}, {}, identity.actor
            )
            break
        except GenerationMismatch:
            continue
    if conflicting_owner is not None:
        # The exporter cannot heal this to the requested owner — a 201 with
        # the requested teilnehmer would be a lie. Zone stays created
        # (journaled); the conflict needs human/exporter resolution.
        logger.error(
            f"register: {zone} concurrently mapped to {conflicting_owner}, "
            f"not {tn} — leaving mapping untouched (journal {capture.journal_id})"
        )
        raise HTTPException(
            409, "zone created but concurrently mapped to another Teilnehmer"
        )
    if generation is None:
        # Zone exists but unowned; the next exporter push (member DB is the
        # source of registrations) heals this. Surface it, don't hide it.
        logger.error(f"mapping update failed after zone create ({zone} -> {tn})")
    return JSONResponse(
        {
            "zone": zone,
            "teilnehmer": tn,
            "journal_id": capture.journal_id,
            "mapping_generation": generation,
        },
        status_code=201,
    )


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
    # Minting requires a strongly-authenticated OIDC session (admin
    # impersonation now, member OIDC later). The shared webui act-as token
    # deliberately cannot mint: a compromised UI host must not be able to
    # create persistent per-member credentials that survive token rotation
    # (luna review 2026-07-15).
    if identity.kind != "oidc":
        raise HTTPException(403, "key minting requires an OIDC session")
    plaintext, prefix, key_hash = generate_key()
    try:
        key_id = await rt.store.insert_key(
            tn, prefix, key_hash, body.label, identity.kind,
            rt.settings.max_keys_per_teilnehmer,
        )
    except KeyLimitReached:
        raise HTTPException(409, "key limit reached")
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
    # Contract (docs/api-contract.md): ADM/EXP/MET only — webui and registrar
    # envs have no business reading ops internals. Admin is checked via
    # is_admin, never via the roles list: an act-as identity inherits its
    # env's full role list without being an admin.
    if not (
        identity.is_admin
        or "exporter" in identity.roles
        or "metrics" in identity.roles
    ):
        raise HTTPException(403, "admin, exporter or metrics credential required")
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
    # sync file read + YAML parse — keep it off the event loop
    await asyncio.to_thread(reload_static_config)
    return {"reloaded": True}


def _identity_admin() -> Identity:
    identity = _identity()
    _require_admin(identity)
    return identity
