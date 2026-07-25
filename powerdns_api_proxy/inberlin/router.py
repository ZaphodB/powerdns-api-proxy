"""/proxy/v1 router: mapping, overrides, journal, rollback, register, keys,
identity, health/ready, reload (docs/api-contract.md)."""

import asyncio
import dataclasses
import sqlite3

from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from powerdns_api_proxy.inberlin.identity import Identity, current_identity
from powerdns_api_proxy.inberlin.journal import (
    JournalCapture,
    classify,
    fetch_zone,
    run_journaled,
)
from powerdns_api_proxy.inberlin.keys import generate_key
from powerdns_api_proxy.inberlin.mapping import DuplicateZoneOwner
from powerdns_api_proxy.inberlin.names import canonical_user, canonical_zone
from powerdns_api_proxy.inberlin.rollback import (
    NotRollbackable,
    build_rollback_request,
    check_entry_drift,
)
from powerdns_api_proxy.inberlin.roles import EXPORTER, METRICS, REGISTRAR
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
    if not (identity.is_admin or EXPORTER in identity.roles):
        raise HTTPException(403, "exporter or admin required")


def _require_session_user(identity: Identity) -> str:
    """Journal/rollback access needs a session (act-as or OIDC), never a key."""
    if identity.kind == "tn-key":
        raise HTTPException(403, "not available for API keys, use a session")
    return _require_user(identity)


def _require_user(identity: Identity) -> str:
    if not identity.effective_user:
        raise HTTPException(403, "no effective User for this credential")
    return identity.effective_user


def _require_generation(if_match: str | None) -> int:
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
async def put_mapping(body: MappingPut, if_match: str | None = Header(None)):
    rt, identity = _runtime(), _identity()
    _require_exporter_or_admin(identity)
    expected = _require_generation(if_match)
    try:
        generation = await rt.mapping.replace(expected, body.mapping, identity.actor)
    except GenerationMismatch as e:
        raise HTTPException(409, f"generation mismatch, current is {e.current}")
    except DuplicateZoneOwner as e:
        # Ambiguous ownership would make owner_of() depend on dict ordering.
        raise HTTPException(422, str(e))
    orphans = rt.mapping.orphaned_overrides()
    return {"generation": generation, "orphaned_overrides": orphans}


@router.patch("/mapping")
async def patch_mapping(body: MappingPatch, if_match: str | None = Header(None)):
    rt, identity = _runtime(), _identity()
    _require_exporter_or_admin(identity)
    expected = _require_generation(if_match)
    try:
        generation = await rt.mapping.patch(
            expected, body.add, body.remove, identity.actor
        )
    except GenerationMismatch as e:
        raise HTTPException(409, f"generation mismatch, current is {e.current}")
    except DuplicateZoneOwner as e:
        raise HTTPException(422, str(e))
    return {
        "generation": generation,
        "orphaned_overrides": rt.mapping.orphaned_overrides(),
    }


@router.get("/mapping")
async def get_mapping():
    rt, identity = _runtime(), _identity()
    _require_admin(identity)
    view = rt.mapping.view
    return {
        "generation": view.generation,
        "applied_at": view.applied_at,
        "mapping": {user: sorted(zones) for user, zones in view.zones_by_user.items()},
    }


@router.get("/mapping/self")
async def get_mapping_self():
    rt, identity = _runtime(), _identity()
    user = _require_user(identity)
    view = rt.mapping.view
    # Resolve through owner_of rather than returning the raw mapping entries, so
    # this agrees with what the member can actually do: a denied zone, or one an
    # override reassigned, is not theirs. environment_for_user() already filters
    # the same way; without this, a UI built on /mapping/self would advertise a
    # zone whose every operation 403s.
    zones = sorted(z for z in view.zones_for(user) if view.owner_of(z) == user)
    return {"user": user, "zones": zones}


# -- overrides --------------------------------------------------------------


class OverrideCreate(BaseModel):
    zone: str
    user: str
    note: str | None = None


@router.get("/overrides")
async def list_overrides():
    rt, identity = _runtime(), _identity()
    _require_admin(identity)
    return {"overrides": await rt.store.list_overrides()}


@router.post("/overrides", status_code=201)
async def create_override(body: OverrideCreate, if_match: str | None = Header(None)):
    rt, identity = _runtime(), _identity()
    _require_admin(identity)
    expected = _require_generation(if_match)
    zone = canonical_zone(body.zone)
    try:
        override_id, generation = await rt.mapping.add_override(
            expected, zone, canonical_user(body.user), identity.actor, body.note
        )
    except GenerationMismatch as e:
        raise HTTPException(409, f"generation mismatch, current is {e.current}")
    except sqlite3.IntegrityError:
        raise HTTPException(409, "override for this zone already exists")
    return {"id": override_id, "zone": zone, "generation": generation}


@router.delete("/overrides/{override_id}")
async def delete_override(override_id: int, if_match: str | None = Header(None)):
    rt, identity = _runtime(), _identity()
    _require_admin(identity)
    expected = _require_generation(if_match)
    try:
        deleted, generation = await rt.mapping.delete_override(
            expected, override_id, identity.actor
        )
    except GenerationMismatch as e:
        raise HTTPException(409, f"generation mismatch, current is {e.current}")
    if not deleted:
        raise HTTPException(404, "override not found")
    return {"deleted": override_id, "generation": generation}


# -- journal ----------------------------------------------------------------


def _journal_row_public(row: dict) -> dict:
    """List-view projection: metadata only, no before/after payloads."""
    return {
        k: row[k]
        for k in (
            "id",
            "ts",
            "status",
            "user",
            "actor",
            "actor_kind",
            "impersonator",
            "webui_user",
            "zone",
            "method",
            "path",
            "operation",
            "status_code",
            "rollbackable",
            "rollback_of",
        )
        if k in row
    }


@router.get("/journal")
async def query_journal(
    zone: str | None = None,
    name: str | None = None,
    type: str | None = None,
    since: str | None = None,
    until: str | None = None,
    user: str | None = None,
    limit: int = 100,
    offset: int = 0,
):
    rt, identity = _runtime(), _identity()
    if identity.is_admin:
        tn_filter = canonical_user(user) if user else None
    else:
        if user is not None:
            raise HTTPException(403, "user filter is admin-only")
        tn_filter = _require_session_user(identity)
    rows = await rt.store.journal_query(
        user=tn_filter,
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
    """Pending/uncertain rows plus live upstream state per affected zone
    (docs/api-contract.md line 46) — reconciliation without manual refetching."""
    rt, identity = _runtime(), _identity()
    _require_admin(identity)
    pending = await rt.store.journal_query(status="pending", limit=500)
    uncertain = await rt.store.journal_query(status="uncertain", limit=500)
    rows = pending + uncertain

    from powerdns_api_proxy.proxy import pdns

    server_id = rt.settings.upstream_server_id
    upstream: dict[str, dict | None] = {}
    for zone in {r["zone"] for r in rows} - {"."}:
        try:
            upstream[zone] = await fetch_zone(pdns, server_id, zone)
        except Exception:
            upstream[zone] = {"error": "upstream fetch failed"}
    return {"entries": [_journal_row_public(r) for r in rows], "upstream": upstream}


@router.get("/journal/{journal_id}")
async def get_journal_entry(journal_id: int):
    rt, identity = _runtime(), _identity()
    entry = await rt.store.journal_get(journal_id)
    if entry is None:
        raise HTTPException(404, "journal entry not found")
    if not identity.is_admin and entry["user"] != _require_session_user(identity):
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
    if not identity.is_admin and entry["user"] != _require_session_user(identity):
        raise HTTPException(404, "journal entry not found")
    if entry["status"] != "committed" or not entry["rollbackable"]:
        raise HTTPException(409, "entry is not rollbackable")
    if body.force and not identity.is_admin:
        raise HTTPException(403, "force is admin-only")

    # current authz on the zone required (ownership may have changed)
    if not identity.is_admin:
        owner = rt.mapping.view.owner_of(entry["zone"])
        if owner != identity.effective_user:
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

    async def drift_check() -> None:
        # Re-check ownership HERE, not only above: this runs after the per-zone
        # lock is held and immediately before journal intent and the upstream
        # mutation, whereas the earlier check happens while any concurrent
        # mapping update can still land (mapping writes take a different lock).
        # Without this, a member whose zone was reassigned or denied between the
        # two points could still roll the zone back. The earlier check stays as
        # a cheap early rejection; this one is the security boundary.
        if not identity.is_admin:
            current = rt.mapping.view.owner_of(entry["zone"])
            if current != identity.effective_user:
                raise HTTPException(403, "no current authorization on this zone")
        if body.force:
            return
        try:
            drift = await check_entry_drift(entry, pdns, server_id)
        except RuntimeError:
            raise HTTPException(502, "upstream unavailable, cannot verify drift")
        if drift:
            raise HTTPException(409, "state drifted: " + "; ".join(drift))

    resp = await run_journaled(
        capture,
        rt.zone_lock(canonical_zone(entry["zone"])),
        lambda: pdns.request(method, path, payload=payload or {}),
        status_of=lambda r: r.status,
        rollback_of=journal_id,
        before_intent=drift_check,
    )
    if resp is None:
        raise HTTPException(503, "journal unavailable, rollback refused")
    if resp.status >= 400:
        raise HTTPException(502, f"upstream rejected rollback: {resp.status}")
    result: dict[str, object] = {
        "rolled_back": journal_id,
        "journal_id": capture.journal_id,
    }
    if entry["operation"] == "zone-delete":
        # Recreate-from-export cannot restore DNSSEC keys or catalog
        # membership (docs/api-contract.md line 79-80) — flag the loss.
        result["lossy"] = True
        result["lossy_detail"] = "DNSSEC and catalog state not restored"
    return result


# -- registration -------------------------------------------------------------


class RegisterBody(BaseModel):
    zone: str
    user: str


@router.post("/register", status_code=201)
async def register_zone(body: RegisterBody):
    """Create-only domain registration (registrar role or admin): new zone
    from the configured template + mapping entry for the User, both
    journaled. Existing zones are never touched — pdns rejects duplicate
    creates with an unconditional 409 (verified in auth-5.1.x ws-auth.cc),
    so this credential structurally cannot modify existing data."""
    rt, identity = _runtime(), _identity()
    if not (identity.is_admin or REGISTRAR in identity.roles):
        raise HTTPException(403, "registrar or admin required")
    reg = rt.settings.registration
    if reg is None:
        raise HTTPException(501, "registration not configured")
    zone = canonical_zone(body.zone)
    user = canonical_user(body.user)
    view = rt.mapping.view
    if view.is_denied(zone):
        raise HTTPException(403, "zone is on the deny list")
    if view.owner_of(zone) is not None:
        raise HTTPException(409, "zone already owned by a User")

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
    # Journal against the target User so the registration shows up in
    # their own journal history; actor stays the registrar credential.
    journal_identity = dataclasses.replace(identity, effective_user=user)
    capture = JournalCapture(rt, pdns, journal_identity, "POST", path, info, payload)
    resp = await run_journaled(
        capture,
        rt.zone_lock(zone),
        lambda: pdns.request("POST", path, payload=payload),
        status_of=lambda r: r.status,
    )
    if resp is None:
        raise HTTPException(503, "journal unavailable, registration refused")
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
        if owner == user:
            generation = rt.mapping.view.generation  # already mapped, done
            break
        if owner is not None:
            conflicting_owner = owner
            break
        try:
            generation = await rt.mapping.patch(
                rt.mapping.view.generation, {user: [zone]}, {}, identity.actor
            )
            break
        except GenerationMismatch:
            continue
    if conflicting_owner is not None:
        # The exporter cannot heal this to the requested owner — a 201 with
        # the requested user would be a lie. Zone stays created
        # (journaled); the conflict needs human/exporter resolution.
        logger.error(
            f"register: {zone} concurrently mapped to {conflicting_owner}, "
            f"not {user} — leaving mapping untouched (journal {capture.journal_id})"
        )
        raise HTTPException(409, "zone created but concurrently mapped to another User")
    if generation is None:
        # Zone exists but unowned; the next exporter push (member DB is the
        # source of registrations) heals this. Surface it, don't hide it.
        logger.error(f"mapping update failed after zone create ({zone} -> {user})")
    return JSONResponse(
        {
            "zone": zone,
            "user": user,
            "journal_id": capture.journal_id,
            "mapping_generation": generation,
        },
        status_code=201,
    )


# -- keys ---------------------------------------------------------------------


class KeyCreate(BaseModel):
    label: str | None = None


@router.get("/keys")
async def list_keys():
    rt, identity = _runtime(), _identity()
    user = _require_user(identity)
    return {"keys": await rt.store.list_keys(user)}


@router.post("/keys", status_code=201)
async def create_key(body: KeyCreate):
    rt, identity = _runtime(), _identity()
    user = _require_user(identity)
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
            user,
            prefix,
            key_hash,
            body.label,
            identity.kind,
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
    scope = None if identity.is_admin else _require_user(identity)
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
        # wire name stays teilnehmer (docs/api-contract.md line 52); the
        # internal field is effective_user
        "effective_teilnehmer": identity.effective_user,
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
        identity.is_admin or EXPORTER in identity.roles or METRICS in identity.roles
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
    _require_admin(_identity())
    from powerdns_api_proxy.inberlin.reload import reload_static_config

    # sync file read + YAML parse — keep it off the event loop
    await asyncio.to_thread(reload_static_config)
    return {"reloaded": True}
