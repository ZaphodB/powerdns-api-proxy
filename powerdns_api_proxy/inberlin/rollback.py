"""Rollback: inverse-apply a committed journal entry via the normal pdns API.

Inverse table (docs/api-contract.md):
  created RRset          -> DELETE
  deleted/replaced RRset -> REPLACE with complete prior RRset (records + TTL)
  zone-delete            -> recreate from journaled export (DNSSEC/catalog excluded)
  zone-create            -> delete zone (admin confirmation happens at the API layer)

Drift check: live state must equal the recorded after-state, else 409
(admin force overrides). The rollback request goes through the proxy's own
journal middleware semantics by journaling a new entry with rollback_of set.
"""

import json
from typing import Any

from powerdns_api_proxy.inberlin.journal import fetch_zone, rrsets_by_key
from powerdns_api_proxy.inberlin.names import canonical_zone
from powerdns_api_proxy.pdns import PDNSConnector


class NotRollbackable(Exception):
    """Entry has no inverse (crypto/tsig/meta ops, or missing recorded state)."""


def _normalize_rrset(rrset: dict | None) -> dict | None:
    """Canonical comparable form (name canonicalized, records sorted) for drift checks."""
    if rrset is None:
        return None
    return {
        "name": canonical_zone(rrset["name"]),
        "type": rrset["type"],
        "ttl": rrset.get("ttl"),
        "records": sorted(
            (
                {"content": r["content"], "disabled": bool(r.get("disabled", False))}
                for r in rrset.get("records", [])
            ),
            key=lambda r: (r["content"], r["disabled"]),
        ),
    }


def inverse_rrsets(entry_rrsets: list[dict]) -> list[dict]:
    """Builds the PATCH rrsets list that undoes the entry."""
    patch = []
    for row in entry_rrsets:
        before = json.loads(row["before_rrset"]) if row["before_rrset"] else None
        if before is None:
            patch.append(
                {"name": row["name"], "type": row["rtype"], "changetype": "DELETE"}
            )
        else:
            patch.append(
                {
                    "name": row["name"],
                    "type": row["rtype"],
                    "changetype": "REPLACE",
                    "ttl": before.get("ttl"),
                    "records": [
                        {
                            "content": r["content"],
                            "disabled": bool(r.get("disabled", False)),
                        }
                        for r in before.get("records", [])
                    ],
                }
            )
    return patch


async def check_drift(
    pdns: PDNSConnector, server_id: str, zone: str, entry_rrsets: list[dict]
) -> list[str]:
    """Returns list of drift descriptions (empty = live state matches after)."""
    live_zone = await fetch_zone(pdns, server_id, zone)
    live = rrsets_by_key(live_zone)
    drift = []
    for row in entry_rrsets:
        key = (canonical_zone(row["name"]), row["rtype"])
        recorded_after = json.loads(row["after_rrset"]) if row["after_rrset"] else None
        if _normalize_rrset(live.get(key)) != _normalize_rrset(recorded_after):
            drift.append(f"{row['name']}/{row['rtype']} changed since this entry")
    return drift


def zone_state_drift(live: dict | None, recorded_after: dict | None) -> list[str]:
    """Drift between a live zone and a recorded whole-zone after-state
    (zone-create rollback: the zone about to be deleted must still look
    exactly like it did right after creation)."""
    if live is None:
        return ["zone no longer exists"]
    if not recorded_after:
        return ["no recorded after-state to compare against"]
    live_map = rrsets_by_key(live)
    rec_map = rrsets_by_key(recorded_after)
    drift = []
    for key in sorted(set(live_map) | set(rec_map)):
        if _normalize_rrset(live_map.get(key)) != _normalize_rrset(rec_map.get(key)):
            drift.append(f"{key[0]}/{key[1]} changed since this entry")
    return drift


async def check_entry_drift(
    entry: dict, pdns: PDNSConnector, server_id: str
) -> list[str]:
    """Drift between live upstream state and the entry's recorded after-state
    (empty = safe to apply the inverse). Every rollbackable operation gets a
    check, not just RRset patches: deleting a zone that changed since
    creation, or recreating one that already exists again, silently destroys
    someone else's later work. Raises RuntimeError on upstream failure."""
    op = entry["operation"]
    if op == "rrset-patch":
        return await check_drift(pdns, server_id, entry["zone"], entry["rrsets"])
    if op == "zone-create":
        live = await fetch_zone(pdns, server_id, entry["zone"])
        after = json.loads(entry["after_state"]) if entry.get("after_state") else None
        return zone_state_drift(live, after)
    if op == "zone-delete":
        live = await fetch_zone(pdns, server_id, entry["zone"])
        return [] if live is None else ["zone was recreated since this entry"]
    return []


def build_rollback_request(entry: dict) -> tuple[str, str, dict[str, Any] | None]:
    """Returns (method, path_suffix, body) to execute against /api/v1.

    path_suffix is relative to /api/v1/servers/{server_id}.
    """
    op = entry["operation"]
    zone = entry["zone"]
    if op == "rrset-patch":
        if not entry.get("rrsets"):
            raise NotRollbackable()
        return "PATCH", f"/zones/{zone}", {"rrsets": inverse_rrsets(entry["rrsets"])}
    if op == "zone-delete":
        export = json.loads(entry["before_state"]) if entry["before_state"] else None
        if not export:
            raise NotRollbackable()
        body = {
            k: v
            for k, v in export.items()
            if k in ("name", "kind", "masters", "nameservers", "rrsets", "account")
        }
        body.setdefault("kind", "Native")
        # NS records live in rrsets of the export; nameservers list must be
        # empty to avoid duplicate NS creation.
        body["nameservers"] = []
        return "POST", "/zones", body
    if op == "zone-create":
        return "DELETE", f"/zones/{zone}", None
    raise NotRollbackable()
