"""Canonicalization and label-boundary matching for zones and Teilnehmer ids.

Authorization must never use raw string suffix matching (docs/authz-flow.md §5).
"""

import unicodedata


def canonical_tn(name: str) -> str:
    """Canonical Teilnehmer identifier: NFC, lowercase, stripped."""
    return unicodedata.normalize("NFC", name.strip()).lower()


def canonical_zone(zone: str) -> str:
    """Canonical zone name: lowercase, IDNA where applicable, single trailing dot."""
    z = zone.strip().rstrip(".").lower()
    try:
        z = z.encode("idna").decode("ascii") if any(ord(c) > 127 for c in z) else z
    except UnicodeError:
        pass
    return z + "."


def zone_is_or_under(zone: str, parent: str) -> bool:
    """True if zone == parent or zone is under parent, on label boundaries."""
    z = canonical_zone(zone)
    p = canonical_zone(parent)
    return z == p or z.endswith("." + p)


def zone_depth(zone: str) -> int:
    return canonical_zone(zone).rstrip(".").count(".") + 1
