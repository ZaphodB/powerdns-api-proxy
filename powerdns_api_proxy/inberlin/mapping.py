"""In-memory Teilnehmer→zones mapping with generation CAS and atomic swap.

The dict reference swap is atomic under CPython/asyncio; readers never lock.
SQLite persistence happens in the same Store transaction that bumps the
generation, so memory and disk cannot diverge on a successful request.
"""

from dataclasses import dataclass
from typing import Optional

from powerdns_api_proxy.inberlin.names import (
    canonical_tn,
    canonical_zone,
    zone_depth,
    zone_is_or_under,
)
from powerdns_api_proxy.inberlin.store import Store


@dataclass(frozen=True)
class MappingView:
    """Immutable snapshot of the authz mapping; replaced wholesale on update."""

    generation: int
    zones_by_tn: dict[str, frozenset[str]]
    overrides: dict[str, str]  # canonical zone -> canonical tn
    deny_zones: tuple[str, ...] = ()

    def zones_for(self, teilnehmer: str) -> set[str]:
        """Mapped zones plus override grants for a Teilnehmer (canonical)."""
        tn = canonical_tn(teilnehmer)
        zones = set(self.zones_by_tn.get(tn, frozenset()))
        zones.update(z for z, owner in self.overrides.items() if owner == tn)
        return zones

    def owner_of(self, zone: str) -> Optional[str]:
        """Resolution per docs/authz-flow.md §5: deny set, then most-specific
        override on the zone or an ancestor, then longest owned suffix."""
        z = canonical_zone(zone)
        for denied in self.deny_zones:
            if zone_is_or_under(z, denied):
                return None
        best_override: tuple[int, str] | None = None
        for ov_zone, owner in self.overrides.items():
            if zone_is_or_under(z, ov_zone):
                depth = zone_depth(ov_zone)
                if best_override is None or depth > best_override[0]:
                    best_override = (depth, owner)
        # Overrides are deliberate admin exceptions to the bulk-exported
        # mapping: any applicable override (on the zone or an ancestor) wins
        # over implicit ownership, even a deeper explicit mapping entry
        # (docs/authz-flow.md §5, plan Decision 6). Most-specific override
        # wins among overrides.
        if best_override is not None:
            return best_override[1]
        best_owned: tuple[int, str] | None = None
        for tn, zones in self.zones_by_tn.items():
            for owned in zones:
                if zone_is_or_under(z, owned):
                    depth = zone_depth(owned)
                    if best_owned is None or depth > best_owned[0]:
                        best_owned = (depth, tn)
        return best_owned[1] if best_owned else None


class MappingState:
    """Mutable holder of the current MappingView; writes go through the Store
    with generation CAS, then swap the view reference (atomic for readers)."""

    def __init__(self, store: Store, deny_zones: list[str]):
        self._store = store
        self._deny = tuple(canonical_zone(z) for z in deny_zones)
        self.view = MappingView(0, {}, {}, self._deny)

    async def load(self) -> None:
        """Restore the last committed snapshot from SQLite (startup path)."""
        generation, mapping, overrides = await self._store.load_mapping()
        self.view = self._build(generation, mapping, overrides)

    def _build(
        self, generation: int, mapping: dict[str, set[str]], overrides: dict[str, str]
    ) -> MappingView:
        """Canonicalize all names once at build time so lookups stay cheap."""
        return MappingView(
            generation=generation,
            zones_by_tn={
                canonical_tn(tn): frozenset(canonical_zone(z) for z in zones)
                for tn, zones in mapping.items()
            },
            overrides={
                canonical_zone(z): canonical_tn(tn) for z, tn in overrides.items()
            },
            deny_zones=self._deny,
        )

    async def replace(
        self, expected_generation: int, mapping: dict[str, list[str]], actor: str
    ) -> int:
        """Full replace (PUT). CAS on expected_generation; returns new generation."""
        normalized = {
            canonical_tn(tn): {canonical_zone(z) for z in zones}
            for tn, zones in mapping.items()
        }
        new_gen = await self._store.save_mapping(
            expected_generation, normalized, actor, {"mapping": mapping}
        )
        # Overrides live in a separate table untouched by save_mapping; reuse
        # the current in-memory copy so a transient read failure can't leave
        # memory behind the committed generation.
        self.view = self._build(new_gen, normalized, dict(self.view.overrides))
        return new_gen

    async def patch(
        self,
        expected_generation: int,
        add: dict[str, list[str]],
        remove: dict[str, list[str]],
        actor: str,
    ) -> int:
        """Incremental add/remove (PATCH). Same CAS semantics as replace()."""
        current = {tn: set(zones) for tn, zones in self.view.zones_by_tn.items()}
        for tn, zones in add.items():
            current.setdefault(canonical_tn(tn), set()).update(
                canonical_zone(z) for z in zones
            )
        for tn, zones in remove.items():
            ctn = canonical_tn(tn)
            if ctn in current:
                current[ctn] -= {canonical_zone(z) for z in zones}
                if not current[ctn]:
                    del current[ctn]
        new_gen = await self._store.save_mapping(
            expected_generation, current, actor,
            {"patch": {"add": add, "remove": remove}},
        )
        self.view = self._build(new_gen, current, dict(self.view.overrides))
        return new_gen

    async def reload_overrides(self) -> None:
        """Rebuild the view after an override table change (keeps generation)."""
        generation, mapping, overrides = await self._store.load_mapping()
        self.view = self._build(self.view.generation, mapping, overrides)

    def orphaned_overrides(self) -> list[str]:
        """Override zones whose grantee has no mapping entry at all."""
        return [
            z for z, tn in self.view.overrides.items()
            if tn not in self.view.zones_by_tn
        ]
