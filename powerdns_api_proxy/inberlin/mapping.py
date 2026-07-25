"""In-memory User→zones mapping with generation CAS and atomic swap.

The dict reference swap is atomic under CPython/asyncio; readers never lock.
SQLite persistence happens in the same Store transaction that bumps the
generation, so memory and disk cannot diverge on a successful request.
"""

import asyncio
from dataclasses import dataclass

from powerdns_api_proxy.inberlin.names import (
    canonical_user,
    canonical_zone,
    zone_depth,
    zone_is_or_under,
)
from powerdns_api_proxy.inberlin.store import Store


@dataclass(frozen=True)
class MappingView:
    """Immutable snapshot of the authz mapping; replaced wholesale on update."""

    generation: int
    zones_by_user: dict[str, frozenset[str]]
    overrides: dict[str, str]  # canonical zone -> canonical user
    deny_zones: tuple[str, ...] = ()
    # Denied as an exact zone; subzones are unaffected. in-berlin.de is the
    # driving case: the apex must never resolve to a member, but every member
    # zone is a subzone of it, so a subtree deny would lock out the entire
    # namespace the service exists to delegate.
    deny_zones_exact: tuple[str, ...] = ()
    applied_at: str = ""  # commit timestamp of generation; "" for empty store

    def zones_for(self, user: str) -> set[str]:
        """Mapped zones plus override grants for a User (canonical)."""
        canonical = canonical_user(user)
        zones = set(self.zones_by_user.get(canonical, frozenset()))
        zones.update(z for z, owner in self.overrides.items() if owner == canonical)
        return zones

    def is_denied(self, zone: str) -> bool:
        """True if the zone is in the deny set, by subtree or exact match.

        Both sides are canonicalized rather than compared as given: MappingState
        already stores canonical entries, but a deny list that silently stops
        matching because a caller wrote `in-berlin.de` instead of
        `in-berlin.de.` would fail OPEN, and this list exists precisely to be
        the last word.
        """
        z = canonical_zone(zone)
        if any(zone_is_or_under(z, denied) for denied in self.deny_zones):
            return True
        return any(z == canonical_zone(denied) for denied in self.deny_zones_exact)

    def owner_of(self, zone: str) -> str | None:
        """Resolution per docs/authz-flow.md §5: deny set, then most-specific
        override on the zone or an ancestor, then longest owned suffix."""
        z = canonical_zone(zone)
        if self.is_denied(z):
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
        for user, zones in self.zones_by_user.items():
            for owned in zones:
                if zone_is_or_under(z, owned):
                    depth = zone_depth(owned)
                    if best_owned is None or depth > best_owned[0]:
                        best_owned = (depth, user)
        return best_owned[1] if best_owned else None


class MappingState:
    """Mutable holder of the current MappingView; writes go through the Store
    with generation CAS, then swap the view reference (atomic for readers)."""

    def __init__(
        self,
        store: Store,
        deny_zones: list[str],
        deny_zones_exact: list[str] | None = None,
    ):
        self._store = store
        self._deny = tuple(canonical_zone(z) for z in deny_zones)
        self._deny_exact = tuple(canonical_zone(z) for z in (deny_zones_exact or []))
        self.view = MappingView(0, {}, {}, self._deny, self._deny_exact)
        # Serializes every "store mutation/read → view swap" sequence: two
        # interleaved updaters (mapping write vs override reload) could
        # otherwise each await mid-sequence and install a view built from
        # data older than what the other already published.
        self._mutation_lock = asyncio.Lock()

    async def load(self) -> None:
        """Restore the last committed snapshot from SQLite (startup path)."""
        async with self._mutation_lock:
            await self._reload_locked()

    async def _reload_locked(self) -> None:
        """Rebuild the view from the store; caller must hold _mutation_lock."""
        generation, applied_at, mapping, overrides = await self._store.load_mapping()
        self.view = self._build(generation, mapping, overrides, applied_at)

    def _build(
        self,
        generation: int,
        mapping: dict[str, set[str]],
        overrides: dict[str, str],
        applied_at: str = "",
    ) -> MappingView:
        """Canonicalize all names once at build time so lookups stay cheap."""
        return MappingView(
            generation=generation,
            zones_by_user={
                canonical_user(user): frozenset(canonical_zone(z) for z in zones)
                for user, zones in mapping.items()
            },
            overrides={
                canonical_zone(z): canonical_user(user) for z, user in overrides.items()
            },
            deny_zones=self._deny,
            deny_zones_exact=self._deny_exact,
            applied_at=applied_at,
        )

    async def replace(
        self, expected_generation: int, mapping: dict[str, list[str]], actor: str
    ) -> int:
        """Full replace (PUT). CAS on expected_generation; returns new generation."""
        normalized = {
            canonical_user(user): {canonical_zone(z) for z in zones}
            for user, zones in mapping.items()
        }
        async with self._mutation_lock:
            new_gen, applied_at = await self._store.save_mapping(
                expected_generation, normalized, actor, {"mapping": mapping}
            )
            # Overrides live in a separate table untouched by save_mapping; reuse
            # the current in-memory copy so a transient read failure can't leave
            # memory behind the committed generation.
            self.view = self._build(
                new_gen, normalized, dict(self.view.overrides), applied_at
            )
            return new_gen

    async def patch(
        self,
        expected_generation: int,
        add: dict[str, list[str]],
        remove: dict[str, list[str]],
        actor: str,
    ) -> int:
        """Incremental add/remove (PATCH). Same CAS semantics as replace()."""
        async with self._mutation_lock:
            current = {
                user: set(zones) for user, zones in self.view.zones_by_user.items()
            }
            for user, zones in add.items():
                current.setdefault(canonical_user(user), set()).update(
                    canonical_zone(z) for z in zones
                )
            for user, zones in remove.items():
                cuser = canonical_user(user)
                if cuser in current:
                    current[cuser] -= {canonical_zone(z) for z in zones}
                    if not current[cuser]:
                        del current[cuser]
            new_gen, applied_at = await self._store.save_mapping(
                expected_generation,
                current,
                actor,
                {"patch": {"add": add, "remove": remove}},
            )
            self.view = self._build(
                new_gen, current, dict(self.view.overrides), applied_at
            )
            return new_gen

    async def add_override(
        self,
        expected_generation: int,
        zone: str,
        user: str,
        actor: str,
        note: str | None,
    ) -> tuple[int, int]:
        """Persist an override grant and republish the view atomically.

        CAS on the shared generation (docs/api-contract.md line 41): the grant
        and the generation bump commit in one store transaction, so an
        override racing an exporter full-replace loses with a 409 instead of
        silently applying against a mapping the admin hadn't seen. The store
        write must happen under the same lock as the view swap:
        committed-but-not-yet-published override state is exactly the window
        a concurrent mapping update would clobber.
        Returns (override_id, new generation)."""
        async with self._mutation_lock:
            override_id, new_gen = await self._store.add_override(
                zone, user, actor, note, expected_generation
            )
            await self._reload_locked()
            return override_id, new_gen

    async def delete_override(
        self, expected_generation: int, override_id: int, actor: str
    ) -> tuple[bool, int]:
        """Delete an override grant and republish the view atomically.
        Returns (deleted, new-or-current generation)."""
        async with self._mutation_lock:
            deleted, new_gen = await self._store.delete_override(
                override_id, expected_generation, actor
            )
            if deleted:
                await self._reload_locked()
            return deleted, new_gen

    def orphaned_overrides(self) -> list[str]:
        """Override zones whose grantee has no mapping entry at all."""
        return [
            z
            for z, user in self.view.overrides.items()
            if user not in self.view.zones_by_user
        ]
