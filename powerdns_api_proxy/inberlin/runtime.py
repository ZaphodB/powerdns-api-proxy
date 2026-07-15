"""Process-wide runtime for the IN-Berlin extension, initialized from the app
lifespan. None when the `inberlin:` config block is absent (extension off)."""

import asyncio
import weakref
from typing import Optional

from powerdns_api_proxy.inberlin.mapping import MappingState
from powerdns_api_proxy.inberlin.oidc import OIDCValidator
from powerdns_api_proxy.inberlin.settings import (
    InBerlinSettings,
    load_inberlin_settings,
)
from powerdns_api_proxy.inberlin.store import Store
from powerdns_api_proxy.logging import logger


class Runtime:
    """Owns the extension's long-lived state: SQLite store, in-memory mapping,
    optional OIDC validator, and the daily journal-prune task.

    Exactly one instance per process (single uvicorn worker is an operational
    requirement — the in-memory mapping and store locks are process-local).
    """

    def __init__(self, settings: InBerlinSettings):
        self.settings = settings
        self.store = Store(settings.state_db)
        self.mapping = MappingState(self.store, settings.deny_zones)
        self.oidc: Optional[OIDCValidator] = (
            OIDCValidator(settings.oidc) if settings.oidc else None
        )
        self._prune_task: Optional[asyncio.Task] = None
        # WeakValueDictionary: a lock lives only while some task holds a
        # strong reference (i.e. is inside the `async with`). Zone names come
        # from authenticated-but-arbitrary request paths — a plain dict would
        # be a slow memory leak an API-key holder could feed forever.
        self._zone_locks: weakref.WeakValueDictionary[str, asyncio.Lock] = (
            weakref.WeakValueDictionary()
        )

    def zone_lock(self, zone: str) -> asyncio.Lock:
        """Per-zone mutation lock. The journal's before/after capture is only
        correct if intent → forward → finalize runs serialized per zone —
        concurrent same-RRset writes would record stale before-states and a
        later rollback would silently wipe the intervening change. Single
        worker, so an asyncio.Lock suffices. Callers must keep the returned
        lock referenced for the whole critical section (`async with` does)."""
        lock = self._zone_locks.get(zone)
        if lock is None:
            lock = asyncio.Lock()
            self._zone_locks[zone] = lock
        return lock

    async def start(self) -> None:
        """Load the mapping snapshot from SQLite and start the prune loop."""
        await self.mapping.load()
        logger.info(
            f"inberlin runtime up: mapping generation {self.mapping.view.generation}, "
            f"{len(self.mapping.view.zones_by_tn)} user"
        )
        self._prune_task = asyncio.create_task(self._prune_loop())

    async def stop(self) -> None:
        if self._prune_task:
            self._prune_task.cancel()
        self.store.close()

    async def _prune_loop(self) -> None:
        """Daily journal retention prune (journal_retention_days, default 2y)."""
        while True:
            try:
                pruned = await self.store.journal_prune(
                    self.settings.journal_retention_days
                )
                if pruned:
                    logger.info(f"journal prune: removed {pruned} entries")
            except Exception:
                logger.exception("journal prune failed")
            await asyncio.sleep(24 * 3600)

    def env_roles(self, env_name: str) -> tuple[str, ...]:
        """Roles configured for a static environment name (empty if none)."""
        return tuple(self.settings.environment_roles.get(env_name, ()))


_runtime: Optional[Runtime] = None


def get_runtime() -> Optional[Runtime]:
    return _runtime


async def init_runtime() -> Optional[Runtime]:
    """App-lifespan entry point: build and start the runtime, or return None
    (extension disabled) when no `inberlin:` config block exists."""
    global _runtime
    settings = load_inberlin_settings()
    if settings is None:
        logger.info("inberlin extension disabled (no config block)")
        return None
    _runtime = Runtime(settings)
    await _runtime.start()
    return _runtime


async def shutdown_runtime() -> None:
    global _runtime
    if _runtime:
        await _runtime.stop()
        _runtime = None
