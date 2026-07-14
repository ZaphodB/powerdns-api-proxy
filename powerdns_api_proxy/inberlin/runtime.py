"""Process-wide runtime for the IN-Berlin extension, initialized from the app
lifespan. None when the `inberlin:` config block is absent (extension off)."""

import asyncio
from typing import Optional

from powerdns_api_proxy.inberlin.mapping import MappingState
from powerdns_api_proxy.inberlin.oidc import OIDCValidator
from powerdns_api_proxy.inberlin.settings import InBerlinSettings, load_inberlin_settings
from powerdns_api_proxy.inberlin.store import Store
from powerdns_api_proxy.logging import logger


class Runtime:
    def __init__(self, settings: InBerlinSettings):
        self.settings = settings
        self.store = Store(settings.state_db)
        self.mapping = MappingState(self.store, settings.deny_zones)
        self.oidc: Optional[OIDCValidator] = (
            OIDCValidator(settings.oidc) if settings.oidc else None
        )
        self._prune_task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        await self.mapping.load()
        logger.info(
            f"inberlin runtime up: mapping generation {self.mapping.view.generation}, "
            f"{len(self.mapping.view.zones_by_tn)} teilnehmer"
        )
        self._prune_task = asyncio.create_task(self._prune_loop())

    async def stop(self) -> None:
        if self._prune_task:
            self._prune_task.cancel()
        self.store.close()

    async def _prune_loop(self) -> None:
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
        return tuple(self.settings.environment_roles.get(env_name, ()))


_runtime: Optional[Runtime] = None


def get_runtime() -> Optional[Runtime]:
    return _runtime


async def init_runtime() -> Optional[Runtime]:
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
