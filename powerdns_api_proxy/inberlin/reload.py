"""Static YAML reload via SIGHUP or POST /proxy/v1/admin/reload.

Only the static config (upstream token, environments, inberlin settings) is
re-read; dynamic state (mapping, keys, journal) lives in SQLite and memory and
is unaffected. Upstream load_config() is lru_cached — clearing both caches and
re-validating achieves an atomic swap (the caches repopulate on next call)."""

import os
import signal
from pathlib import Path

from powerdns_api_proxy.config import load_config
from powerdns_api_proxy.inberlin.settings import (
    load_inberlin_settings,
    reset_settings_cache,
)
from powerdns_api_proxy.logging import logger


def reload_static_config() -> None:
    """Reload the static YAML. Validates the new file BEFORE clearing the live
    caches, so a broken config leaves the running process untouched instead of
    emptying load_config()'s cache and 500-ing every subsequent request."""
    logger.info("reloading static configuration")
    path = os.getenv("PROXY_CONFIG_PATH")
    if not path:
        raise ValueError("PROXY_CONFIG_PATH not set")

    # Parse-check against a fresh path (cache-miss) without disturbing the
    # currently cached objects. Raises on a broken file — caches stay warm.
    load_config(Path(path))

    # New file is valid: now swap the caches atomically.
    load_config.cache_clear()
    reset_settings_cache()
    load_config()
    load_inberlin_settings()
    logger.info("static configuration reloaded")


def install_sighup_handler() -> None:
    def _handler(signum, frame):
        try:
            reload_static_config()
        except Exception:
            pass
    try:
        signal.signal(signal.SIGHUP, _handler)
        logger.info("SIGHUP config reload handler installed")
    except ValueError:
        # not in main thread (e.g. under test runner)
        pass
