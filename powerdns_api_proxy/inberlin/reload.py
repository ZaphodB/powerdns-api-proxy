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
    settings = load_inberlin_settings()
    _apply_to_runtime(settings)
    logger.info("static configuration reloaded")


# Baked into objects built at startup, so re-reading the file cannot change
# them: state_db opens a connection, oidc builds a validator, and the deny lists
# are canonicalized into the immutable MappingView. Changing any of these needs
# a restart, and a reload must SAY so rather than look like it worked.
RESTART_REQUIRED_FIELDS = ("state_db", "oidc", "deny_zones", "deny_zones_exact")


def _apply_to_runtime(settings) -> None:
    """Point the live runtime at the newly loaded settings.

    Without this, a reload updated the module-level caches while every request
    kept reading `runtime.settings` — the object captured at startup. Narrowing
    `webui_source_ips` and reloading therefore appeared to work and changed
    nothing, which is a silent failure of a security control: the act-as
    credential stayed accepted from the old source. Observed on ans0,
    2026-07-25 (config said .99, request from .1 still got 200 until restart).
    """
    from powerdns_api_proxy.inberlin.runtime import get_runtime

    runtime = get_runtime()
    if runtime is None or settings is None:
        # Extension off, or reload ran before startup finished; nothing live to
        # update and init_runtime() will read the fresh settings itself.
        return

    stale = [
        field
        for field in RESTART_REQUIRED_FIELDS
        if getattr(runtime.settings, field) != getattr(settings, field)
    ]
    runtime.settings = settings
    if stale:
        logger.warning(
            "reload applied, but these settings only take effect after a "
            f"restart: {', '.join(stale)}"
        )


def install_sighup_handler() -> None:
    """Wire SIGHUP to reload_static_config(); no-op outside the main thread."""

    def _handler(signum, frame):
        try:
            reload_static_config()
        except Exception:
            # A broken new config must never kill the process from a signal
            # handler; reload_static_config left the old config live.
            logger.exception("SIGHUP config reload failed; keeping old config")

    try:
        signal.signal(signal.SIGHUP, _handler)
        logger.info("SIGHUP config reload handler installed")
    except ValueError:
        # not in main thread (e.g. under test runner)
        pass
