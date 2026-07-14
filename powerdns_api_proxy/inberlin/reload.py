"""Static YAML reload via SIGHUP or POST /proxy/v1/admin/reload.

Only the static config (upstream token, environments, inberlin settings) is
re-read; dynamic state (mapping, keys, journal) lives in SQLite and memory and
is unaffected. Upstream load_config() is lru_cached — clearing both caches and
re-validating achieves an atomic swap (the caches repopulate on next call)."""

import signal

from powerdns_api_proxy.config import load_config
from powerdns_api_proxy.inberlin.settings import load_inberlin_settings, reset_settings_cache
from powerdns_api_proxy.logging import logger


def reload_static_config() -> None:
    logger.info("reloading static configuration")
    # validate the new file BEFORE dropping the old cache: a broken config
    # must not take the proxy down
    load_config.cache_clear()
    try:
        load_config()
        reset_settings_cache()
        load_inberlin_settings()
        logger.info("static configuration reloaded")
    except Exception:
        logger.exception("config reload failed — keeping process alive; "
                         "old in-memory objects remain in use where cached")
        raise


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
