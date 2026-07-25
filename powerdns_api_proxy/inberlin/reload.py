"""Static YAML reload via SIGHUP or POST /proxy/v1/admin/reload.

Re-read: the environment map (tokens -> grants) and the hot-swappable half of
the inberlin settings. Dynamic state (mapping, keys, journal) lives in SQLite
and memory and is unaffected.

NOT re-read, and warned about instead of silently half-applied:
  * RESTART_REQUIRED_FIELDS below — baked into objects built at startup.
  * pdns_api_url / pdns_api_token — the PDNSConnector is constructed once at
    import in proxy.py, so rotating the upstream credential needs a restart.

The swap is NOT atomic across those two halves: the environment map and the
settings object are separate references. Reloads are serialized (see the lock
below) and the ordering is chosen so the window fails closed for the case that
matters (see reload_static_config), but a caller that needs a guaranteed
coherent switch should restart. The ansible role does exactly that: it restarts
on any config change and never notifies a reload."""

import os
import signal
import threading
from pathlib import Path

from powerdns_api_proxy.config import load_config
from powerdns_api_proxy.inberlin.settings import (
    load_inberlin_settings,
    reset_settings_cache,
)
from powerdns_api_proxy.logging import logger


# Serializes reloads. A SIGHUP can interrupt the main thread at any bytecode,
# including one inside an in-flight reload started by POST /proxy/v1/admin/reload
# (which runs in a worker thread) — this code is not reentrant, and two
# interleaved reloads could combine settings from one version of the file with
# environments from another. Acquired NON-blocking precisely because a signal
# handler must never wait on a lock the interrupted code may already hold.
_reload_lock = threading.Lock()


def reload_static_config() -> bool:
    """Reload the static YAML. Validates the new file BEFORE clearing the live
    caches, so a broken config leaves the running process untouched instead of
    emptying load_config()'s cache and 500-ing every subsequent request.

    Returns False when another reload was already in flight and this one was
    skipped — the caller must not report success for a reload that did not
    happen, which is the same class of lie as a reload that silently applies
    nothing.
    """
    if not _reload_lock.acquire(blocking=False):
        logger.warning("reload already in progress; ignoring this request")
        return False
    try:
        _reload_locked()
    finally:
        _reload_lock.release()
    return True


def _reload_locked() -> None:
    logger.info("reloading static configuration")
    path = os.getenv("PROXY_CONFIG_PATH")
    if not path:
        raise ValueError("PROXY_CONFIG_PATH not set")

    # Parse-check against a fresh path (cache-miss) without disturbing the
    # currently cached objects. Raises on a broken file — caches stay warm.
    candidate = load_config(Path(path))
    previous = load_config()

    # The connector holding these was built at import and is never rebuilt, so
    # a rotated upstream credential would look applied and would not be.
    if (
        candidate.pdns_api_url != previous.pdns_api_url
        or candidate.pdns_api_token != previous.pdns_api_token
    ):
        logger.warning(
            "pdns_api_url/pdns_api_token changed, but the upstream connector is "
            "built once at startup: the OLD upstream credential stays in use "
            "until the service is restarted"
        )

    # New file is valid. Settings go live BEFORE the environment map is swapped,
    # because the two are not swapped atomically and the ordering decides which
    # way the gap fails. Settings first means a reload that simultaneously
    # rotates a token and narrows webui_source_ips has the tighter source-IP
    # rule already in force while the new token becomes valid; the reverse order
    # leaves a window where the new token is accepted from the old, now
    # forbidden, source address. The mirror-image case (widening source IPs while
    # rotating a token) is briefly permissive instead — unavoidable without one
    # atomic snapshot, which is why the deployment restarts rather than reloads.
    reset_settings_cache()
    settings = load_inberlin_settings()

    # Same cross-check init_runtime() does, against the CANDIDATE environments —
    # not the ones still cached, which is why it happens here rather than inside
    # _apply_to_runtime. Renaming an environment (or mistyping a role key) and
    # reloading would otherwise leave the real environment with no roles, which
    # silently disables the /api/v1 service-credential gate for it. Refusing the
    # reload keeps the last known-good config live, matching the contract that a
    # bad file never disturbs a running process.
    if settings is not None:
        from powerdns_api_proxy.inberlin.runtime import roles_vs_environments_error

        problem = roles_vs_environments_error(settings, candidate)
        if problem:
            raise ValueError(f"refusing reload: {problem}")

    _apply_to_runtime(settings)

    load_config.cache_clear()
    load_config()
    logger.info("static configuration reloaded")


# Baked into objects built at startup, so re-reading the file cannot change
# them: state_db opens a connection, oidc builds a validator, the deny lists are
# canonicalized into the immutable MappingView, and the rate limiter is
# constructed once and cached on app.state. Changing any of these needs a
# restart, and a reload must SAY so rather than look like it worked.
RESTART_REQUIRED_FIELDS = (
    "state_db",
    "oidc",
    "deny_zones",
    "deny_zones_exact",
    "rate_limit_auth_failures_per_minute",
    "rate_limit_mutations_per_minute",
    "rate_limit_webui_global_mutations_per_minute",
)


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
    if runtime is None:
        # Reload landed before startup finished, or the extension was never on;
        # init_runtime() will read the fresh settings itself.
        return

    if settings is None:
        # The `inberlin:` block was removed or set to enabled:false while the
        # extension is LIVE. Nothing here can tear the runtime down safely, so
        # the whole multi-tenant layer stays in force — say so loudly rather
        # than let the operator believe the reload disabled it.
        logger.warning(
            "reload found no usable inberlin settings (block removed or "
            "disabled), but the extension is already running: it stays ACTIVE "
            "with the previous settings until the service is restarted"
        )
        return

    stale = [
        field
        for field in RESTART_REQUIRED_FIELDS
        if getattr(runtime.settings, field) != getattr(settings, field)
    ]

    # Carry the restart-required fields forward from the LIVE settings instead of
    # publishing the new file's values for them. Publishing them produced a
    # hybrid configuration whose behavior depended on which component read a
    # field: middleware would read the new oidc block while runtime.oidc still
    # validated with the old one, and the new deny lists would appear in
    # settings while mapping.view kept enforcing the old ones. Everything that
    # can genuinely be swapped is swapped; everything that cannot keeps the
    # value the running objects actually enforce, so settings and behavior
    # always agree.
    runtime.settings = settings.model_copy(
        update={
            field: getattr(runtime.settings, field) for field in RESTART_REQUIRED_FIELDS
        }
    )
    if stale:
        logger.warning(
            "reload applied, but these settings still hold their previous "
            f"values and only change on restart: {', '.join(stale)}"
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
