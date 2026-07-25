"""SIGHUP must be handled from import time, not from the lifespan hook.

Until a handler is installed, Python's default disposition for SIGHUP kills the
process. The handler used to be installed inside the FastAPI lifespan startup,
which left a window between exec and application startup: a `systemctl reload`
arriving in that window killed the service, and because the exit is clean
`Restart=on-failure` did not bring it back. Seen on ans0 on 2026-07-25, where a
config-management run notified restart and reload in the same pass.
"""

import signal


def test_sighup_is_handled_after_importing_the_app():
    import powerdns_api_proxy.proxy  # noqa: F401  (import installs the handler)

    current = signal.getsignal(signal.SIGHUP)
    assert current not in (signal.SIG_DFL, None), (
        "SIGHUP is at its default disposition, which terminates the process"
    )
    assert callable(current)


def test_handler_survives_a_broken_reload(monkeypatch):
    """A reload failure must never kill the process from inside the handler."""
    import powerdns_api_proxy.inberlin.reload as reload_mod

    def boom() -> None:
        raise RuntimeError("broken config")

    monkeypatch.setattr(reload_mod, "reload_static_config", boom)
    reload_mod.install_sighup_handler()
    handler = signal.getsignal(signal.SIGHUP)
    handler(signal.SIGHUP, None)  # must not raise
