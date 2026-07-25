"""A reload must actually change what requests see.

Requests read `runtime.settings`, the object captured when the runtime was
built. reload_static_config() used to refresh only the module-level caches, so
editing the config and reloading looked successful and changed nothing.

That is a silent failure of a security control: on ans0 (2026-07-25) the config
was changed to bind the webui act-as credential to 192.168.254.99, reloaded, and
a request from 192.168.254.1 was still accepted with 200. Only a restart applied
it (403).
"""

import powerdns_api_proxy.inberlin.reload as reload_mod
from powerdns_api_proxy.inberlin.settings import InBerlinSettings


class _FakeRuntime:
    def __init__(self, settings):
        self.settings = settings


def _settings(**kwargs) -> InBerlinSettings:
    base = dict(state_db="/tmp/does-not-matter.sqlite", webui_source_ips=["10.0.0.1"])
    base.update(kwargs)
    return InBerlinSettings(**base)


def test_runtime_settings_are_replaced(monkeypatch):
    runtime = _FakeRuntime(_settings())
    monkeypatch.setattr(reload_mod, "get_runtime", lambda: runtime, raising=False)
    monkeypatch.setattr(
        "powerdns_api_proxy.inberlin.runtime.get_runtime", lambda: runtime
    )

    fresh = _settings(webui_source_ips=["192.168.254.99"])
    reload_mod._apply_to_runtime(fresh)

    assert runtime.settings.webui_source_ips == ["192.168.254.99"]


def test_no_runtime_is_not_an_error(monkeypatch):
    """Reload can land before startup finished; it must not explode."""
    monkeypatch.setattr("powerdns_api_proxy.inberlin.runtime.get_runtime", lambda: None)
    reload_mod._apply_to_runtime(_settings())  # must not raise


def test_restart_required_fields_are_reported(monkeypatch, caplog):
    runtime = _FakeRuntime(_settings(deny_zones=["old.example"]))
    monkeypatch.setattr(
        "powerdns_api_proxy.inberlin.runtime.get_runtime", lambda: runtime
    )

    with caplog.at_level("WARNING"):
        reload_mod._apply_to_runtime(_settings(deny_zones=["new.example"]))

    assert "deny_zones" in caplog.text
    assert "restart" in caplog.text


def test_hot_swappable_change_warns_about_nothing(monkeypatch, caplog):
    runtime = _FakeRuntime(_settings())
    monkeypatch.setattr(
        "powerdns_api_proxy.inberlin.runtime.get_runtime", lambda: runtime
    )

    with caplog.at_level("WARNING"):
        reload_mod._apply_to_runtime(_settings(webui_source_ips=["192.168.254.9"]))

    assert "restart" not in caplog.text
