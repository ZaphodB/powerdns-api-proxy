"""Findings from the hy3 review round.

A refused reload must leave the process EXACTLY as it was. The environment-roles
validation added in the previous round ran after `reset_settings_cache()`, so a
config that failed validation still left its settings in the module cache while
the runtime kept the old ones — a "refused" reload that half-applied, which is
the contract this code exists to uphold.

Also: a deny-list entry that is empty or whitespace canonicalizes to the root
and matches nothing, protecting nothing while looking like protection.
"""

import pytest
from pydantic import ValidationError

import powerdns_api_proxy.inberlin.reload as reload_mod
from powerdns_api_proxy.inberlin.settings import (
    InBerlinSettings,
    load_inberlin_settings,
)
from tests.unit.inberlin.conftest import make_config

CONFIG_YAML = """
pdns_api_url: http://127.0.0.1:8081
pdns_api_token: upstream-token
environments: []
inberlin:
  state_db: /tmp/hy3-test.sqlite
  webui_source_ips: ["192.168.254.9"]
  environment_roles:
    nonexistent-env: [registrar]
"""


def test_refused_reload_leaves_the_settings_cache_untouched(monkeypatch, tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text(CONFIG_YAML)
    monkeypatch.setenv("PROXY_CONFIG_PATH", str(config_file))
    monkeypatch.setattr(reload_mod, "load_config", lambda *a, **k: make_config())

    live = InBerlinSettings(webui_source_ips=["10.0.0.1"])
    reset_called = []
    monkeypatch.setattr(
        reload_mod, "reset_settings_cache", lambda: reset_called.append(True)
    )
    monkeypatch.setattr(reload_mod, "load_inberlin_settings", load_inberlin_settings)
    applied = []
    monkeypatch.setattr(reload_mod, "_apply_to_runtime", applied.append)

    with pytest.raises(ValueError) as excinfo:
        reload_mod._reload_locked()

    assert "refusing reload" in str(excinfo.value)
    assert reset_called == [], "the live settings cache must not be reset"
    assert applied == [], "nothing may go live from a refused reload"
    assert live.webui_source_ips == ["10.0.0.1"]


@pytest.mark.parametrize("bad", ["", "   ", "\t"])
def test_empty_deny_entries_are_rejected(bad):
    with pytest.raises(ValidationError):
        InBerlinSettings(deny_zones=[bad])
    with pytest.raises(ValidationError):
        InBerlinSettings(deny_zones_exact=[bad])


def test_normal_deny_entries_still_accepted():
    settings = InBerlinSettings(
        deny_zones=["infra.in-berlin.de"], deny_zones_exact=["in-berlin.de"]
    )
    assert settings.deny_zones == ["infra.in-berlin.de"]
