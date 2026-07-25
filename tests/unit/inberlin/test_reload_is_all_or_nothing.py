"""A refused reload must publish NOTHING — verified against the real loader.

Three separate rounds fixed pieces of this and all three missed the actual
defect, because every test mocked `load_config`. The real function is
`lru_cache(maxsize=1)`: calling it with an explicit path EVICTS the no-arg
entry, so the next no-arg call is a cache miss that re-reads the new file and
publishes it as the live config. Validation that ran afterwards was therefore
refusing a config that was already live — tokens, grants and all.

These tests drive the genuine cached loader against real files on disk.
"""

import pytest

import powerdns_api_proxy.inberlin.reload as reload_mod
from powerdns_api_proxy.config import load_config
from powerdns_api_proxy.inberlin.settings import (
    load_inberlin_settings,
    reset_settings_cache,
)

GOOD = """
pdns_api_url: http://127.0.0.1:8081
pdns_api_token: original-upstream-token
environments:
  - name: registrar
    token_sha512: "{hash}"
inberlin:
  state_db: /tmp/all-or-nothing.sqlite
  webui_source_ips: ["192.168.254.9"]
  environment_roles:
    registrar: [registrar]
"""

# same file, but the environment was renamed without updating environment_roles:
# the registrar environment would end up with no roles, which un-gates it.
REFUSED = """
pdns_api_url: http://127.0.0.1:9999
pdns_api_token: rotated-upstream-token
environments:
  - name: registrar-renamed
    token_sha512: "{hash}"
inberlin:
  state_db: /tmp/all-or-nothing.sqlite
  webui_source_ips: []
  environment_roles:
    registrar: [registrar]
"""

HASH = "a" * 128


@pytest.fixture()
def config_file(tmp_path, monkeypatch):
    path = tmp_path / "config.yaml"
    path.write_text(GOOD.format(hash=HASH))
    monkeypatch.setenv("PROXY_CONFIG_PATH", str(path))
    load_config.cache_clear()
    reset_settings_cache()
    yield path
    load_config.cache_clear()
    reset_settings_cache()


def test_refused_reload_publishes_nothing(config_file, monkeypatch):
    # prime the live caches with the good config
    live = load_config()
    assert [env.name for env in live.environments] == ["registrar"]
    assert live.pdns_api_token == "original-upstream-token"
    live_settings = load_inberlin_settings()
    assert live_settings.webui_source_ips == ["192.168.254.9"]

    applied = []
    monkeypatch.setattr(reload_mod, "_apply_to_runtime", applied.append)

    config_file.write_text(REFUSED.format(hash=HASH))
    with pytest.raises(ValueError) as excinfo:
        reload_mod._reload_locked()
    assert "refusing reload" in str(excinfo.value)

    # nothing may have gone live: not the environment map...
    after = load_config()
    assert [env.name for env in after.environments] == ["registrar"], (
        "the environment map was published by a REFUSED reload"
    )
    assert after.pdns_api_token == "original-upstream-token"
    # ...not the settings...
    assert load_inberlin_settings().webui_source_ips == ["192.168.254.9"]
    # ...and the runtime was never touched
    assert applied == []


def test_successful_reload_publishes_everything(config_file, monkeypatch):
    load_config()
    applied = []
    monkeypatch.setattr(reload_mod, "_apply_to_runtime", applied.append)

    rotated = (
        GOOD.format(hash=HASH)
        .replace("original-upstream-token", "rotated-upstream-token")
        .replace('["192.168.254.9"]', '["192.168.254.10"]')
    )
    config_file.write_text(rotated)

    reload_mod._reload_locked()

    assert load_config().pdns_api_token == "rotated-upstream-token"
    assert load_inberlin_settings().webui_source_ips == ["192.168.254.10"]
    assert len(applied) == 1


def test_upstream_credential_change_is_warned_about(config_file, caplog):
    """`previous` must really be the OLD config, or this warning never fires."""
    load_config()
    config_file.write_text(
        GOOD.format(hash=HASH).replace(
            "original-upstream-token", "rotated-upstream-token"
        )
    )
    with caplog.at_level("WARNING"):
        reload_mod._reload_locked()
    assert "upstream connector is built once at startup" in caplog.text


def test_broken_yaml_leaves_the_live_config_alone(config_file, monkeypatch):
    load_config()
    applied = []
    monkeypatch.setattr(reload_mod, "_apply_to_runtime", applied.append)

    config_file.write_text("this: is: not: valid: yaml: [")
    with pytest.raises(Exception):
        reload_mod._reload_locked()

    assert load_config().pdns_api_token == "original-upstream-token"
    assert applied == []


def test_admin_reload_endpoint_reports_a_rejection(client, config_file):
    """The operator gets the reason and a 4xx, not a bare 500."""
    from tests.unit.inberlin.conftest import ADMIN_TOKEN

    config_file.write_text("not: [valid")
    r = client.post("/proxy/v1/admin/reload", headers={"X-API-Key": ADMIN_TOKEN})
    assert r.status_code == 400
    assert "config unchanged" in r.json()["error"]
