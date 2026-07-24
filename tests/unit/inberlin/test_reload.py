import pytest

from powerdns_api_proxy.config import load_config
from powerdns_api_proxy.inberlin import reload as reload_mod

VALID = """
pdns_api_url: "http://127.0.0.1:8081"
pdns_api_token: "tok"
environments: []
"""

BROKEN = "pdns_api_url: [unclosed\n"


def test_reload_validate_before_clear_keeps_cache_on_broken_file(tmp_path, monkeypatch):
    cfg = tmp_path / "config.yaml"
    cfg.write_text(VALID)
    monkeypatch.setenv("PROXY_CONFIG_PATH", str(cfg))
    load_config.cache_clear()

    reload_mod.reload_static_config()
    good = load_config()
    assert good.pdns_api_url == "http://127.0.0.1:8081"

    # ship a broken file and reload — must raise, but the live cache must
    # survive (not be emptied) so requests keep working.
    cfg.write_text(BROKEN)
    with pytest.raises(Exception):
        reload_mod.reload_static_config()
    still = load_config()
    assert still.pdns_api_url == "http://127.0.0.1:8081"
