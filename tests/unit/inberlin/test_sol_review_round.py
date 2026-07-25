"""Findings from the sol review round.

Each test below corresponds to a concrete failing scenario that existed before
this round:

* a reload published restart-required values into runtime.settings, producing a
  hybrid configuration where middleware read the NEW oidc block while
  runtime.oidc still validated with the OLD one, and the new deny lists appeared
  in settings while mapping.view kept enforcing the old ones;
* two reloads could interleave (SIGHUP during an /admin/reload) and combine
  settings from one version of the file with environments from another;
* an environment_roles key naming no configured environment silently left the
  real environment role-less, which un-gated it on /api/v1;
* a mapping write could assign the same zone to two users, making owner_of()
  depend on dict iteration order;
* the rate limiter never evicted keys, and act-as traffic keys on an
  attacker-chosen member name.
"""

import threading
import time

import pytest

import powerdns_api_proxy.inberlin.reload as reload_mod
from powerdns_api_proxy.inberlin.mapping import (
    DuplicateZoneOwner,
    _reject_duplicate_owners,
)
from powerdns_api_proxy.inberlin.middleware import RateLimiter
from powerdns_api_proxy.inberlin.runtime import assert_roles_match_environments
from powerdns_api_proxy.inberlin.settings import InBerlinSettings, OIDCSettings
from tests.unit.inberlin.conftest import make_config


class _FakeRuntime:
    def __init__(self, settings):
        self.settings = settings


def _settings(**kwargs) -> InBerlinSettings:
    base = dict(state_db="/tmp/irrelevant.sqlite", webui_source_ips=["10.0.0.1"])
    base.update(kwargs)
    return InBerlinSettings(**base)


# -- restart-required fields keep their live values ---------------------------


def test_restart_required_fields_are_not_published(monkeypatch):
    live = _settings(deny_zones=["old.example"], webui_source_ips=["10.0.0.1"])
    runtime = _FakeRuntime(live)
    monkeypatch.setattr(
        "powerdns_api_proxy.inberlin.runtime.get_runtime", lambda: runtime
    )

    reload_mod._apply_to_runtime(
        _settings(deny_zones=["new.example"], webui_source_ips=["10.0.0.2"])
    )

    # hot-swappable field took effect...
    assert runtime.settings.webui_source_ips == ["10.0.0.2"]
    # ...while the one the mapping view still enforces did NOT change under it
    assert runtime.settings.deny_zones == ["old.example"]


def test_oidc_block_cannot_be_swapped_under_the_validator(monkeypatch):
    oidc = OIDCSettings(issuer="https://old.example/", audience="dnsapi")
    runtime = _FakeRuntime(_settings(oidc=oidc))
    monkeypatch.setattr(
        "powerdns_api_proxy.inberlin.runtime.get_runtime", lambda: runtime
    )

    reload_mod._apply_to_runtime(_settings(oidc=None))

    assert runtime.settings.oidc is not None
    assert runtime.settings.oidc.issuer == "https://old.example/"


# -- reloads are serialized ---------------------------------------------------


def test_concurrent_reload_is_skipped_not_interleaved(monkeypatch):
    started = threading.Event()
    release = threading.Event()
    calls = []

    def slow_reload():
        calls.append("run")
        started.set()
        release.wait(timeout=5)

    monkeypatch.setattr(reload_mod, "_reload_locked", slow_reload)

    worker = threading.Thread(target=reload_mod.reload_static_config)
    worker.start()
    assert started.wait(timeout=5)

    # second reload arrives while the first still holds the lock
    reload_mod.reload_static_config()
    assert calls == ["run"], "second reload must be skipped, not interleaved"

    release.set()
    worker.join(timeout=5)


def test_lock_is_released_even_if_reload_raises(monkeypatch):
    def boom():
        raise RuntimeError("bad config")

    monkeypatch.setattr(reload_mod, "_reload_locked", boom)
    with pytest.raises(RuntimeError):
        reload_mod.reload_static_config()

    assert reload_mod._reload_lock.acquire(blocking=False)
    reload_mod._reload_lock.release()


# -- environment_roles keys must name real environments -----------------------


def test_orphaned_environment_roles_key_is_rejected(monkeypatch):
    monkeypatch.setattr(
        "powerdns_api_proxy.config.load_config", lambda *a, **k: make_config()
    )
    settings = _settings(environment_roles={"registrarr": ["registrar"]})
    with pytest.raises(ValueError) as excinfo:
        assert_roles_match_environments(settings)
    assert "registrarr" in str(excinfo.value)


def test_matching_keys_are_accepted(monkeypatch):
    monkeypatch.setattr(
        "powerdns_api_proxy.config.load_config", lambda *a, **k: make_config()
    )
    settings = _settings(
        environment_roles={"registrar": ["registrar"], "webui": ["webui"]}
    )
    assert_roles_match_environments(settings)  # must not raise


# -- one zone, one owner ------------------------------------------------------


def test_same_zone_for_two_users_is_rejected():
    with pytest.raises(DuplicateZoneOwner) as excinfo:
        _reject_duplicate_owners(
            {"tn-a": {"shared.in-berlin.de."}, "tn-b": {"shared.in-berlin.de."}}
        )
    assert "shared.in-berlin.de." in str(excinfo.value)


def test_parent_and_child_ownership_remains_legal():
    """Longest-suffix resolution is a designed feature, not a duplicate."""
    _reject_duplicate_owners(
        {"tn-a": {"in-berlin.de."}, "tn-b": {"child.in-berlin.de."}}
    )


def test_same_zone_for_the_same_user_twice_is_fine():
    _reject_duplicate_owners({"tn-a": {"a.in-berlin.de.", "b.in-berlin.de."}})


# -- rate limiter evicts ------------------------------------------------------


def test_limiter_evicts_stale_keys():
    limiter = RateLimiter(30, 120, 600)
    limiter._SWEEP_EVERY = 10

    for i in range(9):
        limiter.hit("mutation", f"victim-{i}")
    assert len(limiter.events) == 9

    # age them out, then trip the sweep
    for key in limiter.events:
        limiter.events[key][-1] = time.monotonic() - 3600
    limiter.hit("mutation", "fresh")

    assert len(limiter.events) == 1
    assert ("mutation", "fresh") in limiter.events


def test_sweep_keeps_live_buckets():
    limiter = RateLimiter(30, 120, 600)
    limiter._SWEEP_EVERY = 2
    limiter.hit("mutation", "active")
    limiter.hit("mutation", "active")
    assert ("mutation", "active") in limiter.events
