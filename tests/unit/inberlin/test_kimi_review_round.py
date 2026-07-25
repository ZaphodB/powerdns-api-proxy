"""Findings from the kimi k3 review round.

* environment_roles was cross-checked at startup but NOT on reload, so renaming
  an environment (or mistyping a role key) and reloading silently left the real
  environment role-less — which disables the /api/v1 service-credential gate for
  it, the exact state an earlier fix closed.
* /proxy/v1/admin/reload answered {"reloaded": true} even when the lock was held
  and its reload was skipped.
* an uppercase sha512 in the config parsed and deployed fine but could never
  authenticate, because lookups key on hashlib's lowercase digest().hex() and
  token_env_map stores the configured value verbatim.
* a stored mapping with ambiguous ownership loaded silently and then made every
  PATCH fail with no explanation.

Plus a maintenance guard: any future InBerlinSettings field that is baked into a
startup-built object must be declared restart-required, or it will appear to
hot-swap while the running objects keep enforcing the old value.
"""

import pytest
from pydantic import ValidationError

import powerdns_api_proxy.inberlin.reload as reload_mod
from powerdns_api_proxy.inberlin.reload import RESTART_REQUIRED_FIELDS
from powerdns_api_proxy.inberlin.runtime import roles_vs_environments_error
from powerdns_api_proxy.inberlin.settings import InBerlinSettings
from powerdns_api_proxy.models import ProxyConfigEnvironment
from tests.unit.inberlin.conftest import ADMIN_TOKEN, make_config, sha512

# Every settings field must be classified: either it is safe to swap under a
# running process, or it is baked into something built at startup and therefore
# restart-required. A new field lands in neither list and fails this test.
HOT_SWAPPABLE = {
    "enabled",
    "webui_source_ips",
    "environment_roles",
    "registration",
    "journal_retention_days",
    "upstream_server_id",
    "max_keys_per_teilnehmer",
}


def test_every_settings_field_is_classified():
    fields = set(InBerlinSettings.model_fields)
    unclassified = fields - HOT_SWAPPABLE - set(RESTART_REQUIRED_FIELDS)
    assert not unclassified, (
        "new InBerlinSettings field(s) are neither declared hot-swappable nor "
        f"restart-required: {sorted(unclassified)}. If the value is captured by "
        "an object built at startup it MUST be added to RESTART_REQUIRED_FIELDS, "
        "otherwise a reload will appear to apply it and will not."
    )


def test_classifications_do_not_overlap():
    assert not HOT_SWAPPABLE & set(RESTART_REQUIRED_FIELDS)


# -- reload re-validates roles against the CANDIDATE environments -------------


def test_orphaned_role_key_detected_against_candidate_config():
    settings = InBerlinSettings(environment_roles={"registrar": ["registrar"]})
    config = make_config()
    assert roles_vs_environments_error(settings, config) is None

    renamed = make_config()
    renamed.environments = [
        env for env in renamed.environments if env.name != "registrar"
    ] + [
        ProxyConfigEnvironment(
            name="registrar-eu", token_sha512=sha512("registrar-eu-token")
        )
    ]
    problem = roles_vs_environments_error(settings, renamed)
    assert problem is not None
    assert "registrar" in problem


# The end-to-end "a reload that would un-gate a credential is refused" case
# lives in test_hy3_review_round.py, which additionally asserts that the refusal
# leaves the settings cache untouched — the stricter property.


# -- a skipped reload is not a successful reload ------------------------------


def test_reload_reports_whether_it_ran(monkeypatch):
    monkeypatch.setattr(reload_mod, "_reload_locked", lambda: None)
    assert reload_mod.reload_static_config() is True

    reload_mod._reload_lock.acquire()
    try:
        assert reload_mod.reload_static_config() is False
    finally:
        reload_mod._reload_lock.release()


# -- token hashes must be lowercase hex --------------------------------------


def test_uppercase_token_hash_is_rejected():
    upper = sha512(ADMIN_TOKEN).upper()
    with pytest.raises(ValidationError) as excinfo:
        ProxyConfigEnvironment(name="x", token_sha512=upper)
    assert "lowercase hex" in str(excinfo.value)


def test_non_hex_token_hash_is_rejected():
    with pytest.raises(ValidationError):
        ProxyConfigEnvironment(name="x", token_sha512="z" * 128)


def test_lowercase_token_hash_is_accepted():
    env = ProxyConfigEnvironment(name="x", token_sha512=sha512(ADMIN_TOKEN))
    assert env.token_sha512 == sha512(ADMIN_TOKEN)
