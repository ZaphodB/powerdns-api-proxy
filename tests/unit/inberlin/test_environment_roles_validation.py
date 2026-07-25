"""A typo in environment_roles must fail at startup, not silently widen access.

Every authorization gate is a membership test against these role strings, so an
unrecognised name does not raise anywhere — it leaves the environment with no
roles, which REMOVES restrictions. Writing `registrar: ["regisrar"]` would put
the registrar token back on /api/v1 (the exact behaviour the service-credential
gate exists to stop) while breaking /proxy/v1/register.
"""

import pytest
from pydantic import ValidationError

from powerdns_api_proxy.inberlin.roles import KNOWN_ROLES
from powerdns_api_proxy.inberlin.settings import InBerlinSettings


def test_known_roles_are_accepted():
    settings = InBerlinSettings(
        environment_roles={
            "webui": ["webui"],
            "infra-admin": ["admin"],
            "registrar": ["registrar"],
            "exporter": ["exporter"],
            "metrics": ["metrics"],
        }
    )
    assert settings.environment_roles["registrar"] == ["registrar"]


@pytest.mark.parametrize("typo", ["regisrar", "Admin", "admins", "exportor", ""])
def test_unknown_role_is_rejected(typo):
    with pytest.raises(ValidationError) as excinfo:
        InBerlinSettings(environment_roles={"registrar": [typo]})
    assert "unknown role" in str(excinfo.value)


def test_error_names_the_valid_roles():
    with pytest.raises(ValidationError) as excinfo:
        InBerlinSettings(environment_roles={"x": ["nope"]})
    message = str(excinfo.value)
    for role in KNOWN_ROLES:
        assert role in message


def test_empty_mapping_is_fine():
    """No inberlin roles at all = plain upstream environments."""
    assert InBerlinSettings(environment_roles={}).environment_roles == {}
