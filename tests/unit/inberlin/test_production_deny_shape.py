"""Drive the DEPLOYED deny configuration through the real request path.

The shared fixtures configure `deny_zones=["in-berlin.de", ...]` (subtree). The
IN-Berlin deployment configures the opposite shape — `deny_zones: []` plus
`deny_zones_exact: ["in-berlin.de"]` — because a subtree entry on the apex denied
every member zone beneath it, which is exactly what broke the first ans0
deployment while the whole suite stayed green.

These tests therefore build a runtime with the production shape and exercise it
end to end: middleware ownership gate, environment synthesis, /mapping/self and
/proxy/v1/register. A regression in either direction fails here rather than on
the DNS primary.
"""

import asyncio
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

import powerdns_api_proxy.inberlin.runtime as runtime_mod
from powerdns_api_proxy.inberlin.runtime import Runtime
from powerdns_api_proxy.inberlin.settings import InBerlinSettings, RegistrationSettings
from tests.unit.inberlin.conftest import (
    REGISTRAR_TOKEN,
    WEBUI_TOKEN,
    make_config,
)

APEX = "in-berlin.de."
MEMBER_ZONE = "member-one.in-berlin.de."
INFRA_ZONE = "ns1.in-berlin.de."
MEMBER = "tn-one"
ZONES_PATH = "/api/v1/servers/localhost/zones"


def _production_settings(tmp_path) -> InBerlinSettings:
    return InBerlinSettings(
        state_db=str(tmp_path / "prod-shape.sqlite"),
        # exactly what roles/pdns_api_proxy/defaults/main.yml renders
        deny_zones=["ns1.in-berlin.de"],
        deny_zones_exact=["in-berlin.de"],
        webui_source_ips=["testclient"],
        environment_roles={
            "webui": ["webui"],
            "exporter": ["exporter"],
            "infra-admin": ["admin"],
            "registrar": ["registrar"],
            "metrics": ["metrics"],
        },
        registration=RegistrationSettings(
            nameservers=["ns1.in-berlin.de.", "ns2.in-berlin.de."]
        ),
    )


@pytest.fixture()
def prod_client(tmp_path, fake_pdns):
    """Same wiring as the shared `client` fixture, with the deployed deny shape.

    The mapping deliberately grants the member all three zones — apex, infra and
    its own — so the deny lists, not the mapping, are what decides.
    """
    for zone in (APEX, MEMBER_ZONE, INFRA_ZONE, "member-two.in-berlin.de."):
        fake_pdns.zones[zone] = {
            "id": zone,
            "name": zone,
            "kind": "Native",
            "rrsets": [],
        }

    config = make_config()
    rt = Runtime(_production_settings(tmp_path))
    asyncio.run(rt.mapping.load())
    asyncio.run(
        rt.mapping.replace(0, {MEMBER: [MEMBER_ZONE, APEX, INFRA_ZONE]}, "test-seed")
    )
    rt.journal_db_bytes = asyncio.run(rt.store.db_size_bytes())
    runtime_mod._runtime = rt
    from powerdns_api_proxy.proxy import app

    with (
        patch("powerdns_api_proxy.config.load_config", return_value=config),
        patch("powerdns_api_proxy.middleware.load_config", return_value=config),
        patch(
            "powerdns_api_proxy.inberlin.middleware.load_config", return_value=config
        ),
    ):
        yield TestClient(app)
    runtime_mod._runtime = None
    rt.store.close()


def act_as(tn: str = MEMBER) -> dict:
    return {"X-API-Key": WEBUI_TOKEN, "X-Teilnehmer": tn}


def test_member_reaches_its_own_zone_under_the_apex(prod_client):
    """The regression that broke the first deployment: this was 403."""
    r = prod_client.get(f"{ZONES_PATH}/{MEMBER_ZONE}", headers=act_as())
    assert r.status_code != 403, r.text


def test_apex_itself_stays_denied(prod_client):
    r = prod_client.get(f"{ZONES_PATH}/{APEX}", headers=act_as())
    assert r.status_code == 403


def test_infra_subtree_entry_still_denies(prod_client):
    r = prod_client.get(f"{ZONES_PATH}/{INFRA_ZONE}", headers=act_as())
    assert r.status_code == 403


def test_mapping_self_hides_denied_zones(prod_client):
    """Even though the mapping lists them, they are not the member's."""
    r = prod_client.get("/proxy/v1/mapping/self", headers=act_as())
    assert r.status_code == 200
    zones = r.json()["zones"]
    assert MEMBER_ZONE in zones
    assert APEX not in zones
    assert INFRA_ZONE not in zones


def test_registrar_may_create_under_the_apex_but_not_the_apex(prod_client):
    reg = {"X-API-Key": REGISTRAR_TOKEN}
    denied = prod_client.post(
        "/proxy/v1/register", headers=reg, json={"zone": APEX, "user": MEMBER}
    )
    assert denied.status_code == 403
    assert "deny list" in denied.json()["error"]

    infra = prod_client.post(
        "/proxy/v1/register", headers=reg, json={"zone": INFRA_ZONE, "user": MEMBER}
    )
    assert infra.status_code == 403

    allowed = prod_client.post(
        "/proxy/v1/register",
        headers=reg,
        json={"zone": "member-two.in-berlin.de.", "user": MEMBER},
    )
    assert allowed.status_code != 403, allowed.text
