"""Service credentials (registrar, exporter, metrics) are barred from /api/v1.

docs/api-contract.md says REG reaches `/proxy/v1/register` ONLY and EXP is
mapping-only. That used to be enforced merely by configuring those environments
with an empty zone list, so the registrar token answered `200 []` on
`/api/v1/servers/localhost/zones` instead of 403 — observed on the first ans0
deployment — and a single stray zone grant in the deployment config would have
turned a create-only credential into a DNS-editing one.
"""

from tests.unit.inberlin.conftest import (
    ADMIN_TOKEN,
    EXPORTER_TOKEN,
    METRICS_TOKEN,
    PLAIN_TOKEN,
    REGISTRAR_TOKEN,
)

ZONES_PATH = "/api/v1/servers/localhost/zones"


def key(token: str) -> dict:
    return {"X-API-Key": token}


def test_registrar_cannot_read_the_powerdns_api(client):
    r = client.get(ZONES_PATH, headers=key(REGISTRAR_TOKEN))
    assert r.status_code == 403
    assert "PowerDNS API" in r.json()["error"]


def test_registrar_cannot_mutate_a_zone(client):
    r = client.delete(f"{ZONES_PATH}/example.de.", headers=key(REGISTRAR_TOKEN))
    assert r.status_code == 403


def test_exporter_cannot_read_the_powerdns_api(client):
    assert client.get(ZONES_PATH, headers=key(EXPORTER_TOKEN)).status_code == 403


def test_metrics_credential_cannot_read_the_powerdns_api(client):
    assert client.get(ZONES_PATH, headers=key(METRICS_TOKEN)).status_code == 403


def test_registrar_still_reaches_its_own_endpoint(client):
    """The gate must not break the one thing the registrar exists to do."""
    r = client.post(
        "/proxy/v1/register",
        headers=key(REGISTRAR_TOKEN),
        json={"zone": "in-berlin.de.", "user": "tn-test"},
    )
    # in-berlin.de is deny-listed in the test settings, so the register endpoint
    # itself answers 403 — reaching that verdict proves the route was not cut
    # off by the credential gate.
    assert r.status_code == 403
    assert "deny list" in r.json()["error"]


def test_admin_keeps_full_api_access(client):
    assert client.get(ZONES_PATH, headers=key(ADMIN_TOKEN)).status_code == 200


def test_plain_upstream_environment_is_untouched(client):
    """No inberlin role at all = ordinary upstream env; must keep working, which
    is what keeps the extension inert for non-IN-Berlin deployments."""
    assert client.get(ZONES_PATH, headers=key(PLAIN_TOKEN)).status_code == 200
