"""End-to-end API tests through the full middleware stack with FakePDNS."""

import json
import sqlite3

from tests.unit.inberlin.conftest import (
    ADMIN_TOKEN,
    EXPORTER_TOKEN,
    PLAIN_TOKEN,
    WEBUI_TOKEN,
)

ZONES_PATH = "/api/v1/servers/localhost/zones"


def act_as(tn, user=None):
    h = {"X-API-Key": WEBUI_TOKEN, "X-Teilnehmer": tn}
    if user:
        h["X-Webui-User"] = user
    return h


# -- credential hygiene -------------------------------------------------------

def test_no_credentials_401(client):
    assert client.get(ZONES_PATH).status_code == 401


def test_ambiguous_credentials_400(client):
    r = client.get(ZONES_PATH, headers={
        "X-API-Key": WEBUI_TOKEN, "Authorization": "Bearer xyz"})
    assert r.status_code == 400


def test_act_as_header_forbidden_for_plain_static(client):
    r = client.get(ZONES_PATH, headers={
        "X-API-Key": PLAIN_TOKEN, "X-Teilnehmer": "alice"})
    assert r.status_code == 403


def test_impersonate_header_forbidden_for_plain_static(client):
    r = client.get(ZONES_PATH, headers={
        "X-API-Key": PLAIN_TOKEN, "X-Impersonate-Teilnehmer": "alice"})
    assert r.status_code == 403


def test_webui_without_tn_header_is_plain_static(client):
    r = client.get("/proxy/v1/whoami", headers={"X-API-Key": WEBUI_TOKEN})
    assert r.status_code == 200
    assert r.json()["kind"] == "static"
    assert r.json()["effective_teilnehmer"] is None


# -- act-as authorization -----------------------------------------------------

def test_act_as_sees_only_own_zones(client):
    r = client.get(ZONES_PATH, headers=act_as("alice"))
    assert r.status_code == 200
    names = [z["name"] for z in r.json()]
    assert names == ["kunde.example."]

    r = client.get(ZONES_PATH, headers=act_as("bob"))
    assert [z["name"] for z in r.json()] == []


def test_act_as_zone_get_denied_for_foreign_zone(client):
    r = client.get(f"{ZONES_PATH}/kunde.example.", headers=act_as("bob"))
    assert r.status_code == 403


def test_whoami_act_as(client):
    r = client.get("/proxy/v1/whoami", headers=act_as("Alice", user="alice-login"))
    body = r.json()
    assert body["kind"] == "webui-act-as"
    assert body["effective_teilnehmer"] == "alice"
    assert body["webui_user"] == "alice-login"


def test_mapping_self(client):
    r = client.get("/proxy/v1/mapping/self", headers=act_as("alice"))
    assert r.json() == {"teilnehmer": "alice", "zones": ["kunde.example."]}


# -- mapping CAS ---------------------------------------------------------------

def test_mapping_put_requires_if_match(client):
    r = client.put("/proxy/v1/mapping", headers={"X-API-Key": EXPORTER_TOKEN},
                   json={"mapping": {"alice": ["kunde.example"]}})
    assert r.status_code == 400


def test_mapping_put_cas_and_effect(client):
    r = client.put(
        "/proxy/v1/mapping",
        headers={"X-API-Key": EXPORTER_TOKEN, "If-Match": "1"},
        json={"mapping": {"carol": ["carol.example"]}},
    )
    assert r.status_code == 200
    assert r.json()["generation"] == 2

    # stale generation -> 409
    r = client.put(
        "/proxy/v1/mapping",
        headers={"X-API-Key": EXPORTER_TOKEN, "If-Match": "1"},
        json={"mapping": {}},
    )
    assert r.status_code == 409

    # alice lost her zone
    r = client.get(ZONES_PATH, headers=act_as("alice"))
    assert r.json() == []


def test_mapping_endpoints_forbidden_for_tn(client):
    r = client.get("/proxy/v1/mapping", headers=act_as("alice"))
    assert r.status_code == 403


# -- journal + rollback round-trip ----------------------------------------------

PATCH_BODY = {
    "rrsets": [{
        "name": "www.kunde.example.", "type": "A", "changetype": "REPLACE",
        "ttl": 600, "records": [{"content": "198.51.100.7", "disabled": False}],
    }]
}


def test_journal_and_rollback_roundtrip(client, fake_pdns):
    r = client.patch(f"{ZONES_PATH}/kunde.example.", headers=act_as("alice", "al"),
                     json=PATCH_BODY)
    assert r.status_code == 204
    live = fake_pdns.zones["kunde.example."]["rrsets"]
    assert live[0]["records"][0]["content"] == "198.51.100.7"

    r = client.get("/proxy/v1/journal", headers=act_as("alice"))
    entries = r.json()["entries"]
    assert len(entries) == 1
    entry = entries[0]
    assert entry["status"] == "committed"
    assert entry["operation"] == "rrset-patch"
    assert entry["rollbackable"] == 1
    assert entry["webui_user"] == "al"

    r = client.get(f"/proxy/v1/journal/{entry['id']}", headers=act_as("alice"))
    full = r.json()
    before = json.loads(full["rrsets"][0]["before_rrset"])
    assert before["records"][0]["content"] == "192.0.2.1"
    assert before["ttl"] == 300

    # rollback restores prior content and TTL
    r = client.post(f"/proxy/v1/journal/{entry['id']}/rollback", headers=act_as("alice"))
    assert r.status_code == 200
    live = fake_pdns.zones["kunde.example."]["rrsets"]
    assert live[0]["records"][0]["content"] == "192.0.2.1"
    assert live[0]["ttl"] == 300

    # rollback itself journaled with rollback_of
    r = client.get("/proxy/v1/journal", headers=act_as("alice"))
    entries = r.json()["entries"]
    assert len(entries) == 2
    assert entries[0]["rollback_of"] == entry["id"]


def test_rollback_drift_409(client, fake_pdns):
    r = client.patch(f"{ZONES_PATH}/kunde.example.", headers=act_as("alice"),
                     json=PATCH_BODY)
    entry_id = client.get("/proxy/v1/journal", headers=act_as("alice")).json()["entries"][0]["id"]

    # out-of-band change (simulates a later edit)
    fake_pdns.zones["kunde.example."]["rrsets"][0]["records"][0]["content"] = "203.0.113.9"

    r = client.post(f"/proxy/v1/journal/{entry_id}/rollback", headers=act_as("alice"))
    assert r.status_code == 409

    # force is admin-only
    r = client.post(f"/proxy/v1/journal/{entry_id}/rollback", headers=act_as("alice"),
                    json={"force": True})
    assert r.status_code == 403


def test_journal_scoping_no_idor(client):
    client.patch(f"{ZONES_PATH}/kunde.example.", headers=act_as("alice"), json=PATCH_BODY)
    entry_id = client.get("/proxy/v1/journal", headers=act_as("alice")).json()["entries"][0]["id"]

    # bob can't see or roll back alice's entry, and gets no oracle
    assert client.get(f"/proxy/v1/journal/{entry_id}", headers=act_as("bob")).status_code == 404
    assert client.post(f"/proxy/v1/journal/{entry_id}/rollback",
                       headers=act_as("bob")).status_code == 404
    # TN may not use the teilnehmer filter
    assert client.get("/proxy/v1/journal?teilnehmer=alice",
                      headers=act_as("bob")).status_code == 403
    # admin sees it
    r = client.get(f"/proxy/v1/journal/{entry_id}", headers={"X-API-Key": ADMIN_TOKEN})
    assert r.status_code == 200


def test_zone_delete_rollback_recreates(client, fake_pdns):
    r = client.delete(f"{ZONES_PATH}/kunde.example.", headers=act_as("alice"))
    assert r.status_code == 204
    assert "kunde.example." not in fake_pdns.zones

    entry = client.get("/proxy/v1/journal", headers=act_as("alice")).json()["entries"][0]
    assert entry["operation"] == "zone-delete"
    assert entry["rollbackable"] == 1

    r = client.post(f"/proxy/v1/journal/{entry['id']}/rollback", headers=act_as("alice"))
    assert r.status_code == 200
    assert "kunde.example." in fake_pdns.zones
    assert fake_pdns.zones["kunde.example."]["rrsets"]


# -- keys -----------------------------------------------------------------------

def test_key_mint_use_revoke_and_hygiene(client, tmp_path):
    r = client.post("/proxy/v1/keys", headers=act_as("alice"), json={"label": "acme"})
    assert r.status_code == 201
    plaintext = r.json()["key"]
    key_id = r.json()["id"]

    # key works for DNS ops, scoped to alice's zones
    r = client.get(ZONES_PATH, headers={"X-API-Key": plaintext})
    assert [z["name"] for z in r.json()] == ["kunde.example."]

    # key cannot mint keys
    r = client.post("/proxy/v1/keys", headers={"X-API-Key": plaintext}, json={})
    assert r.status_code == 403

    # key + identity headers rejected
    r = client.get(ZONES_PATH, headers={"X-API-Key": plaintext, "X-Teilnehmer": "bob"})
    assert r.status_code == 403

    # plaintext never persisted: not in the sqlite file
    db_bytes = (tmp_path / "state.sqlite").read_bytes()
    assert plaintext.encode() not in db_bytes

    # revoke ends access
    r = client.delete(f"/proxy/v1/keys/{key_id}", headers=act_as("alice"))
    assert r.status_code == 200
    assert client.get(ZONES_PATH, headers={"X-API-Key": plaintext}).status_code == 401


def test_key_journal_access_forbidden(client):
    r = client.post("/proxy/v1/keys", headers=act_as("alice"), json={})
    plaintext = r.json()["key"]
    assert client.get("/proxy/v1/journal",
                      headers={"X-API-Key": plaintext}).status_code == 403
    client.patch(f"{ZONES_PATH}/kunde.example.", headers=act_as("alice"), json=PATCH_BODY)
    entry_id = client.get("/proxy/v1/journal", headers=act_as("alice")).json()["entries"][0]["id"]
    assert client.post(f"/proxy/v1/journal/{entry_id}/rollback",
                       headers={"X-API-Key": plaintext}).status_code == 403


# -- fail-closed journal ----------------------------------------------------------

def test_journal_fail_closed_blocks_mutation(client, fake_pdns, tmp_path):
    import powerdns_api_proxy.inberlin.runtime as runtime_mod
    rt = runtime_mod.get_runtime()
    rt.store.close()  # journal unwritable

    r = client.patch(f"{ZONES_PATH}/kunde.example.", headers=act_as("alice"),
                     json=PATCH_BODY)
    assert r.status_code == 503
    # mutation NOT forwarded
    live = fake_pdns.zones["kunde.example."]["rrsets"]
    assert live[0]["records"][0]["content"] == "192.0.2.1"
    # reopen so fixture teardown doesn't explode
    rt.store._conn = sqlite3.connect(str(tmp_path / "state.sqlite"), check_same_thread=False)


# -- ready / health -----------------------------------------------------------------

def test_health_public(client):
    assert client.get("/proxy/v1/health").status_code == 200


def test_ready_admin_only_and_reports(client):
    assert client.get("/proxy/v1/ready", headers=act_as("alice")).status_code == 403
    r = client.get("/proxy/v1/ready", headers={"X-API-Key": ADMIN_TOKEN})
    assert r.status_code == 200
    body = r.json()
    assert body["upstream"] and body["journal_writable"]
    assert body["mapping_generation"] == 1
