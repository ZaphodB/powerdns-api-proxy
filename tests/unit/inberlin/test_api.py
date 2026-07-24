"""End-to-end API tests through the full middleware stack with FakePDNS."""

import json
import sqlite3

from tests.unit.inberlin.conftest import (
    ADMIN_TOKEN,
    EXPORTER_TOKEN,
    PLAIN_TOKEN,
    REGISTRAR_TOKEN,
    WEBUI_TOKEN,
    bearer,
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
    r = client.get(
        ZONES_PATH, headers={"X-API-Key": WEBUI_TOKEN, "Authorization": "Bearer xyz"}
    )
    assert r.status_code == 400


def test_conflicting_identity_headers_400(client):
    # reject-not-precedence-resolve: both act-as forms together is ambiguous
    r = client.get(
        ZONES_PATH,
        headers={
            "X-API-Key": WEBUI_TOKEN,
            "X-Teilnehmer": "alice",
            "X-Impersonate-Teilnehmer": "bob",
        },
    )
    assert r.status_code == 400


def test_act_as_header_forbidden_for_plain_static(client):
    r = client.get(
        ZONES_PATH, headers={"X-API-Key": PLAIN_TOKEN, "X-Teilnehmer": "alice"}
    )
    assert r.status_code == 403


def test_impersonate_header_forbidden_for_plain_static(client):
    r = client.get(
        ZONES_PATH,
        headers={"X-API-Key": PLAIN_TOKEN, "X-Impersonate-Teilnehmer": "alice"},
    )
    assert r.status_code == 403


def test_webui_without_tn_header_400(client):
    # the shared UI token is act-as ONLY: missing X-Teilnehmer is a malformed
    # act-as request (authz-flow.md: missing header -> 400), not a forbidden one
    r = client.get("/proxy/v1/whoami", headers={"X-API-Key": WEBUI_TOKEN})
    assert r.status_code == 400


def test_duplicate_x_api_key_400(client):
    # duplicate identity headers are ambiguous (authz-flow.md line 21) — the
    # first value must never win silently
    r = client.get(
        "/proxy/v1/whoami",
        headers=[("X-API-Key", ADMIN_TOKEN), ("X-API-Key", EXPORTER_TOKEN)],
    )
    assert r.status_code == 400


def test_duplicate_authorization_400(client):
    r = client.get(
        "/proxy/v1/whoami",
        headers=[("Authorization", "Bearer a"), ("Authorization", "Bearer b")],
    )
    assert r.status_code == 400


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
    assert r.json() == {"user": "alice", "zones": ["kunde.example."]}


# -- mapping CAS ---------------------------------------------------------------


def test_mapping_put_requires_if_match(client):
    r = client.put(
        "/proxy/v1/mapping",
        headers={"X-API-Key": EXPORTER_TOKEN},
        json={"mapping": {"alice": ["kunde.example"]}},
    )
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


def test_mapping_get_contract_shape(client):
    # contract line 38: {generation, applied_at, mapping} — nothing else
    r = client.get("/proxy/v1/mapping", headers={"X-API-Key": ADMIN_TOKEN})
    body = r.json()
    assert set(body) == {"generation", "applied_at", "mapping"}
    assert body["generation"] == 1
    assert body["applied_at"]
    assert body["mapping"] == {
        "alice": ["kunde.example."],
        "bob": ["bob.example."],
    }


def test_mapping_endpoints_forbidden_for_tn(client):
    r = client.get("/proxy/v1/mapping", headers=act_as("alice"))
    assert r.status_code == 403


# -- journal + rollback round-trip ----------------------------------------------

PATCH_BODY = {
    "rrsets": [
        {
            "name": "www.kunde.example.",
            "type": "A",
            "changetype": "REPLACE",
            "ttl": 600,
            "records": [{"content": "198.51.100.7", "disabled": False}],
        }
    ]
}


def test_journal_and_rollback_roundtrip(client, fake_pdns):
    r = client.patch(
        f"{ZONES_PATH}/kunde.example.", headers=act_as("alice", "al"), json=PATCH_BODY
    )
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

    # rollback restores prior content and TTL (lossless — no lossy flag)
    r = client.post(
        f"/proxy/v1/journal/{entry['id']}/rollback", headers=act_as("alice")
    )
    assert r.status_code == 200
    assert "lossy" not in r.json()
    live = fake_pdns.zones["kunde.example."]["rrsets"]
    assert live[0]["records"][0]["content"] == "192.0.2.1"
    assert live[0]["ttl"] == 300

    # rollback itself journaled with rollback_of
    r = client.get("/proxy/v1/journal", headers=act_as("alice"))
    entries = r.json()["entries"]
    assert len(entries) == 2
    assert entries[0]["rollback_of"] == entry["id"]


def test_rollback_drift_409(client, fake_pdns):
    r = client.patch(
        f"{ZONES_PATH}/kunde.example.", headers=act_as("alice"), json=PATCH_BODY
    )
    entry_id = client.get("/proxy/v1/journal", headers=act_as("alice")).json()[
        "entries"
    ][0]["id"]

    # out-of-band change (simulates a later edit)
    fake_pdns.zones["kunde.example."]["rrsets"][0]["records"][0]["content"] = (
        "203.0.113.9"
    )

    r = client.post(f"/proxy/v1/journal/{entry_id}/rollback", headers=act_as("alice"))
    assert r.status_code == 409

    # force is admin-only
    r = client.post(
        f"/proxy/v1/journal/{entry_id}/rollback",
        headers=act_as("alice"),
        json={"force": True},
    )
    assert r.status_code == 403


def test_journal_scoping_no_idor(client):
    client.patch(
        f"{ZONES_PATH}/kunde.example.", headers=act_as("alice"), json=PATCH_BODY
    )
    entry_id = client.get("/proxy/v1/journal", headers=act_as("alice")).json()[
        "entries"
    ][0]["id"]

    # bob can't see or roll back alice's entry, and gets no oracle
    assert (
        client.get(f"/proxy/v1/journal/{entry_id}", headers=act_as("bob")).status_code
        == 404
    )
    assert (
        client.post(
            f"/proxy/v1/journal/{entry_id}/rollback", headers=act_as("bob")
        ).status_code
        == 404
    )
    # TN may not use the user filter
    assert (
        client.get("/proxy/v1/journal?user=alice", headers=act_as("bob")).status_code
        == 403
    )
    # admin sees it
    r = client.get(f"/proxy/v1/journal/{entry_id}", headers={"X-API-Key": ADMIN_TOKEN})
    assert r.status_code == 200


def test_zone_delete_rollback_recreates(client, fake_pdns):
    admin = {"X-API-Key": ADMIN_TOKEN}
    r = client.delete(f"{ZONES_PATH}/kunde.example.", headers=admin)
    assert r.status_code == 204
    assert "kunde.example." not in fake_pdns.zones

    entry = client.get("/proxy/v1/journal", headers=admin).json()["entries"][0]
    assert entry["operation"] == "zone-delete"
    assert entry["rollbackable"] == 1

    r = client.post(f"/proxy/v1/journal/{entry['id']}/rollback", headers=admin)
    assert r.status_code == 200
    # contract line 79-80: recreate-from-export excludes DNSSEC/catalog state —
    # that loss must be flagged in the response, not silent
    assert r.json()["lossy"] is True
    assert "DNSSEC" in r.json()["lossy_detail"]
    assert "kunde.example." in fake_pdns.zones
    assert fake_pdns.zones["kunde.example."]["rrsets"]


def test_member_owns_zone_fully(client, fake_pdns):
    # Owner decision 2026-07-25: owning a zone means full control over it and
    # its descendants — record ops, subzone create, delete, DNSSEC keys. No
    # gatekeeping. Only unrelated apexes stay off-limits.
    assert (
        client.patch(
            f"{ZONES_PATH}/kunde.example.", headers=act_as("alice"), json=PATCH_BODY
        ).status_code
        == 204
    )
    assert (
        client.post(
            ZONES_PATH,
            headers=act_as("alice"),
            json={"name": "sub.kunde.example.", "kind": "Native", "rrsets": []},
        ).status_code
        == 201
    )
    assert (
        client.get(
            f"{ZONES_PATH}/kunde.example./cryptokeys", headers=act_as("alice")
        ).status_code
        == 200
    )
    assert (
        client.delete(
            f"{ZONES_PATH}/kunde.example.", headers=act_as("alice")
        ).status_code
        == 204
    )
    # zones alice does not own remain denied
    assert (
        client.post(
            ZONES_PATH,
            headers=act_as("alice"),
            json={"name": "raw.example.", "kind": "Native", "rrsets": []},
        ).status_code
        == 403
    )


# -- keys -----------------------------------------------------------------------


def test_key_mint_use_revoke_and_hygiene(client, tmp_path):
    # act-as (shared webui token) may NOT mint — OIDC session required
    r = client.post("/proxy/v1/keys", headers=act_as("alice"), json={"label": "acme"})
    assert r.status_code == 403
    # admin impersonating alice via OIDC mints for her
    r = client.post(
        "/proxy/v1/keys",
        headers=bearer(admin=True, **{"X-Impersonate-Teilnehmer": "alice"}),
        json={"label": "acme"},
    )
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


def test_keys_list_uses_contract_field_names(client):
    # contract line 49: own keys -> id, prefix, label, created_at, revoked_at
    r = client.post(
        "/proxy/v1/keys",
        headers=bearer(admin=True, **{"X-Impersonate-Teilnehmer": "alice"}),
        json={"label": "acme"},
    )
    prefix = r.json()["prefix"]
    r = client.get("/proxy/v1/keys", headers=act_as("alice"))
    key = r.json()["keys"][0]
    assert key["prefix"] == prefix
    assert "key_prefix" not in key
    for field in ("id", "label", "created_at", "revoked_at"):
        assert field in key


def test_key_journal_access_forbidden(client):
    r = client.post(
        "/proxy/v1/keys",
        headers=bearer(admin=True, **{"X-Impersonate-Teilnehmer": "alice"}),
        json={},
    )
    plaintext = r.json()["key"]
    assert (
        client.get("/proxy/v1/journal", headers={"X-API-Key": plaintext}).status_code
        == 403
    )
    client.patch(
        f"{ZONES_PATH}/kunde.example.", headers=act_as("alice"), json=PATCH_BODY
    )
    entry_id = client.get("/proxy/v1/journal", headers=act_as("alice")).json()[
        "entries"
    ][0]["id"]
    assert (
        client.post(
            f"/proxy/v1/journal/{entry_id}/rollback", headers={"X-API-Key": plaintext}
        ).status_code
        == 403
    )


# -- registration ---------------------------------------------------------------

REG = {"X-API-Key": REGISTRAR_TOKEN}


def test_register_creates_zone_mapping_and_journal(client, fake_pdns):
    r = client.post(
        "/proxy/v1/register", headers=REG, json={"zone": "Neu.Example", "user": "Carol"}
    )
    assert r.status_code == 201
    body = r.json()
    assert body["zone"] == "neu.example." and body["user"] == "carol"
    assert body["mapping_generation"] == 2
    assert "neu.example." in fake_pdns.zones
    # carol owns it immediately
    r = client.get("/proxy/v1/mapping/self", headers=act_as("carol"))
    assert r.json()["zones"] == ["neu.example."]
    # journaled as committed zone-create by the registrar env
    r = client.get(
        f"/proxy/v1/journal/{body['journal_id']}", headers={"X-API-Key": ADMIN_TOKEN}
    )
    entry = r.json()
    assert entry["operation"] == "zone-create"
    assert entry["status"] == "committed"
    assert entry["actor"] == "registrar"
    assert entry["user"] == "carol"


def test_register_refuses_existing_and_denied(client, fake_pdns):
    # owned in mapping (kunde.example -> alice)
    r = client.post(
        "/proxy/v1/register",
        headers=REG,
        json={"zone": "kunde.example", "user": "carol"},
    )
    assert r.status_code == 409
    # exists upstream but unowned
    fake_pdns.zones["ghost.example."] = {
        "id": "ghost.example.",
        "name": "ghost.example.",
        "kind": "Native",
        "rrsets": [],
    }
    r = client.post(
        "/proxy/v1/register",
        headers=REG,
        json={"zone": "ghost.example", "user": "carol"},
    )
    assert r.status_code == 409
    # deny set
    r = client.post(
        "/proxy/v1/register",
        headers=REG,
        json={"zone": "evil.in-berlin.de", "user": "carol"},
    )
    assert r.status_code == 403


def test_registrar_token_is_create_only(client):
    # no /api/v1 reads or writes with the registrar credential
    assert client.get(ZONES_PATH, headers=REG).json() == []
    r = client.patch(f"{ZONES_PATH}/kunde.example.", headers=REG, json=PATCH_BODY)
    assert r.status_code in (401, 403)
    r = client.delete(f"{ZONES_PATH}/kunde.example.", headers=REG)
    assert r.status_code in (401, 403)
    # direct zone-create on /api/v1 (bypassing template) also denied
    r = client.post(
        ZONES_PATH,
        headers=REG,
        json={"name": "raw.example.", "kind": "Native", "rrsets": []},
    )
    assert r.status_code in (401, 403)
    # and no proxy admin surfaces
    assert client.get("/proxy/v1/journal", headers=REG).status_code == 403
    assert client.get("/proxy/v1/mapping", headers=REG).status_code == 403


def test_register_denied_for_other_credentials(client):
    body = {"zone": "x.example", "user": "carol"}
    assert (
        client.post(
            "/proxy/v1/register", headers=act_as("alice"), json=body
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/proxy/v1/register", headers={"X-API-Key": EXPORTER_TOKEN}, json=body
        ).status_code
        == 403
    )
    # admin is allowed
    assert (
        client.post(
            "/proxy/v1/register", headers={"X-API-Key": ADMIN_TOKEN}, json=body
        ).status_code
        == 201
    )


def test_register_501_when_unconfigured(client):
    import powerdns_api_proxy.inberlin.runtime as runtime_mod

    rt = runtime_mod.get_runtime()
    saved, rt.settings.registration = rt.settings.registration, None
    try:
        r = client.post(
            "/proxy/v1/register",
            headers=REG,
            json={"zone": "y.example", "user": "carol"},
        )
        assert r.status_code == 501
    finally:
        rt.settings.registration = saved


# -- webui token binding ----------------------------------------------------------


def test_webui_token_bound_to_source_ip(client):
    import powerdns_api_proxy.inberlin.runtime as runtime_mod

    rt = runtime_mod.get_runtime()
    saved = rt.settings.webui_source_ips
    # TestClient connects as "testclient"
    rt.settings.webui_source_ips = ["192.168.254.9"]
    try:
        r = client.get(ZONES_PATH, headers=act_as("alice"))
        assert r.status_code == 403
        # the binding also applies WITHOUT act-as headers — a stolen token
        # from a foreign host must get nothing in any form
        r = client.get("/proxy/v1/whoami", headers={"X-API-Key": WEBUI_TOKEN})
        assert r.status_code == 403
        rt.settings.webui_source_ips = ["testclient"]
        assert client.get(ZONES_PATH, headers=act_as("alice")).status_code == 200
    finally:
        rt.settings.webui_source_ips = saved


# -- fail-closed journal ----------------------------------------------------------


def test_journal_uncertain_includes_live_upstream(client):
    # contract line 46: pending/uncertain rows PLUS live upstream state for
    # reconciliation — an admin must not have to refetch every zone by hand
    import asyncio

    import powerdns_api_proxy.inberlin.runtime as runtime_mod

    rt = runtime_mod.get_runtime()

    async def seed():
        from powerdns_api_proxy.inberlin.identity import Identity

        for zone in ("kunde.example.", "gone.example."):
            jid = await rt.store.journal_intent(
                Identity(kind="webui-act-as", actor="webui", effective_user="alice"),
                zone=zone,
                method="PATCH",
                path=f"/api/v1/servers/localhost/zones/{zone}",
                operation="rrset-patch",
                raw_request=None,
                before_state=None,
            )
            await rt.store.journal_finalize(
                jid,
                status="uncertain",
                status_code=None,
                after_state=None,
                rollbackable=False,
            )

    asyncio.run(seed())

    r = client.get("/proxy/v1/journal/uncertain", headers={"X-API-Key": ADMIN_TOKEN})
    assert r.status_code == 200
    body = r.json()
    assert len(body["entries"]) == 2
    # live state for the zone that exists upstream ...
    live = body["upstream"]["kunde.example."]
    assert live["rrsets"][0]["name"] == "www.kunde.example."
    # ... and an explicit null for the one that is gone
    assert body["upstream"]["gone.example."] is None


def test_journal_fail_closed_blocks_mutation(client, fake_pdns, tmp_path):
    import powerdns_api_proxy.inberlin.runtime as runtime_mod

    rt = runtime_mod.get_runtime()
    rt.store.close()  # journal unwritable

    r = client.patch(
        f"{ZONES_PATH}/kunde.example.", headers=act_as("alice"), json=PATCH_BODY
    )
    assert r.status_code == 503
    # mutation NOT forwarded
    live = fake_pdns.zones["kunde.example."]["rrsets"]
    assert live[0]["records"][0]["content"] == "192.0.2.1"
    # reopen so fixture teardown doesn't explode
    rt.store._conn = sqlite3.connect(
        str(tmp_path / "state.sqlite"), check_same_thread=False
    )


# -- ready / health -----------------------------------------------------------------


def test_health_public(client):
    assert client.get("/proxy/v1/health").status_code == 200


def test_journal_db_size_gauge_on_metrics(client):
    # contract lines 57-58: upstream /metrics (basic auth, metrics_proxy env)
    # plus journal DB size gauge
    import re

    from tests.unit.inberlin.conftest import METRICS_TOKEN

    r = client.get("/metrics", auth=("metrics", METRICS_TOKEN))
    assert r.status_code == 200
    match = re.search(r"^inberlin_journal_db_bytes ([\d.eE+]+)", r.text, re.MULTILINE)
    assert match, "journal DB size gauge missing from /metrics"
    assert float(match.group(1)) > 0


def test_ready_admin_only_and_reports(client):
    assert client.get("/proxy/v1/ready", headers=act_as("alice")).status_code == 403
    # contract: ADM/EXP/MET only — plain webui (no act-as header: 400 at the
    # identity layer) / registrar envs are refused
    assert (
        client.get("/proxy/v1/ready", headers={"X-API-Key": WEBUI_TOKEN}).status_code
        == 400
    )
    assert (
        client.get(
            "/proxy/v1/ready", headers={"X-API-Key": REGISTRAR_TOKEN}
        ).status_code
        == 403
    )
    r = client.get("/proxy/v1/ready", headers={"X-API-Key": EXPORTER_TOKEN})
    assert r.status_code == 200
    r = client.get("/proxy/v1/ready", headers={"X-API-Key": ADMIN_TOKEN})
    assert r.status_code == 200
    body = r.json()
    assert body["upstream"] and body["journal_writable"]
    assert body["mapping_generation"] == 1


# -- kimi round regressions ---------------------------------------------------


def test_create_override_duplicate_409(client):
    admin = {"X-API-Key": ADMIN_TOKEN}
    body = {"zone": "sub.kunde.example.", "user": "bob"}
    assert (
        client.post(
            "/proxy/v1/overrides", headers={**admin, "If-Match": "1"}, json=body
        ).status_code
        == 201
    )
    # UNIQUE(zone) violation must surface as a conflict, not a 500
    assert (
        client.post(
            "/proxy/v1/overrides", headers={**admin, "If-Match": "2"}, json=body
        ).status_code
        == 409
    )


def test_overrides_require_if_match_and_cas(client):
    # contract lines 41-42: override writes carry If-Match like mapping writes;
    # 400 missing, 409 stale — an override racing an exporter push must lose,
    # never silently apply against a mapping the admin hadn't seen
    admin = {"X-API-Key": ADMIN_TOKEN}
    body = {"zone": "sub.kunde.example.", "user": "bob"}
    r = client.post("/proxy/v1/overrides", headers=admin, json=body)
    assert r.status_code == 400
    r = client.post(
        "/proxy/v1/overrides", headers={**admin, "If-Match": "99"}, json=body
    )
    assert r.status_code == 409

    r = client.post(
        "/proxy/v1/overrides", headers={**admin, "If-Match": "1"}, json=body
    )
    assert r.status_code == 201
    override_id = r.json()["id"]
    # the write bumped the shared generation
    assert r.json()["generation"] == 2
    r = client.get("/proxy/v1/mapping", headers=admin)
    assert r.json()["generation"] == 2

    # an exporter push against the pre-override generation now conflicts
    r = client.put(
        "/proxy/v1/mapping",
        headers={"X-API-Key": EXPORTER_TOKEN, "If-Match": "1"},
        json={"mapping": {"alice": ["kunde.example"]}},
    )
    assert r.status_code == 409

    r = client.delete(f"/proxy/v1/overrides/{override_id}", headers=admin)
    assert r.status_code == 400
    r = client.delete(
        f"/proxy/v1/overrides/{override_id}", headers={**admin, "If-Match": "99"}
    )
    assert r.status_code == 409
    r = client.delete(
        f"/proxy/v1/overrides/{override_id}", headers={**admin, "If-Match": "2"}
    )
    assert r.status_code == 200
    assert r.json()["generation"] == 3


def test_nondict_json_body_not_500(client):
    # top-level JSON array: capture code must not crash on body.get()
    r = client.patch(
        f"{ZONES_PATH}/kunde.example.",
        headers={**act_as("alice"), "Content-Type": "application/json"},
        content="[1, 2]",
    )
    assert r.status_code != 500


# -- round-7 regressions: zone-op rollback drift ----------------------------------


def test_zone_create_rollback_drift_409(client, fake_pdns):
    r = client.post(
        "/proxy/v1/register",
        headers=REG,
        json={"zone": "drifty.example", "user": "carol"},
    )
    assert r.status_code == 201
    entry_id = r.json()["journal_id"]

    # the zone gains a record after creation — rollback must not delete it
    fake_pdns.zones["drifty.example."]["rrsets"].append(
        {
            "name": "www.drifty.example.",
            "type": "A",
            "ttl": 300,
            "records": [{"content": "192.0.2.5", "disabled": False}],
        }
    )

    r = client.post(
        f"/proxy/v1/journal/{entry_id}/rollback", headers={"X-API-Key": ADMIN_TOKEN}
    )
    assert r.status_code == 409
    assert "drifty.example." in fake_pdns.zones

    # admin force overrides the drift check
    r = client.post(
        f"/proxy/v1/journal/{entry_id}/rollback",
        headers={"X-API-Key": ADMIN_TOKEN},
        json={"force": True},
    )
    assert r.status_code == 200
    assert "drifty.example." not in fake_pdns.zones


def test_zone_delete_rollback_recreated_409(client, fake_pdns):
    admin = {"X-API-Key": ADMIN_TOKEN}
    r = client.delete(f"{ZONES_PATH}/kunde.example.", headers=admin)
    assert r.status_code == 204
    entry = client.get("/proxy/v1/journal", headers=admin).json()["entries"][0]

    # zone comes back out-of-band — recreate-rollback must not clobber it
    fake_pdns.zones["kunde.example."] = {
        "id": "kunde.example.",
        "name": "kunde.example.",
        "kind": "Native",
        "rrsets": [],
    }
    r = client.post(f"/proxy/v1/journal/{entry['id']}/rollback", headers=admin)
    assert r.status_code == 409
