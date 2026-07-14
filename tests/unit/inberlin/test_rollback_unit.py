import json

import pytest

from powerdns_api_proxy.inberlin.rollback import (
    NotRollbackable,
    build_rollback_request,
    inverse_rrsets,
)


def test_inverse_created_rrset_is_delete():
    rows = [{"name": "www.k.example.", "rtype": "A", "before_rrset": None,
             "after_rrset": '{"ttl": 300}'}]
    patch = inverse_rrsets(rows)
    assert patch == [{"name": "www.k.example.", "type": "A", "changetype": "DELETE"}]


def test_inverse_replaced_rrset_restores_prior_incl_ttl():
    before = {"name": "www.k.example.", "type": "A", "ttl": 1234,
              "records": [{"content": "192.0.2.1", "disabled": False}]}
    rows = [{"name": "www.k.example.", "rtype": "A",
             "before_rrset": json.dumps(before), "after_rrset": '{"ttl": 300}'}]
    patch = inverse_rrsets(rows)
    assert patch[0]["changetype"] == "REPLACE"
    assert patch[0]["ttl"] == 1234
    assert patch[0]["records"] == [{"content": "192.0.2.1", "disabled": False}]


def test_zone_delete_rollback_recreates_from_export():
    export = {"name": "k.example.", "kind": "Native", "rrsets": [{"name": "k.example.",
              "type": "SOA", "ttl": 3600, "records": []}], "serial": 5, "dnssec": True}
    entry = {"operation": "zone-delete", "zone": "k.example.",
             "before_state": json.dumps(export), "rrsets": []}
    method, path, body = build_rollback_request(entry)
    assert (method, path) == ("POST", "/zones")
    assert body["name"] == "k.example."
    assert body["nameservers"] == []
    assert "dnssec" not in body  # non-reconstructable state excluded
    assert "serial" not in body


def test_zone_create_rollback_is_delete():
    entry = {"operation": "zone-create", "zone": "k.example.",
             "before_state": None, "rrsets": []}
    method, path, body = build_rollback_request(entry)
    assert (method, path, body) == ("DELETE", "/zones/k.example.", None)


def test_non_rollbackable_ops_raise():
    for op in ("crypto", "tsig", "other", "zone-meta"):
        with pytest.raises(NotRollbackable):
            build_rollback_request(
                {"operation": op, "zone": "k.example.", "before_state": None, "rrsets": []}
            )
    with pytest.raises(NotRollbackable):
        build_rollback_request(
            {"operation": "rrset-patch", "zone": "k.example.",
             "before_state": None, "rrsets": []}
        )
