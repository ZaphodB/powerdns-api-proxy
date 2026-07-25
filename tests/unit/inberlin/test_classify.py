"""Journal classification of zone-metadata requests.

The regression that motivates this file: /zones/<z>/metadata/<kind> is a
zone-addressed path, so before the explicit branch existed a DELETE of one
metadata kind fell through to the generic DELETE arm and was journaled as
`zone-delete` — whose inverse recreates the whole zone from the before-state.
"""

import pytest

from powerdns_api_proxy.inberlin.journal import OPERATIONS, classify
from powerdns_api_proxy.inberlin.rollback import NotRollbackable, build_rollback_request

ZONE = "/api/v1/servers/localhost/zones/example.com."


@pytest.mark.parametrize(
    "method,path",
    [
        ("POST", f"{ZONE}/metadata"),
        ("PUT", f"{ZONE}/metadata/SOA-EDIT"),
        ("DELETE", f"{ZONE}/metadata/SOA-EDIT"),
        ("DELETE", f"{ZONE}/metadata"),
    ],
)
def test_metadata_mutations_classify_as_zone_metadata(method, path):
    info = classify(method, path)
    assert info is not None
    assert info.operation == "zone-metadata"
    assert info.server_id == "localhost"
    assert info.zone_id == "example.com."


def test_metadata_reads_are_not_journal_relevant():
    assert classify("GET", f"{ZONE}/metadata") is None
    assert classify("GET", f"{ZONE}/metadata/SOA-EDIT") is None


def test_zone_delete_still_classifies_as_zone_delete():
    assert classify("DELETE", ZONE).operation == "zone-delete"


def test_zone_metadata_has_an_operations_entry():
    spec = OPERATIONS["zone-metadata"]
    assert spec.secret is False
    assert spec.pre_get is False
    assert spec.restore_from_before is False


def test_zone_metadata_is_not_rollbackable():
    entry = {"operation": "zone-metadata", "zone": "example.com."}
    with pytest.raises(NotRollbackable):
        build_rollback_request(entry)
