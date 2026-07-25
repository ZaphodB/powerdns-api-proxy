"""Exact-match deny entries.

`deny_zones` denies a zone and everything under it, which is right for infra
namespaces but wrong for an apex whose subzones are the product: IN-Berlin hands
members zones under in-berlin.de, so `deny_zones: [in-berlin.de]` denied every
member zone. Found on the first ans0 deployment — the member could not read its
own zone ("zone not owned") and the registrar refused every registration with
"zone is on the deny list".

`deny_zones_exact` denies just the named zone.
"""

import pytest

from powerdns_api_proxy.inberlin.mapping import MappingView

MAPPING = {"tn-test": frozenset({"proxy-test.in-berlin.de"})}


def _view(**kwargs) -> MappingView:
    return MappingView(generation=1, zones_by_user=MAPPING, overrides={}, **kwargs)


def test_subtree_deny_blocks_descendants():
    view = _view(deny_zones=("in-berlin.de",))
    assert view.owner_of("in-berlin.de") is None
    assert view.owner_of("proxy-test.in-berlin.de") is None


def test_exact_deny_protects_only_the_apex():
    view = _view(deny_zones_exact=("in-berlin.de",))
    assert view.owner_of("in-berlin.de") is None
    assert view.owner_of("proxy-test.in-berlin.de") == "tn-test"


def test_exact_deny_is_label_boundary_safe():
    """A name that merely ends with the string must not be treated as the zone."""
    view = _view(deny_zones_exact=("berlin.de",))
    assert not view.is_denied("in-berlin.de")
    assert not view.is_denied("proxy-test.in-berlin.de")
    assert view.is_denied("berlin.de")


def test_exact_deny_matches_regardless_of_trailing_dot():
    """A deny list must never fail open on a formatting difference."""
    for written in ("in-berlin.de", "in-berlin.de.", "IN-Berlin.DE"):
        view = _view(deny_zones_exact=(written,))
        assert view.is_denied("in-berlin.de"), written
        assert view.owner_of("in-berlin.de") is None, written


def test_both_lists_apply_together():
    view = _view(deny_zones=("infra.in-berlin.de",), deny_zones_exact=("in-berlin.de",))
    assert view.owner_of("in-berlin.de") is None
    assert view.owner_of("infra.in-berlin.de") is None
    assert view.owner_of("db.infra.in-berlin.de") is None
    assert view.owner_of("proxy-test.in-berlin.de") == "tn-test"


@pytest.mark.parametrize(
    "zone,denied",
    [
        ("in-berlin.de", True),
        ("IN-BERLIN.DE.", True),  # canonicalization
        ("proxy-test.in-berlin.de", False),
        ("notin-berlin.de", False),
    ],
)
def test_is_denied_matches_canonically(zone, denied):
    view = _view(deny_zones_exact=("in-berlin.de",))
    assert view.is_denied(zone) is denied
