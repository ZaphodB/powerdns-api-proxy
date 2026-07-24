from powerdns_api_proxy.inberlin.mapping import MappingView
from powerdns_api_proxy.inberlin.names import (
    canonical_user,
    canonical_zone,
    zone_is_or_under,
)


def test_canonical_zone():
    assert canonical_zone("Example.DE") == "example.de."
    assert canonical_zone("example.de.") == "example.de."
    assert canonical_zone(" example.de ") == "example.de."


def test_canonical_zone_idna():
    assert canonical_zone("münchen.example") == "xn--mnchen-3ya.example."


def test_canonical_tn():
    assert canonical_user("  Alice ") == "alice"


def test_label_boundary():
    assert zone_is_or_under("sub.example.de", "example.de")
    assert zone_is_or_under("example.de", "example.de")
    assert not zone_is_or_under("evilexample.de", "example.de")
    assert not zone_is_or_under("example.de", "sub.example.de")


def _view(**kw):
    defaults = dict(generation=1, zones_by_user={}, overrides={}, deny_zones=())
    defaults.update(kw)
    return MappingView(**defaults)


def test_owner_implicit_subzone():
    v = _view(zones_by_user={"alice": frozenset({"kunde.example."})})
    assert v.owner_of("kunde.example.") == "alice"
    assert v.owner_of("deep.sub.kunde.example.") == "alice"
    assert v.owner_of("evilkunde.example.") is None


def test_owner_longest_suffix_wins():
    v = _view(
        zones_by_user={
            "alice": frozenset({"example."}),
            "bob": frozenset({"sub.example."}),
        }
    )
    assert v.owner_of("x.sub.example.") == "bob"
    assert v.owner_of("other.example.") == "alice"


def test_override_beats_implicit_and_mapping_entry():
    v = _view(
        zones_by_user={
            "alice": frozenset({"example."}),
            "bob": frozenset({"deep.sub.example."}),
        },
        overrides={"sub.example.": "carol"},
    )
    # override on sub.example. beats alice's implicit grant
    assert v.owner_of("sub.example.") == "carol"
    assert v.owner_of("x.sub.example.") == "carol"
    # override-first: an applicable ancestor override wins even over a deeper
    # explicit mapping entry — carol's delegation of sub.example. is a
    # deliberate admin exception that a bulk-exported bob entry can't silently
    # override (an admin would add a deeper override for bob instead).
    assert v.owner_of("deep.sub.example.") == "carol"


def test_ancestor_override_wins_over_deeper_mapping_entry():
    # override-first: even a more-specific explicit mapping entry does not beat
    # an ancestor override (the admin's deliberate delegation holds).
    v = _view(
        overrides={"example.": "carol"},
        zones_by_user={"bob": frozenset({"deep.sub.example."})},
    )
    assert v.owner_of("deep.sub.example.") == "carol"
    assert v.owner_of("x.deep.sub.example.") == "carol"


def test_deeper_override_wins_over_shallower():
    v = _view(
        overrides={"sub.example.": "carol", "deep.sub.example.": "dave"},
        zones_by_user={"alice": frozenset({"example."})},
    )
    assert v.owner_of("deep.sub.example.") == "dave"
    assert v.owner_of("other.sub.example.") == "carol"


def test_deny_set_resolves_to_nobody():
    v = _view(
        zones_by_user={"alice": frozenset({"in-berlin.de."})},
        overrides={"sub.in-berlin.de.": "alice"},
        deny_zones=("in-berlin.de.",),
    )
    assert v.owner_of("in-berlin.de.") is None
    assert v.owner_of("sub.in-berlin.de.") is None


def test_zones_for_includes_overrides():
    v = _view(
        zones_by_user={"alice": frozenset({"a.example."})},
        overrides={"sub.b.example.": "alice"},
    )
    assert v.zones_for("Alice") == {"a.example.", "sub.b.example."}
