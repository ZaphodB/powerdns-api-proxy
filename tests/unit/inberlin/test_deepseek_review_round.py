"""Findings from the deepseek review round.

The rollback endpoint re-checks ownership inside the per-zone lock (added in an
earlier round). Ordinary /api/v1 mutations did not: IdentityMiddleware checks
ownership outside that lock, and mapping writes take a different lock, so a
member whose zone was reassigned or denied in between could still land the
mutation. The journal would then record a write that was authorized when it was
admitted and not when it executed.

Also covers the case a previous reviewer could only mark uncertain: subtree deny
entries are matched case-insensitively and dot-insensitively, because
zone_is_or_under canonicalizes BOTH arguments.
"""

import pytest

from powerdns_api_proxy.inberlin.mapping import MappingView

MEMBER = "tn-one"
ZONE = "member-one.in-berlin.de."


def _view(**kwargs) -> MappingView:
    return MappingView(
        generation=1,
        zones_by_user={MEMBER: frozenset({ZONE})},
        overrides={},
        **kwargs,
    )


@pytest.mark.parametrize(
    "queried",
    [
        "ns1.in-berlin.de",
        "ns1.in-berlin.de.",
        "NS1.IN-BERLIN.DE.",
        "Ns1.In-Berlin.De",
        "sub.ns1.in-berlin.de.",
        "DEEP.SUB.NS1.in-berlin.de",
    ],
)
def test_subtree_deny_is_case_and_dot_insensitive(queried):
    """zone_is_or_under canonicalizes both sides; assert it, do not assume it."""
    view = _view(deny_zones=("ns1.in-berlin.de",))
    assert view.is_denied(queried) is True
    assert view.owner_of(queried) is None


@pytest.mark.parametrize(
    "entry", ["ns1.in-berlin.de", "ns1.in-berlin.de.", "NS1.IN-BERLIN.DE."]
)
def test_subtree_deny_entry_spelling_does_not_matter(entry):
    view = _view(deny_zones=(entry,))
    assert view.is_denied("ns1.in-berlin.de.") is True


def test_neighbouring_name_is_not_caught_by_subtree_deny():
    """Label boundaries: 'notns1.in-berlin.de' must not match 'ns1.in-berlin.de'."""
    view = _view(deny_zones=("ns1.in-berlin.de",))
    assert view.is_denied("notns1.in-berlin.de.") is False


class _FakeMappingView:
    """Ownership flips the first time it is asked, simulating a mapping write
    that lands between the identity check and the locked section."""

    def __init__(self, owner_sequence):
        self._sequence = list(owner_sequence)

    def owner_of(self, zone):
        return self._sequence.pop(0) if self._sequence else None


def test_ownership_recheck_sees_the_reassignment():
    """The property the middleware re-check depends on: a second owner_of call
    observes the new mapping, so checking twice is not redundant."""
    view = _FakeMappingView([MEMBER, "tn-two"])
    assert view.owner_of(ZONE) == MEMBER  # identity middleware
    assert view.owner_of(ZONE) != MEMBER  # inside the zone lock
