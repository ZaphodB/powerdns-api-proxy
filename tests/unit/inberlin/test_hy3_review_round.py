"""Findings from the hy3 review round.

A refused reload must leave the process EXACTLY as it was. The environment-roles
validation added in the previous round ran after `reset_settings_cache()`, so a
config that failed validation still left its settings in the module cache while
the runtime kept the old ones — a "refused" reload that half-applied, which is
the contract this code exists to uphold.

Also: a deny-list entry that is empty or whitespace canonicalizes to the root
and matches nothing, protecting nothing while looking like protection.
"""

import pytest
from pydantic import ValidationError

from powerdns_api_proxy.inberlin.settings import InBerlinSettings


# The "refused reload publishes nothing" property is asserted in
# test_reload_is_all_or_nothing.py. The version that lived here mocked
# load_config, and that mock is exactly why this round's fix looked complete
# while the live environment map was still being published: the real loader is
# lru_cache(maxsize=1), and a mocked one cannot exhibit the eviction that caused
# the bug. Do not reintroduce a mocked variant.


@pytest.mark.parametrize("bad", ["", "   ", "\t"])
def test_empty_deny_entries_are_rejected(bad):
    with pytest.raises(ValidationError):
        InBerlinSettings(deny_zones=[bad])
    with pytest.raises(ValidationError):
        InBerlinSettings(deny_zones_exact=[bad])


def test_normal_deny_entries_still_accepted():
    settings = InBerlinSettings(
        deny_zones=["infra.in-berlin.de"], deny_zones_exact=["in-berlin.de"]
    )
    assert settings.deny_zones == ["infra.in-berlin.de"]
