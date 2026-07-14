"""Ephemeral environment synthesis for Teilnehmer-scoped identities.

For an identity with an effective Teilnehmer, builds an upstream
ProxyConfigEnvironment on the fly from the live mapping view: every owned zone
becomes a zone entry with subzones=True and full record access; override
grants included; deny-set zones excluded by owner resolution. Admin OIDC
identities get a wildcard admin environment.

The synthesized environment is placed in the current_environment contextvar;
the patched upstream get_environment_for_token() prefers it over the static
token map, which is what keeps every upstream endpoint untouched.
"""

from powerdns_api_proxy.inberlin.identity import Identity
from powerdns_api_proxy.inberlin.mapping import MappingView
from powerdns_api_proxy.models import ProxyConfigEnvironment, ProxyConfigZone

# 128 hex zeros: syntactically valid, matches no real token (tokens hash to
# sha512 of themselves; nothing hashes to all-zeros in practice and the static
# map lookup happens on real hashes only).
_PLACEHOLDER_HASH = "0" * 128


def environment_for_teilnehmer(
    teilnehmer: str, view: MappingView
) -> ProxyConfigEnvironment:
    zones = []
    for zone in sorted(view.zones_for(teilnehmer)):
        # owner_of re-checks deny set and override precedence: a zone listed in
        # the mapping but overridden away or denied must not be granted.
        if view.owner_of(zone) != teilnehmer:
            continue
        zones.append(
            ProxyConfigZone(
                name=zone,
                admin=True,
                subzones=True,
                cryptokeys=True,
            )
        )
    return ProxyConfigEnvironment(
        name=f"tn:{teilnehmer}",
        token_sha512=_PLACEHOLDER_HASH,
        zones=zones,
    )


def environment_for_admin(identity: Identity) -> ProxyConfigEnvironment:
    return ProxyConfigEnvironment(
        name=f"admin:{identity.actor}",
        token_sha512=_PLACEHOLDER_HASH,
        zones=[ProxyConfigZone(name=".*", regex=True, admin=True, subzones=True, cryptokeys=True)],
        global_search=True,
        global_cryptokeys=True,
        global_tsigkeys=True,
        global_config=True,
        global_statistics=True,
    )
