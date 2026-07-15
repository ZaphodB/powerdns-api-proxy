import asyncio
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from powerdns_api_proxy.inberlin.oidc import OIDCValidator
from powerdns_api_proxy.inberlin.settings import OIDCSettings

ISSUER = "https://auth.example/application/o/dnsapi/"
AUDIENCE = "dnsapi"


@pytest.fixture(scope="module")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def make_validator(rsa_key) -> OIDCValidator:
    settings = OIDCSettings(issuer=ISSUER, audience=AUDIENCE, admin_group="dns-admins")
    v = OIDCValidator(settings)
    public_jwk = jwt.algorithms.RSAAlgorithm.to_jwk(rsa_key.public_key(), as_dict=True)
    public_jwk["kid"] = "test-kid"
    v._jwks = {"test-kid": jwt.PyJWK(dict(public_jwk, alg="RS256"))}
    v._fetched_at = time.monotonic()
    return v


def make_token(rsa_key, **overrides):
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "user-123",
        "iat": now,
        "exp": now + 300,
        "preferred_username": "Alice",
        "groups": ["members"],
    }
    claims.update(overrides)
    return jwt.encode(claims, rsa_key, algorithm="RS256", headers={"kid": "test-kid"})


def test_valid_token(rsa_key):
    v = make_validator(rsa_key)
    claims = asyncio.run(v.validate(make_token(rsa_key)))
    assert claims["sub"] == "user-123"
    assert not v.is_admin(claims)


def test_admin_group(rsa_key):
    v = make_validator(rsa_key)
    claims = asyncio.run(v.validate(make_token(rsa_key, groups=["dns-admins"])))
    assert v.is_admin(claims)


def test_wrong_audience_rejected(rsa_key):
    v = make_validator(rsa_key)
    with pytest.raises(jwt.InvalidAudienceError):
        asyncio.run(v.validate(make_token(rsa_key, aud="other-app")))


def test_wrong_issuer_rejected(rsa_key):
    v = make_validator(rsa_key)
    with pytest.raises(jwt.InvalidIssuerError):
        asyncio.run(v.validate(make_token(rsa_key, iss="https://evil.example/")))


def test_expired_rejected(rsa_key):
    v = make_validator(rsa_key)
    now = int(time.time())
    with pytest.raises(jwt.ExpiredSignatureError):
        asyncio.run(v.validate(make_token(rsa_key, exp=now - 3600, iat=now - 7200)))


def test_disallowed_alg_rejected(rsa_key):
    v = make_validator(rsa_key)
    token = jwt.encode(
        {"iss": ISSUER, "aud": AUDIENCE, "sub": "x"}, "hmac-secret", algorithm="HS256"
    )
    with pytest.raises(ValueError):
        asyncio.run(v.validate(token))


def test_missing_groups_claim_not_admin(rsa_key):
    v = make_validator(rsa_key)
    claims = asyncio.run(v.validate(make_token(rsa_key, groups=None)))
    assert not v.is_admin(claims)


def test_token_without_kid_rejected(rsa_key):
    v = make_validator(rsa_key)
    now = int(time.time())
    token = jwt.encode(
        {"iss": ISSUER, "aud": AUDIENCE, "sub": "x", "iat": now, "exp": now + 300},
        rsa_key,
        algorithm="RS256",  # no kid header
    )
    with pytest.raises(ValueError, match="kid"):
        asyncio.run(v.validate(token))


def test_unknown_kid_refresh_cooldown(rsa_key, monkeypatch):
    # forged kids must not drive unlimited JWKS fetches — even when the
    # fetch itself fails (IdP down), the cooldown clock still advances
    v = make_validator(rsa_key)
    fetches = []

    async def failing_jwks_url():
        fetches.append(1)
        raise RuntimeError("idp down")

    monkeypatch.setattr(v, "_jwks_url", failing_jwks_url)

    # cooldown active from make_validator's fresh _fetched_at → no fetch
    asyncio.run(v._refresh())
    assert fetches == []
    # expire the cooldown, spam refreshes: exactly ONE fetch attempt goes out
    v._fetched_at = time.monotonic() - 10
    for _ in range(5):
        try:
            asyncio.run(v._refresh())
        except RuntimeError:
            pass
    assert len(fetches) == 1
