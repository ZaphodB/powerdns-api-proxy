import asyncio
import hashlib
import json
import os
import time
from collections.abc import Generator
from unittest.mock import patch

os.environ.setdefault("PROXY_CONFIG_PATH", "./config-example.yml")

import pytest
from fastapi.testclient import TestClient

import powerdns_api_proxy.inberlin.runtime as runtime_mod
from powerdns_api_proxy.inberlin.runtime import Runtime
from powerdns_api_proxy.inberlin.settings import (
    InBerlinSettings,
    OIDCSettings,
    RegistrationSettings,
)
from powerdns_api_proxy.models import (
    ProxyConfig,
    ProxyConfigEnvironment,
    ProxyConfigZone,
)

WEBUI_TOKEN = "webui-secret-token"
EXPORTER_TOKEN = "exporter-secret-token"
ADMIN_TOKEN = "admin-secret-token"
PLAIN_TOKEN = "plain-static-token"
REGISTRAR_TOKEN = "registrar-secret-token"
METRICS_TOKEN = "metrics-secret-token"


def sha512(s: str) -> str:
    return hashlib.sha512(s.encode()).hexdigest()


def make_config() -> ProxyConfig:
    return ProxyConfig(
        pdns_api_token="upstream-token",
        pdns_api_url="http://127.0.0.1:8081",
        environments=[
            ProxyConfigEnvironment(name="webui", token_sha512=sha512(WEBUI_TOKEN)),
            ProxyConfigEnvironment(
                name="exporter", token_sha512=sha512(EXPORTER_TOKEN)
            ),
            ProxyConfigEnvironment(
                name="infra-admin",
                token_sha512=sha512(ADMIN_TOKEN),
                zones=[ProxyConfigZone(name=".*", regex=True, admin=True)],
            ),
            ProxyConfigEnvironment(
                name="plain",
                token_sha512=sha512(PLAIN_TOKEN),
                zones=[ProxyConfigZone(name="static.example.")],
            ),
            ProxyConfigEnvironment(
                name="registrar", token_sha512=sha512(REGISTRAR_TOKEN)
            ),
            ProxyConfigEnvironment(
                name="metrics", token_sha512=sha512(METRICS_TOKEN), metrics_proxy=True
            ),
        ],
    )


def make_settings(tmp_path) -> InBerlinSettings:
    return InBerlinSettings(
        state_db=str(tmp_path / "state.sqlite"),
        deny_zones=["in-berlin.de"],
        environment_roles={
            "webui": ["webui"],
            "exporter": ["exporter"],
            "infra-admin": ["admin"],
            "registrar": ["registrar"],
            "metrics": ["metrics"],
        },
        registration=RegistrationSettings(nameservers=["ns1.example.", "ns2.example."]),
        oidc=OIDCSettings(
            issuer=OIDC_ISSUER, audience=OIDC_AUDIENCE, admin_group="dns-admins"
        ),
    )


OIDC_ISSUER = "https://auth.example/application/o/dnsapi/"
OIDC_AUDIENCE = "dnsapi"
_RSA_KEY = None


def _rsa_key():
    global _RSA_KEY
    if _RSA_KEY is None:
        from cryptography.hazmat.primitives.asymmetric import rsa

        _RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return _RSA_KEY


def install_test_jwks(validator) -> None:
    import jwt

    public_jwk = jwt.algorithms.RSAAlgorithm.to_jwk(
        _rsa_key().public_key(), as_dict=True
    )
    public_jwk["kid"] = "test-kid"
    validator._jwks = {"test-kid": jwt.PyJWK(dict(public_jwk, alg="RS256"))}
    validator._fetched_at = time.monotonic()


def bearer(sub: str = "user-123", admin: bool = False, **headers) -> dict:
    """Authorization header with a valid OIDC token signed by the test key."""
    import jwt

    now = int(time.time())
    claims = {
        "iss": OIDC_ISSUER,
        "aud": OIDC_AUDIENCE,
        "sub": sub,
        "iat": now,
        "exp": now + 300,
        "preferred_username": sub,
        "groups": ["dns-admins"] if admin else ["members"],
    }
    token = jwt.encode(
        claims, _rsa_key(), algorithm="RS256", headers={"kid": "test-kid"}
    )
    return {"Authorization": f"Bearer {token}", **headers}


class FakeResponse:
    def __init__(self, status: int, data):
        self.status = status
        self._data = data
        self.url = "http://fake-pdns/"

    async def text(self) -> str:
        return json.dumps(self._data) if self._data is not None else ""


class FakePDNS:
    """Minimal in-memory PowerDNS: zones dict keyed by canonical name."""

    def __init__(self):
        self.zones: dict[str, dict] = {}

    def _zone(self, zone_id: str):
        return self.zones.get(zone_id.rstrip(".").lower() + ".")

    async def get(self, path: str, params: dict = {}):
        parts = path.strip("/").split("/")
        if parts[-1] == "servers":
            return FakeResponse(200, [{"id": "localhost"}])
        if "zones" in parts:
            idx = parts.index("zones")
            if len(parts) == idx + 1:
                return FakeResponse(200, list(self.zones.values()))
            zone = self._zone(parts[idx + 1])
            if zone is None:
                return FakeResponse(404, {"error": "Not Found"})
            return FakeResponse(200, zone)
        return FakeResponse(200, {})

    async def request(
        self, method: str, path: str, params: dict = {}, payload: dict = {}
    ):
        if method == "GET":
            return await self.get(path, params)
        parts = path.strip("/").split("/")
        idx = parts.index("zones")
        if method == "POST":
            name = payload["name"].rstrip(".").lower() + "."
            if name in self.zones:
                return FakeResponse(409, {"error": "Conflict"})
            self.zones[name] = {
                "id": name,
                "name": name,
                "kind": payload.get("kind", "Native"),
                "rrsets": payload.get("rrsets", []),
            }
            return FakeResponse(201, self.zones[name])
        zone_id = parts[idx + 1].rstrip(".").lower() + "."
        zone = self.zones.get(zone_id)
        if zone is None:
            return FakeResponse(404, {"error": "Not Found"})
        if method == "DELETE":
            del self.zones[zone_id]
            return FakeResponse(204, None)
        if method == "PATCH":
            for change in payload.get("rrsets", []):
                key = (change["name"].rstrip(".").lower() + ".", change["type"])
                zone["rrsets"] = [
                    r
                    for r in zone["rrsets"]
                    if (r["name"].rstrip(".").lower() + ".", r["type"]) != key
                ]
                if change.get("changetype") == "REPLACE":
                    zone["rrsets"].append(
                        {
                            "name": change["name"],
                            "type": change["type"],
                            "ttl": change.get("ttl", 300),
                            "records": change.get("records", []),
                        }
                    )
            return FakeResponse(204, None)
        return FakeResponse(204, None)

    async def post(self, path, payload={}):
        return await self.request("POST", path, payload=payload)

    async def patch(self, path, payload={}):
        return await self.request("PATCH", path, payload=payload)

    async def put(self, path, payload={}):
        return await self.request("PUT", path, payload=payload)

    async def delete(self, path, payload={}):
        return await self.request("DELETE", path, payload=payload)


@pytest.fixture()
def fake_pdns() -> Generator[FakePDNS, None, None]:
    fake = FakePDNS()
    fake.zones["kunde.example."] = {
        "id": "kunde.example.",
        "name": "kunde.example.",
        "kind": "Native",
        "rrsets": [
            {
                "name": "www.kunde.example.",
                "type": "A",
                "ttl": 300,
                "records": [{"content": "192.0.2.1", "disabled": False}],
            },
        ],
    }
    with patch("powerdns_api_proxy.proxy.pdns", fake):
        yield fake


@pytest.fixture()
def client(tmp_path, fake_pdns) -> Generator[TestClient, None, None]:
    config = make_config()
    settings = make_settings(tmp_path)
    rt = Runtime(settings)
    install_test_jwks(rt.oidc)
    asyncio.run(rt.mapping.load())
    asyncio.run(
        rt.mapping.replace(
            0, {"alice": ["kunde.example"], "bob": ["bob.example"]}, "test-seed"
        )
    )
    runtime_mod._runtime = rt
    from powerdns_api_proxy.proxy import app

    with (
        patch("powerdns_api_proxy.config.load_config", return_value=config),
        patch("powerdns_api_proxy.middleware.load_config", return_value=config),
        patch(
            "powerdns_api_proxy.inberlin.middleware.load_config", return_value=config
        ),
    ):
        yield TestClient(app)
    runtime_mod._runtime = None
    rt.store.close()
