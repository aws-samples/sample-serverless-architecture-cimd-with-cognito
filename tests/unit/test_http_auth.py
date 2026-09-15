"""HTTP-level auth semantics of the FastMCP resource server (RFC 6750):
401 invalid_token for missing/invalid tokens, 403 insufficient_scope for a valid token without the scope,
200 with the scope, 401 for a valid token from an unregistered client."""
import json
import time

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastmcp.server.auth.providers.jwt import JWTVerifier

ISS = "https://cognito-standin.test/pool"
BASE = "https://mcp.example.test"
RES = f"{BASE}/mcp"
SCOPE = f"{RES}/invoke"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PUB = KEY.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def mint(**over):
    now = int(time.time())
    claims = {"iss": ISS, "aud": RES, "scope": SCOPE, "client_id": "registered", "sub": "u1", "iat": now, "exp": now + 600}
    claims.update(over)
    return jwt.encode(claims, KEY, algorithm="RS256")


class FakeStore:
    def is_registered_cognito_client(self, cid):
        return cid == "registered"


@pytest.fixture()
def app(monkeypatch):
    env = {"PUBLIC_BASE_URL": BASE, "ORIGIN_BASE_URL": BASE, "AUTHORIZATION_SERVER_URL": BASE, "RESOURCE_URL": RES,
           "INVOKE_SCOPE": SCOPE, "ALLOWED_HOSTS": "", "TOKEN_ISSUER": ISS, "TABLE_NAME": "t", "REPLY_TEXT": "hello"}
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    import app as app_module
    inner = JWTVerifier(public_key=PUB, issuer=ISS, audience=RES)
    return app_module.build_app(inner_verifier=inner, store=FakeStore(), enforce_registered_client=True)


async def post(app, token=None, method="tools/list"):
    headers = {"content-type": "application/json", "accept": "application/json"}
    if token:
        headers["authorization"] = f"Bearer {token}"
    async with app.router.lifespan_context(app), \
            httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE) as c:
        return await c.post("/mcp", headers=headers, content=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method}))


@pytest.mark.asyncio
async def test_missing_token_401_with_resource_metadata(app):
    r = await post(app)
    assert r.status_code == 401
    assert f'resource_metadata="{BASE}/.well-known/oauth-protected-resource/mcp"' in r.headers["www-authenticate"]


@pytest.mark.asyncio
async def test_valid_token_200(app):
    r = await post(app, mint())
    assert r.status_code == 200 and "tools" in r.json()["result"]


@pytest.mark.asyncio
async def test_missing_scope_403_insufficient_scope(app):
    r = await post(app, mint(scope="openid"))
    assert r.status_code == 403
    assert r.json()["error"] == "insufficient_scope"
    assert 'error="insufficient_scope"' in r.headers["www-authenticate"]


@pytest.mark.asyncio
@pytest.mark.parametrize("over", [{"aud": "https://other.example/mcp"}, {"iss": "https://facade.example"}, {"exp": int(time.time()) - 10}])
async def test_invalid_tokens_401(app, over):
    r = await post(app, mint(**over))
    assert r.status_code == 401 and r.json()["error"] == "invalid_token"


@pytest.mark.asyncio
async def test_unregistered_client_401(app):
    r = await post(app, mint(client_id="not-registered"))
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_prm_document(app):
    async with app.router.lifespan_context(app), \
            httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE) as c:
        r = await c.get("/.well-known/oauth-protected-resource/mcp")
    assert r.status_code == 200
    body = r.json()
    assert body["resource"] == RES and body["authorization_servers"] == [BASE] and SCOPE in body["scopes_supported"]
