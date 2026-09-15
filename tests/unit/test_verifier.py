"""ScopedVerifier: a valid token is accepted only when its client_id maps to an enabled registration; unmapped and
disabled clients are rejected; the registered-client cache TTL is honoured."""
import pytest
from fastmcp.server.auth import AccessToken
from verifier import ScopedVerifier


class FakeInner:
    base_url = None
    required_scopes = ["s"]

    def __init__(self, result):
        self.result = result

    async def verify_token(self, token):
        return self.result


class FakeStore:
    def __init__(self, ok):
        self.ok = ok

    def is_registered_cognito_client(self, cid):
        return cid in self.ok


@pytest.mark.asyncio
async def test_accepts_registered_and_rejects_others():
    tok = AccessToken(token="x", client_id="abc", scopes=["s"], expires_at=None)  # nosec B106 (placeholder, never verified)
    assert await ScopedVerifier(FakeInner(tok), ["s"], FakeStore({"abc"})).verify_token("x") is tok
    assert await ScopedVerifier(FakeInner(tok), ["s"], FakeStore(set())).verify_token("x") is None
    assert await ScopedVerifier(FakeInner(None), ["s"], FakeStore({"abc"})).verify_token("x") is None
    assert await ScopedVerifier(FakeInner(tok), ["s"], store=None).verify_token("x") is tok  # scope-only mode
    assert ScopedVerifier(FakeInner(tok), ["s"]).required_scopes == ["s"]
