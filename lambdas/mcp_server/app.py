"""FastMCP resource server. Cognito is the token issuer; the CIMD proxy is the advertised authorization server.

RemoteAuthProvider.authorization_servers -> authorizationServerUrl (our proxy)
JWTVerifier.issuer                        -> tokenIssuer (Cognito)
JWTVerifier.audience                      -> resourceUrl (RFC 8707 resource binding)
"""
from __future__ import annotations

import os

from fastmcp import FastMCP
from fastmcp.server.auth import RemoteAuthProvider
from fastmcp.server.auth.providers.jwt import JWTVerifier
from shared.logging_setup import get_logger
from shared.mapping_store import MappingStore
from shared.runtime_config import get_urls

logger = get_logger(__name__)


def build_app(inner_verifier=None, store=None, enforce_registered_client: bool | None = None):
    """Build the ASGI app. Test seams: inner_verifier (e.g. a public-key JWTVerifier) and store (a fake MappingStore)."""
    urls = get_urls()
    token_issuer = os.environ["TOKEN_ISSUER"]
    jwks_url = os.environ.get("TOKEN_JWKS_URL") or f"{token_issuer}/.well-known/jwks.json"

    # Inner verifier: signature, issuer, audience only. Scopes live on the outer verifier so a valid
    # token without the scope yields 403 insufficient_scope instead of 401 (RFC 6750 §3.1).
    jwt_verifier = inner_verifier or JWTVerifier(jwks_uri=jwks_url, issuer=token_issuer, audience=urls.resource_url)
    if enforce_registered_client is None:
        enforce_registered_client = os.environ.get("ENFORCE_REGISTERED_CLIENT", "true").lower() == "true"
    if enforce_registered_client and store is None:
        store = MappingStore(cache_seconds=int(os.environ.get("REGISTERED_CLIENT_CACHE_SECONDS", "60")))
    if not enforce_registered_client:
        store = None
    from verifier import ScopedVerifier

    verifier = ScopedVerifier(jwt_verifier, required_scopes=[urls.invoke_scope], store=store)

    auth = RemoteAuthProvider(
        token_verifier=verifier,
        authorization_servers=[urls.authorization_server_url],
        base_url=urls.public_base_url,
        scopes_supported=[urls.invoke_scope],
    )
    mcp = FastMCP(name=os.environ.get("SERVER_NAME", "cimd-cognito-mcp"), auth=auth)

    reply_text = os.environ.get("REPLY_TEXT", "Tool invoked successfully")
    tool_name = os.environ.get("TOOL_NAME", "echo_hello")
    tool_description = os.environ.get("TOOL_DESCRIPTION", "Confirms the tool was invoked.")

    @mcp.tool(name=tool_name, description=tool_description)
    def _tool() -> str:
        return reply_text

    return mcp.http_app(path="/mcp", stateless_http=True, json_response=True,
                        allowed_hosts=list(urls.allowed_hosts) or None)


app = build_app()
