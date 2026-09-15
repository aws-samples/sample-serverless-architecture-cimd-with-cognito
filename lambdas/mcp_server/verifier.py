"""Token verification for the FastMCP resource server.

Layering:
  inner JWTVerifier  -> signature (Cognito JWKS), issuer (tokenIssuer), audience (resourceUrl). No scopes.
  ScopedVerifier     -> carries required_scopes so FastMCP's auth middleware answers a VALID token that lacks
                        the scope with 403 insufficient_scope (not 401), and optionally enforces that the
                        token's client_id maps to an enabled CIMD client (defence in depth behind Cognito's
                        scope grant, so disabling a mapping bites within the cache TTL).
"""
from __future__ import annotations

import logging

from fastmcp.server.auth import AccessToken, TokenVerifier
from shared.logging_setup import get_logger, log
from shared.mapping_store import MappingStore

logger = get_logger(__name__)


class ScopedVerifier(TokenVerifier):
    def __init__(self, inner: TokenVerifier, required_scopes: list[str], store: MappingStore | None = None):
        super().__init__(base_url=inner.base_url, required_scopes=required_scopes)
        self._inner = inner
        self._store = store

    async def verify_token(self, token: str) -> AccessToken | None:
        access = await self._inner.verify_token(token)
        if access is None:
            return None
        if self._store is not None:
            client_id = access.client_id or (access.claims or {}).get("client_id")
            if not client_id or not self._store.is_registered_cognito_client(client_id):
                log(logger, logging.WARNING, "token from unregistered or disabled client rejected", client_id=client_id)
                return None
        return access


# Backwards-compatible name used in tests/docs
RegisteredClientVerifier = ScopedVerifier
