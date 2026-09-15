"""Cognito control-plane operations for shadow app clients and their Managed Login branding."""
from __future__ import annotations

import contextlib
import re
from typing import Any

_NAME_OK = re.compile(r"[^\w\s+=,.@-]")


def sanitize_client_name(name: str, prefix: str = "cimd") -> str:
    cleaned = _NAME_OK.sub("", name).strip() or "client"
    return f"{prefix} {cleaned}"[:128]


class CognitoOps:
    def __init__(self, user_pool_id: str, client: Any = None):
        self.pool = user_pool_id
        self._client = client

    @property
    def c(self):
        if self._client is None:
            import boto3
            self._client = boto3.client("cognito-idp")
        return self._client

    def create_client(self, *, name: str, redirect_uris: list[str], scopes: list[str],
                      access_minutes: int, refresh_days: int) -> str:
        resp = self.c.create_user_pool_client(
            UserPoolId=self.pool,
            ClientName=name,
            GenerateSecret=False,
            AllowedOAuthFlowsUserPoolClient=True,
            AllowedOAuthFlows=["code"],
            AllowedOAuthScopes=scopes,
            CallbackURLs=redirect_uris,
            SupportedIdentityProviders=["COGNITO"],
            ExplicitAuthFlows=["ALLOW_REFRESH_TOKEN_AUTH"],
            PreventUserExistenceErrors="ENABLED",
            EnableTokenRevocation=True,
            AccessTokenValidity=access_minutes,
            IdTokenValidity=access_minutes,
            RefreshTokenValidity=refresh_days,
            TokenValidityUnits={"AccessToken": "minutes", "IdToken": "minutes", "RefreshToken": "days"},
        )
        return resp["UserPoolClient"]["ClientId"]

    def update_callbacks(self, client_id: str, redirect_uris: list[str]) -> None:
        current = self.c.describe_user_pool_client(UserPoolId=self.pool, ClientId=client_id)["UserPoolClient"]
        keep = ["ClientName", "ExplicitAuthFlows", "SupportedIdentityProviders", "AllowedOAuthFlows", "AllowedOAuthScopes",
                "AllowedOAuthFlowsUserPoolClient", "PreventUserExistenceErrors", "EnableTokenRevocation",
                "AccessTokenValidity", "IdTokenValidity", "RefreshTokenValidity", "TokenValidityUnits"]
        args = {k: current[k] for k in keep if k in current}
        self.c.update_user_pool_client(UserPoolId=self.pool, ClientId=client_id, CallbackURLs=redirect_uris, **args)

    def describe_client(self, client_id: str) -> dict | None:
        try:
            return self.c.describe_user_pool_client(UserPoolId=self.pool, ClientId=client_id)["UserPoolClient"]
        except self.c.exceptions.ResourceNotFoundException:
            return None

    def delete_client(self, client_id: str) -> None:
        with contextlib.suppress(self.c.exceptions.ResourceNotFoundException):  # already gone: idempotent
            self.c.delete_user_pool_client(UserPoolId=self.pool, ClientId=client_id)

    def ensure_branding(self, client_id: str) -> bool:
        """Managed Login v2 renders nothing for a client without a branding record. Returns True when created."""
        try:
            self.c.describe_managed_login_branding_by_client(UserPoolId=self.pool, ClientId=client_id)
            return False
        except self.c.exceptions.ResourceNotFoundException:
            self.c.create_managed_login_branding(UserPoolId=self.pool, ClientId=client_id, UseCognitoProvidedValues=True)
            return True

    def delete_branding(self, client_id: str) -> None:
        try:
            b = self.c.describe_managed_login_branding_by_client(UserPoolId=self.pool, ClientId=client_id)
            self.c.delete_managed_login_branding(UserPoolId=self.pool, ManagedLoginBrandingId=b["ManagedLoginBranding"]["ManagedLoginBrandingId"])
        except self.c.exceptions.ResourceNotFoundException:
            pass
