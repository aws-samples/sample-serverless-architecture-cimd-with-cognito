"""Authorization-time freshness contract between the proxy and the registrar.

The schedule gives availability; this gives the security guarantee. A mapping authorizes only when it is `enabled`
and `now < cache_until`. Otherwise the proxy synchronously asks the private registrar to revalidate and fails closed
(`temporarily_unavailable`) unless the registrar answers `fresh && enabled`. `fresh` means "validated by this
invocation", so no-cache/no-store documents authorize the triggering request and are revalidated again next time.
"""
from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable

from oauth import OAuthError
from shared.logging_setup import get_logger, log
from shared.mapping_store import Mapping, MappingStore

logger = get_logger(__name__)
Revalidate = Callable[[str], dict]


class Freshness:
    def __init__(self, store: MappingStore, revalidate: Revalidate, *, retry_after_seconds: int, now=time.time):
        self.store, self.revalidate, self.retry_after, self.now = store, revalidate, retry_after_seconds, now

    def enabled_mapping(self, cimd_url: str) -> Mapping:
        """Strongly consistent read; refuses unknown or disabled clients. No freshness requirement (used by /revoke)."""
        m = self.store.by_cimd_url(cimd_url, consistent=True)
        if not m or not m.enabled:
            raise OAuthError("invalid_client", "client_id is not an allow-listed, registered CIMD client")
        return m

    def fresh_mapping(self, cimd_url: str, loaded: Mapping | None = None) -> Mapping:
        """Mapping that may be used to authorize NOW (/authorize, /consent, /token). `loaded` skips the re-read when the
        caller has just fetched the row with enabled_mapping()."""
        m = loaded if loaded is not None else self.enabled_mapping(cimd_url)
        if int(self.now()) < m.cache_until:
            return m
        result = self._revalidate(cimd_url)
        status = result.get("status")
        # Only a completed reconciliation ("ok") or an allow-list refusal may say the client is gone. "locked",
        # "error", or any unknown status is transient and must fail closed as temporarily_unavailable, never as
        # invalid_client (a client would otherwise treat a busy registrar as a revoked registration).
        if status == "not_allowed" or (status == "ok" and result.get("enabled") is False):
            log(logger, logging.WARNING, "client disabled during on-demand revalidation", cimd_url=cimd_url, result=result)
            raise OAuthError("invalid_client", "client_id is not an allow-listed, registered CIMD client")
        if status != "ok" or not result.get("fresh", False) or not result.get("enabled", False):
            log(logger, logging.WARNING, "on-demand revalidation did not confirm the client; failing closed",
                cimd_url=cimd_url, result=result)
            raise OAuthError("temporarily_unavailable", "client metadata could not be revalidated; retry shortly",
                             status=503, redirectable=True, retry_after=self.retry_after)
        # Re-read: the registrar may have rotated the shadow client or changed redirect_uris in this very call.
        return self.enabled_mapping(cimd_url)

    def _revalidate(self, cimd_url: str) -> dict:
        try:
            result = self.revalidate(cimd_url)
        except Exception as e:  # timeout, throttling, permission: all fail closed
            log(logger, logging.ERROR, "registrar revalidation call failed", cimd_url=cimd_url, error=str(e))
            return {"status": "error", "fresh": False}
        if not isinstance(result, dict):
            return {"status": "error", "fresh": False}
        return result


def lambda_revalidator(function_name: str, timeout_seconds: float, client=None) -> Revalidate:
    """Synchronous invoke of the registrar with a hard client-side timeout and no retries (a retry would only
    lengthen the user's wait; the next authorization attempt retries naturally)."""
    def call(cimd_url: str) -> dict:
        nonlocal client
        if client is None:
            import boto3
            from botocore.config import Config
            client = boto3.client("lambda", config=Config(read_timeout=timeout_seconds, connect_timeout=2,
                                                           retries={"max_attempts": 0}))
        resp = client.invoke(FunctionName=function_name, InvocationType="RequestResponse",
                             Payload=json.dumps({"action": "revalidate", "cimd_url": cimd_url}).encode())
        payload = json.loads(resp["Payload"].read() or b"{}")
        if resp.get("FunctionError"):
            raise RuntimeError(f"registrar function error: {payload.get('errorType', 'unknown')}")
        return payload
    return call
