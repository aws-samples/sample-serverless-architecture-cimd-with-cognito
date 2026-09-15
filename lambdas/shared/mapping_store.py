"""Read side of the CIMD mapping table. Keys: CLIENT#<cimd_url>, INDEX#COGNITO#<cognito_client_id>.

`cache_seconds` (config `mcp.registeredClientCacheSeconds`, default 60) is a SECURITY PARAMETER, not a
performance knob: it is the upper bound on how long a warm Lambda container keeps honouring a client that the
registrar has just disabled or rotated. Every miss is read strongly consistent, so the only staleness is this
TTL. Lower it to shorten the window at the cost of a DynamoDB read per invocation; 0 disables the cache.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Mapping:
    cimd_url: str
    cognito_client_id: str
    enabled: bool
    redirect_uris: tuple[str, ...]
    client_name: str
    cache_until: int = 0  # epoch seconds; the proxy authorizes only while now < cache_until (else it revalidates)


class MappingStore:
    def __init__(self, table_name: str | None = None, cache_seconds: int = 60, client: Any = None):
        self._table = table_name or os.environ["TABLE_NAME"]
        self._ttl = cache_seconds
        self._client = client
        self._cache: dict[str, tuple[float, Mapping | None]] = {}

    def _ddb(self):
        if self._client is None:
            import boto3
            self._client = boto3.client("dynamodb")
        return self._client

    def _get(self, pk: str, consistent: bool = False) -> dict | None:
        resp = self._ddb().get_item(TableName=self._table, Key={"pk": {"S": pk}}, ConsistentRead=consistent)
        return resp.get("Item")

    @staticmethod
    def _to_mapping(item: dict, cimd_url: str) -> Mapping:
        return Mapping(
            cimd_url=cimd_url,
            cognito_client_id=item["cognito_client_id"]["S"],
            enabled=item.get("enabled", {}).get("BOOL", False),
            redirect_uris=tuple(x["S"] for x in item.get("redirect_uris", {}).get("L", [])),
            client_name=item.get("client_name", {}).get("S", ""),
            cache_until=int(item.get("cache_until", {}).get("N", "0")),
        )

    def by_cimd_url(self, cimd_url: str, consistent: bool = False) -> Mapping | None:
        """`consistent=True` bypasses the local cache and reads strongly consistent: the proxy uses it on every
        authorization decision so a disablement or rotation written by the registrar is honoured immediately."""
        key = f"CLIENT#{cimd_url}"
        hit = None if consistent else self._cache.get(key)
        if hit and time.time() - hit[0] < self._ttl:
            return hit[1]
        item = self._get(key, consistent=consistent)
        mapping = self._to_mapping(item, cimd_url) if item else None
        self._cache[key] = (time.time(), mapping)
        return mapping

    def is_registered_cognito_client(self, cognito_client_id: str) -> bool:
        """True when the Cognito app client id maps to an enabled CIMD client (registrar-created).

        A disabled client keeps access for at most `cache_seconds` after the registrar disables it: that TTL is
        the security window, see the module docstring.
        """
        key = f"INDEX#COGNITO#{cognito_client_id}"
        hit = self._cache.get(key)
        if hit and time.time() - hit[0] < self._ttl:
            return hit[1] is not None
        # Security gate: strongly consistent so a disablement is honoured deterministically once the local cache expires.
        item = self._get(key, consistent=True)
        ok = bool(item) and item.get("enabled", {}).get("BOOL", False)
        self._cache[key] = (time.time(), Mapping(item["cimd_url"]["S"], cognito_client_id, True, (), "") if ok else None)
        return ok
