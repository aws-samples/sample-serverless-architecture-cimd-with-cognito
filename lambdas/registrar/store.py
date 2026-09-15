"""Write side of the mapping table plus the registrar lock."""
from __future__ import annotations

import contextlib
import json
import time
from typing import Any

from boto3.dynamodb.types import TypeDeserializer, TypeSerializer

_ser, _de = TypeSerializer(), TypeDeserializer()


def _to_item(d: dict) -> dict:
    return {k: _ser.serialize(v) for k, v in d.items() if v is not None}


def _from_item(item: dict) -> dict:
    return {k: _de.deserialize(v) for k, v in item.items()}


class LockHeld(Exception):
    pass


class Store:
    def __init__(self, table: str, client: Any = None):
        self.table = table
        self._c = client

    @property
    def c(self):
        if self._c is None:
            import boto3
            self._c = boto3.client("dynamodb")
        return self._c

    # ---- mapping rows
    def get_client(self, url: str) -> dict | None:
        r = self.c.get_item(TableName=self.table, Key={"pk": {"S": f"CLIENT#{url}"}}, ConsistentRead=True)
        return _from_item(r["Item"]) if "Item" in r else None

    def list_clients(self) -> list[dict]:
        out, kwargs = [], {"TableName": self.table, "FilterExpression": "begins_with(pk, :p)",
                           "ExpressionAttributeValues": {":p": {"S": "CLIENT#"}}}
        while True:
            r = self.c.scan(**kwargs)
            out += [_from_item(i) for i in r.get("Items", [])]
            if "LastEvaluatedKey" not in r:
                return out
            kwargs["ExclusiveStartKey"] = r["LastEvaluatedKey"]

    def _client_item(self, url: str, row: dict) -> dict:
        return _to_item({**row, "pk": f"CLIENT#{url}", "cimd_url": url})

    def _index_item(self, cognito_client_id: str, url: str, enabled: bool) -> dict:
        return _to_item({"pk": f"INDEX#COGNITO#{cognito_client_id}", "cimd_url": url, "enabled": bool(enabled)})

    def _transact(self, items: list[dict]) -> None:
        """All-or-nothing write of the CLIENT# row and its INDEX# row(s) so the proxy and the verifier never see a half-state."""
        self.c.transact_write_items(TransactItems=items)

    def put_client(self, url: str, row: dict, retire_client_id: str | None = None,
                   retired_delete_after: int | None = None) -> None:
        """Write CLIENT#url and INDEX#COGNITO#<current id> atomically. When `retire_client_id` is given (a stale or
        rotated Cognito client) its INDEX# row is flipped to disabled in the SAME transaction, and when
        `retired_delete_after` is given the retired bookkeeping row is written in that transaction too, so a
        rotation can never leave an orphaned Cognito client."""
        items = [
            {"Put": {"TableName": self.table, "Item": self._client_item(url, row)}},
            {"Put": {"TableName": self.table, "Item": self._index_item(row["cognito_client_id"], url, row.get("enabled", False))}},
        ]
        if retire_client_id and retire_client_id != row["cognito_client_id"]:
            retired_url = f"retired://{retire_client_id}"
            items.append({"Put": {"TableName": self.table, "Item": self._index_item(retire_client_id, retired_url, False)}})
            if retired_delete_after is not None:
                retired = {"cognito_client_id": retire_client_id, "enabled": False, "delete_after": retired_delete_after,
                           "client_name": "retired", "redirect_uris": [], "cache_until": 0}
                items.append({"Put": {"TableName": self.table, "Item": self._client_item(retired_url, retired)}})
        self._transact(items)

    def set_enabled(self, row: dict, enabled: bool, delete_after: int | None = None) -> None:
        self.put_client(row["cimd_url"], {**row, "enabled": enabled, "delete_after": delete_after})

    def delete_client_rows(self, row: dict) -> None:
        self._transact([
            {"Delete": {"TableName": self.table, "Key": {"pk": {"S": f"CLIENT#{row['cimd_url']}"}}}},
            {"Delete": {"TableName": self.table, "Key": {"pk": {"S": f"INDEX#COGNITO#{row['cognito_client_id']}"}}}},
        ])

    # ---- lock
    def acquire_lock(self, owner: str, ttl_seconds: int) -> None:
        now = int(time.time())
        try:
            self.c.put_item(TableName=self.table,
                            Item=_to_item({"pk": "LOCK#registrar", "owner": owner, "ttl": now + ttl_seconds}),
                            ConditionExpression="attribute_not_exists(pk) OR #t < :now",
                            ExpressionAttributeNames={"#t": "ttl"},
                            ExpressionAttributeValues={":now": {"N": str(now)}})
        except self.c.exceptions.ConditionalCheckFailedException as e:
            raise LockHeld() from e

    def release_lock(self, owner: str) -> None:
        with contextlib.suppress(self.c.exceptions.ConditionalCheckFailedException):  # lock expired and was re-taken
            self.c.delete_item(TableName=self.table, Key={"pk": {"S": "LOCK#registrar"}},
                               ConditionExpression="#o = :o", ExpressionAttributeNames={"#o": "owner"},
                               ExpressionAttributeValues={":o": {"S": owner}})


def dumps(o) -> str:
    return json.dumps(o, sort_keys=True, default=str)
