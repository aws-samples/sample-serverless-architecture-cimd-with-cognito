"""Read side of the mapping table: CIMD URL and Cognito client id lookups, the local cache TTL, and the strongly
consistent registered-client gate."""
from shared.mapping_store import MappingStore


class FakeDDB:
    def __init__(self, items):
        self.items = items
        self.calls = 0

    def get_item(self, TableName, Key, ConsistentRead=False):
        self.calls += 1
        item = self.items.get(Key["pk"]["S"])
        return {"Item": item} if item else {}


def test_registered_client_lookup_and_cache():
    ddb = FakeDDB({"INDEX#COGNITO#abc": {"pk": {"S": "INDEX#COGNITO#abc"}, "cimd_url": {"S": "https://c.example/m"}, "enabled": {"BOOL": True}},
                   "INDEX#COGNITO#off": {"pk": {"S": "INDEX#COGNITO#off"}, "cimd_url": {"S": "https://c.example/m"}, "enabled": {"BOOL": False}}})
    store = MappingStore(table_name="t", cache_seconds=60, client=ddb)
    assert store.is_registered_cognito_client("abc") is True
    assert store.is_registered_cognito_client("abc") is True
    assert ddb.calls == 1
    assert store.is_registered_cognito_client("off") is False
    assert store.is_registered_cognito_client("missing") is False


def test_by_cimd_url():
    ddb = FakeDDB({"CLIENT#https://c.example/m": {"cognito_client_id": {"S": "abc"}, "enabled": {"BOOL": True},
                                                  "redirect_uris": {"L": [{"S": "https://c.example/cb"}]}, "client_name": {"S": "C"}}})
    m = MappingStore(table_name="t", client=ddb).by_cimd_url("https://c.example/m")
    assert m and m.cognito_client_id == "abc" and m.redirect_uris == ("https://c.example/cb",)
    assert MappingStore(table_name="t", client=ddb).by_cimd_url("https://nope.example/x") is None
