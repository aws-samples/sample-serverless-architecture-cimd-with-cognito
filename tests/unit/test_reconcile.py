"""Registrar reaction matrix against a fake Cognito and a fake table: first sight, cached no-op, redirect change,
key rotation (single transaction, retired row), same-URL JWKS rotation, first-sight JWKS refusal, no-store handling,
JWKS failure without false rotation, missing client recreated, staleness disable, allow-list removal and deletion,
invalid document, 304, lock contention, on-demand revalidation (validated_now vs cache freshness)."""
import json

import pytest
from botocore.exceptions import ClientError
from fetcher import FetchResult
from reconcile import Reconciler, Settings
from store import LockHeld, Store

URL = "https://c.example/m"
SCOPE = "https://mcp.example/mcp/invoke"


def rnf():
    return ClientError({"Error": {"Code": "ResourceNotFoundException"}}, "op")


class FakeExceptions:
    ResourceNotFoundException = ClientError
    ConditionalCheckFailedException = ClientError


class FakeCognito:
    """Minimal boto3 cognito-idp stand-in."""
    def __init__(self):
        self.clients, self.branding, self.n = {}, set(), 0
        self.exceptions = FakeExceptions()

    def create_user_pool_client(self, **kw):
        self.n += 1
        cid = f"client{self.n}"
        self.clients[cid] = kw
        return {"UserPoolClient": {"ClientId": cid, **kw}}

    def describe_user_pool_client(self, UserPoolId, ClientId):
        if ClientId not in self.clients:
            raise rnf()
        return {"UserPoolClient": {"ClientId": ClientId, **self.clients[ClientId]}}

    def update_user_pool_client(self, UserPoolId, ClientId, **kw):
        self.clients[ClientId].update(kw)

    def delete_user_pool_client(self, UserPoolId, ClientId):
        if ClientId not in self.clients:
            raise rnf()
        del self.clients[ClientId]

    def describe_managed_login_branding_by_client(self, UserPoolId, ClientId):
        if ClientId not in self.branding:
            raise rnf()
        return {"ManagedLoginBranding": {"ManagedLoginBrandingId": f"b-{ClientId}"}}

    def create_managed_login_branding(self, UserPoolId, ClientId, UseCognitoProvidedValues):
        assert UseCognitoProvidedValues is True
        self.branding.add(ClientId)

    def delete_managed_login_branding(self, UserPoolId, ManagedLoginBrandingId):
        self.branding.discard(ManagedLoginBrandingId.removeprefix("b-"))


class FakeDDB:
    def __init__(self):
        self.items = {}
        self.exceptions = FakeExceptions()

    def get_item(self, TableName, Key, ConsistentRead=False):
        i = self.items.get(Key["pk"]["S"])
        return {"Item": i} if i else {}

    def put_item(self, TableName, Item, **kw):
        pk = Item["pk"]["S"]
        if "ConditionExpression" in kw and pk in self.items:
            now = int(kw["ExpressionAttributeValues"][":now"]["N"])
            if int(self.items[pk]["ttl"]["N"]) >= now:
                raise ClientError({"Error": {"Code": "ConditionalCheckFailedException"}}, "PutItem")
        self.items[pk] = Item

    def delete_item(self, TableName, Key, **kw):
        pk = Key["pk"]["S"]
        if "ConditionExpression" in kw and pk in self.items:
            owner = kw["ExpressionAttributeValues"][":o"]["S"]
            if self.items[pk]["owner"]["S"] != owner:
                raise ClientError({"Error": {"Code": "ConditionalCheckFailedException"}}, "DeleteItem")
        self.items.pop(pk, None)

    def scan(self, **kw):
        return {"Items": [i for k, i in self.items.items() if k.startswith("CLIENT#")]}

    def transact_write_items(self, TransactItems):
        assert 1 <= len(TransactItems) <= 100
        staged = dict(self.items)  # all-or-nothing
        for t in TransactItems:
            if "Put" in t:
                staged[t["Put"]["Item"]["pk"]["S"]] = t["Put"]["Item"]
            elif "Delete" in t:
                staged.pop(t["Delete"]["Key"]["pk"]["S"], None)
            else:
                raise AssertionError("unsupported transact op")
        self.items = staged
        self.transactions = getattr(self, "transactions", 0) + 1


def fetch_ok(doc, headers=None, jwks=None):
    def f(url, *, max_bytes, timeout, etag=None, deadline_seconds=None):
        if url == doc.get("jwks_uri"):
            if jwks is None:
                from fetcher import FetchError
                raise FetchError("jwks unreachable")
            return FetchResult(200, json.dumps(jwks).encode(), {}, jwks)
        return FetchResult(200, json.dumps(doc).encode(), headers or {"cache-control": "max-age=3600", "etag": "v1"}, doc)
    return f


def make(doc=None, fetch=None, allowed=(URL,), now=1_000_000):
    from cognito_ops import CognitoOps
    ddb, cog = FakeDDB(), FakeCognito()
    store = Store("t", client=ddb)
    ops = CognitoOps("pool", client=cog)
    s = Settings(list(allowed), SCOPE, 15, 30, 3.0, 6.0, 5120, 300, 86400)
    clock = {"t": now}
    rec = Reconciler(s, store, ops, fetch=fetch or fetch_ok(doc or base_doc()), now=lambda: clock["t"])
    return rec, store, cog, ddb, clock


def base_doc(**over):
    d = {"client_id": URL, "client_name": "Claude (web)", "redirect_uris": ["https://c.example/cb"]}
    d.update(over)
    return d


def test_first_sight_creates_client_branding_and_rows():
    rec, store, cog, ddb, _ = make()
    s = rec.run()
    assert s.created == 1 and s.branding_created == 1
    assert ddb.transactions >= 1  # CLIENT# and INDEX# written atomically
    row = store.get_client(URL)
    assert row["enabled"] is True and row["cognito_client_id"] == "client1"
    assert ddb.items["INDEX#COGNITO#client1"]["enabled"]["BOOL"] is True
    kw = cog.clients["client1"]
    assert kw["GenerateSecret"] is False and kw["AllowedOAuthScopes"] == ["openid", SCOPE]
    assert kw["CallbackURLs"] == ["https://c.example/cb"] and kw["ClientName"].endswith("Claude web")  # parentheses sanitised
    assert "client1" in cog.branding


def test_second_run_within_cache_is_noop_and_reconciles_missing_branding():
    rec, store, cog, ddb, clock = make()
    rec.run()
    cog.branding.clear()
    s = rec.run()
    assert s.created == 0 and s.skipped_cached == 1 and s.branding_created == 1 and "client1" in cog.branding


def test_redirect_change_updates_callbacks():
    rec, store, cog, ddb, clock = make()
    rec.run()
    clock["t"] += 100_000  # past cache
    rec.fetch = fetch_ok(base_doc(redirect_uris=["https://c.example/cb2"]))
    s = rec.run()
    assert s.updated == 1 and cog.clients["client1"]["CallbackURLs"] == ["https://c.example/cb2"]
    assert store.get_client(URL)["redirect_uris"] == ["https://c.example/cb2"]


def test_key_change_rotates_client_and_schedules_old_deletion():
    rec, store, cog, ddb, clock = make()
    rec.run()
    clock["t"] += 100_000
    rec.fetch = fetch_ok(base_doc(jwks_uri="https://c.example/jwks"), jwks={"keys": [{"kty": "RSA", "kid": "a"}]})
    s = rec.run()
    assert s.rotated == 1
    row = store.get_client(URL)
    assert row["cognito_client_id"] == "client2" and ddb.items["INDEX#COGNITO#client2"]["enabled"]["BOOL"] is True
    assert ddb.items["INDEX#COGNITO#client1"]["enabled"]["BOOL"] is False  # old client's tokens rejected immediately
    assert "client1" in cog.clients  # Cognito client kept for one access-token lifetime
    clock["t"] += 15 * 60 + 1
    s2 = rec.run()
    assert s2.deleted == 1 and "client1" not in cog.clients and "client1" not in cog.branding and "INDEX#COGNITO#client1" not in ddb.items


def test_same_url_jwks_content_rotation_detected():
    doc = base_doc(jwks_uri="https://c.example/jwks")
    rec, store, cog, ddb, clock = make(doc=doc, fetch=fetch_ok(doc, jwks={"keys": [{"kty": "RSA", "kid": "a"}]}))
    rec.run()
    clock["t"] += 100_000
    rec.fetch = fetch_ok(doc, jwks={"keys": [{"kty": "RSA", "kid": "b"}]})  # same jwks_uri, new key
    assert rec.run().rotated == 1


def test_first_sight_with_unreachable_jwks_uri_is_refused():
    doc = base_doc(jwks_uri="https://c.example/jwks")
    rec, store, cog, ddb, clock = make(doc=doc, fetch=fetch_ok(doc, jwks=None))
    s = rec.run()
    assert s.created == 0 and store.get_client(URL) is None and not cog.clients
    assert any("jwks_uri could not be validated" in e for e in s.errors)


def test_rotation_is_a_single_transaction_including_retired_row():
    rec, store, cog, ddb, clock = make()
    rec.run()
    clock["t"] += 100_000
    before = ddb.transactions
    rec.fetch = fetch_ok(base_doc(jwks_uri="https://c.example/jwks"), jwks={"keys": [{"kty": "RSA", "kid": "a"}]})
    rec.run()
    assert ddb.transactions == before + 1  # CLIENT#, INDEX#new, INDEX#old(disabled), CLIENT#retired in one transaction
    assert "CLIENT#retired://client1" in ddb.items and store.get_client(URL)["jwks_fetched_at"] == clock["t"]


def test_no_store_keeps_only_derived_state():
    rec, store, cog, ddb, clock = make(fetch=fetch_ok(base_doc(), headers={"cache-control": "no-store"}))
    rec.run()
    row = store.get_client(URL)
    assert row.get("doc") is None and row.get("etag") is None  # no reusable representation retained
    assert row["redirect_uris"] == ["https://c.example/cb"] and row["jwks_fingerprint"] and row["cache_until"] == clock["t"]


def test_revalidate_one_reports_freshness_and_refuses_unknown():
    rec, store, cog, ddb, clock = make()
    rec.run()
    clock["t"] += 100_000  # stale
    r = rec.revalidate_one(URL)
    assert r["status"] == "ok" and r["fresh"] is True and r["enabled"] is True
    assert rec.revalidate_one("https://not.allowed/x")["status"] == "not_allowed"
    from fetcher import FetchError
    def failing(url, *, max_bytes, timeout, etag=None, deadline_seconds=None):
        raise FetchError("down")
    rec.fetch = failing
    clock["t"] += 100_000
    r = rec.revalidate_one(URL)
    assert r["fresh"] is False and r["enabled"] is True  # stale but still enabled → proxy must fail closed


def test_jwks_fetch_failure_does_not_rotate_and_makes_mapping_stale():
    doc = base_doc(jwks_uri="https://c.example/jwks")
    rec, store, cog, ddb, clock = make(doc=doc, fetch=fetch_ok(doc, jwks={"keys": [{"kty": "RSA", "kid": "a"}]}))
    rec.run()
    fp_before = store.get_client(URL)["jwks_fingerprint"]
    clock["t"] += 100_000
    rec.fetch = fetch_ok(doc, jwks=None)  # main doc OK, jwks_uri unreachable
    s = rec.run()
    row = store.get_client(URL)
    assert s.rotated == 0 and row["jwks_fingerprint"] == fp_before and row["jwks_fetched_at"] == 1_000_000
    assert row["cache_until"] == clock["t"]  # effectively stale: authorization must fail closed
    assert rec.revalidate_one(URL)["fresh"] is False
    # beyond the bounded JWKS staleness interval the client is disabled
    clock["t"] += 72 * 3600 + 1
    assert rec.run().disabled == 1 and store.get_client(URL)["enabled"] is False


def test_no_store_with_jwks_uri_then_failure_keeps_fingerprint_no_false_rotation():
    doc = base_doc(jwks_uri="https://c.example/jwks")
    rec, store, cog, ddb, clock = make(doc=doc, fetch=fetch_ok(doc, headers={"cache-control": "no-store"}, jwks={"keys": [{"kid": "a"}]}))
    rec.run()
    row = store.get_client(URL)
    assert row.get("jwks_uri_content") is None and row["jwks_fingerprint"]  # derived state only
    fp = row["jwks_fingerprint"]
    clock["t"] += 10
    rec.fetch = fetch_ok(doc, headers={"cache-control": "no-store"}, jwks=None)
    s = rec.run()
    assert s.rotated == 0 and store.get_client(URL)["jwks_fingerprint"] == fp and len(cog.clients) == 1


def test_missing_cognito_client_recreated_and_old_index_disabled():
    rec, store, cog, ddb, clock = make()
    rec.run()
    del cog.clients["client1"]  # deleted out of band
    clock["t"] += 100_000
    s = rec.run()
    assert s.created == 1 and store.get_client(URL)["cognito_client_id"] == "client2"
    assert ddb.items["INDEX#COGNITO#client1"]["enabled"]["BOOL"] is False
    assert ddb.items["INDEX#COGNITO#client2"]["enabled"]["BOOL"] is True


def test_fetch_failures_disable_after_max_stale():
    from fetcher import FetchError
    rec, store, cog, ddb, clock = make()
    rec.run()
    def failing(url, *, max_bytes, timeout, etag=None, deadline_seconds=None):
        raise FetchError("down")
    rec.fetch = failing
    clock["t"] += 100_000  # past cache, within max stale (72h)
    assert rec.run().disabled == 0 and store.get_client(URL)["enabled"] is True
    clock["t"] += 72 * 3600  # beyond max stale
    assert rec.run().disabled == 1 and store.get_client(URL)["enabled"] is False


def test_no_cache_document_kept_but_expires_immediately():
    rec, store, cog, ddb, clock = make(fetch=fetch_ok(base_doc(), headers={"cache-control": "no-cache"}))
    rec.run()
    row = store.get_client(URL)
    assert row["doc"]["client_name"] == "Claude (web)" and row["cache_until"] == clock["t"]  # kept, but must revalidate before use
    assert rec.run().skipped_cached == 0  # refetched on the very next run


def test_removed_from_allowlist_is_disabled_then_deleted():
    rec, store, cog, ddb, clock = make()
    rec.run()
    rec.s.allowed_clients = []
    s = rec.run()
    assert s.disabled == 1 and store.get_client(URL)["enabled"] is False
    assert ddb.items["INDEX#COGNITO#client1"]["enabled"]["BOOL"] is False
    clock["t"] += 15 * 60 + 1
    s2 = rec.run()
    assert s2.deleted == 1 and store.get_client(URL) is None and not cog.clients


def test_invalid_document_never_stored_and_disables_existing():
    rec, store, cog, ddb, clock = make()
    rec.run()
    clock["t"] += 100_000
    rec.fetch = fetch_ok(base_doc(token_endpoint_auth_method="client_secret_basic"))  # nosec B106 (auth-method name)
    s = rec.run()
    assert s.invalid == 1 and store.get_client(URL)["enabled"] is False
    assert store.get_client(URL)["doc"]["client_name"] == "Claude (web)"  # old doc retained


def test_304_extends_cache():
    rec, store, cog, ddb, clock = make()
    rec.run()
    clock["t"] += 100_000
    rec.fetch = lambda url, *, max_bytes, timeout, etag=None, deadline_seconds=None: FetchResult(304, b"", {"cache-control": "max-age=600"}, None)
    s = rec.run()
    assert s.not_modified == 1 and store.get_client(URL)["cache_until"] == clock["t"] + 600


def test_304_revalidates_stored_redirect_uris_against_the_current_rules():
    """A 304 says the document is unchanged, not that it still passes: the RULES may have been tightened since.

    Without this, a redirect_uri stored by an older build is never re-checked, because an unchanged document with
    a matching ETag never reaches validate_document again — so the hardening would never apply to an existing
    deployment's mappings.
    """
    rec, store, cog, ddb, clock = make()
    rec.run()
    assert store.get_client(URL)["enabled"] is True

    # Simulate a row written before redirect_uri validation rejected loopback literals.
    row = store.get_client(URL)
    row["redirect_uris"] = ["https://127.0.0.1/cb"]
    store.put_client(URL, row)

    clock["t"] += 100_000
    rec.fetch = lambda url, *, max_bytes, timeout, etag=None, deadline_seconds=None: FetchResult(304, b"", {"cache-control": "max-age=600"}, None)
    s = rec.run()
    assert s.invalid == 1 and s.disabled == 1 and s.not_modified == 0
    assert store.get_client(URL)["enabled"] is False
    assert ddb.items[f"INDEX#COGNITO#{row['cognito_client_id']}"]["enabled"]["BOOL"] is False


def test_lock_contention_and_expiry():
    store = Store("t", client=FakeDDB())
    store.acquire_lock("a", 300)
    with pytest.raises(LockHeld):
        store.acquire_lock("b", 300)
    store.release_lock("b")  # not owner: no-op
    with pytest.raises(LockHeld):
        store.acquire_lock("b", 300)
    store.release_lock("a")
    store.acquire_lock("b", 300)


def test_delete_all_removes_everything_except_fixture():
    rec, store, cog, ddb, clock = make()
    rec.run()
    store.put_client("fixture://dev", {"cognito_client_id": "fx", "enabled": True, "client_name": "f", "redirect_uris": [], "cache_until": 0})
    s = rec.delete_all()
    assert s.deleted == 2 and not cog.clients and store.get_client(URL) is None


# ---- validated_now vs cache_fresh: no-cache / no-store must be able to authorize the request that triggered revalidation
def _fetch_counter(doc, headers):
    """fetch_ok wrapper that counts main-document fetches so 'revalidates again' is observable."""
    inner = fetch_ok(doc, headers=headers)
    calls = {"n": 0}
    def f(url, *, max_bytes, timeout, etag=None, deadline_seconds=None):
        if url == URL:
            calls["n"] += 1
        return inner(url, max_bytes=max_bytes, timeout=timeout, etag=etag, deadline_seconds=deadline_seconds)
    return f, calls


@pytest.mark.parametrize("directive", ["no-cache", "no-store"])
def test_revalidate_one_authorizes_current_request_for_uncacheable_documents(directive):
    fetch, calls = _fetch_counter(base_doc(), {"cache-control": directive})
    rec, store, cog, ddb, clock = make(fetch=fetch)
    r = rec.revalidate_one(URL)  # first sight through the on-demand path
    assert r == {"status": "ok", "fresh": True, "enabled": True, "errors": []}
    assert store.get_client(URL)["cache_until"] == clock["t"]  # validated now, but NOT reusable by a later request
    # the very next authorization must revalidate again (stored entry is stale immediately) ...
    n = calls["n"]
    r2 = rec.revalidate_one(URL)
    assert calls["n"] == n + 1 and r2["fresh"] is True and r2["enabled"] is True
    assert len(cog.clients) == 1  # same shadow client; revalidation is not a re-registration


def test_revalidate_one_no_store_then_scheduled_run_refetches_again():
    rec, store, cog, ddb, clock = make(fetch=fetch_ok(base_doc(), headers={"cache-control": "no-store"}))
    assert rec.revalidate_one(URL)["fresh"] is True
    clock["t"] += 1
    s = rec.run()
    assert s.skipped_cached == 0 and s.not_modified == 0  # no etag was retained → a full refetch, never a 304 shortcut


@pytest.mark.parametrize("directive", ["no-cache", "no-store"])
def test_revalidate_one_uncacheable_main_document_failure_is_not_fresh(directive):
    from fetcher import FetchError
    rec, store, cog, ddb, clock = make(fetch=fetch_ok(base_doc(), headers={"cache-control": directive}))
    assert rec.revalidate_one(URL)["fresh"] is True
    def failing(url, *, max_bytes, timeout, etag=None, deadline_seconds=None):
        raise FetchError("down")
    rec.fetch = failing
    r = rec.revalidate_one(URL)
    assert r["fresh"] is False and r["enabled"] is True and r["errors"]  # still enabled, but this request fails closed


@pytest.mark.parametrize("directive", ["no-cache", "no-store"])
def test_revalidate_one_uncacheable_jwks_failure_is_not_fresh(directive):
    doc = base_doc(jwks_uri="https://c.example/jwks")
    jwks = {"keys": [{"kty": "RSA", "kid": "a"}]}
    rec, store, cog, ddb, clock = make(doc=doc, fetch=fetch_ok(doc, headers={"cache-control": directive}, jwks=jwks))
    assert rec.revalidate_one(URL)["fresh"] is True
    fp = store.get_client(URL)["jwks_fingerprint"]
    rec.fetch = fetch_ok(doc, headers={"cache-control": directive}, jwks=None)  # main doc OK, JWKS unreachable
    r = rec.revalidate_one(URL)
    assert r["fresh"] is False and r["enabled"] is True
    assert store.get_client(URL)["jwks_fingerprint"] == fp and len(cog.clients) == 1  # no false rotation
    rec.fetch = fetch_ok(doc, headers={"cache-control": directive}, jwks=jwks)  # JWKS back → authorizes again
    assert rec.revalidate_one(URL)["fresh"] is True


def test_revalidate_one_invalid_document_disables_and_is_not_fresh():
    rec, store, cog, ddb, clock = make(fetch=fetch_ok(base_doc(), headers={"cache-control": "no-cache"}))
    assert rec.revalidate_one(URL)["fresh"] is True
    rec.fetch = fetch_ok(base_doc(redirect_uris=["http://insecure/cb"]), headers={"cache-control": "no-cache"})
    r = rec.revalidate_one(URL)
    assert r == {"status": "ok", "fresh": False, "enabled": False, "errors": []}


def test_revalidate_one_exception_mid_reaction_fails_closed():
    rec, store, cog, ddb, clock = make()
    def boom(**kw):
        raise RuntimeError("cognito down")
    cog.create_user_pool_client = boom  # first sight cannot create the shadow client
    r = rec.revalidate_one(URL)
    assert r["fresh"] is False and r["enabled"] is False and "cognito down" in r["errors"][0]
    assert store.get_client(URL) is None


def test_revalidate_one_304_is_a_successful_revalidation():
    rec, store, cog, ddb, clock = make()
    rec.run()
    clock["t"] += 100_000
    def not_modified(url, *, max_bytes, timeout, etag=None, deadline_seconds=None):
        assert etag == "v1"
        return FetchResult(304, b"", {"cache-control": "max-age=60"}, None)
    rec.fetch = not_modified
    r = rec.revalidate_one(URL)
    assert r["fresh"] is True and store.get_client(URL)["cache_until"] == clock["t"] + 300  # bounded by cache_min_seconds
