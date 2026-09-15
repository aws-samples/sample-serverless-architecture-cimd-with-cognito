"""Runtime URL configuration: environment override for tests, SSM GetParametersByPath with pagination, and the TTL cache."""
import shared.runtime_config as rc


def test_env_fallback(monkeypatch):
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://pub.example")
    monkeypatch.setenv("ORIGIN_BASE_URL", "https://origin.example")
    monkeypatch.setenv("AUTHORIZATION_SERVER_URL", "https://pub.example")
    monkeypatch.setenv("RESOURCE_URL", "https://pub.example/mcp")
    monkeypatch.setenv("INVOKE_SCOPE", "https://pub.example/mcp/invoke")
    monkeypatch.setenv("ALLOWED_HOSTS", "origin.example,pub.example")
    u = rc.get_urls()
    assert u.resource_url == "https://pub.example/mcp"
    assert u.allowed_hosts == ("origin.example", "pub.example")


def test_ssm_path_and_cache(monkeypatch):
    for k in ("PUBLIC_BASE_URL", "RESOURCE_URL", "ORIGIN_BASE_URL", "AUTHORIZATION_SERVER_URL", "INVOKE_SCOPE"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("SSM_PREFIX", "/p/dev")
    monkeypatch.setenv("SSM_CACHE_SECONDS", "300")
    calls = {"n": 0}

    class FakeSSM:
        def get_parameters_by_path(self, **kw):
            calls["n"] += 1
            assert kw["Path"] == "/p/dev" and kw["Recursive"] is False
            names = ["public_base_url", "origin_base_url", "authorization_server_url", "resource_url", "invoke_scope", "allowed_hosts"]
            return {"Parameters": [{"Name": f"/p/dev/{n}", "Value": f"v-{n}"} for n in names]}

    import sys
    import types
    fake_boto3 = types.SimpleNamespace(client=lambda name: FakeSSM())
    monkeypatch.setitem(sys.modules, "boto3", fake_boto3)
    rc._cache = None
    assert rc.get_urls().resource_url == "v-resource_url"
    assert rc.get_urls().resource_url == "v-resource_url"
    assert calls["n"] == 1  # cached
    assert rc.get_urls(force=True).resource_url == "v-resource_url"
    assert calls["n"] == 2
