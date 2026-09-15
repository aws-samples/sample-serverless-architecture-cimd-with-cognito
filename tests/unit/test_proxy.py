"""cimd-proxy: metadata, /authorize validation and error shapes, consent CSRF, freshness fail-closed, /token and /revoke
relay, test client documents, HTTP API event parsing. No AWS."""
import base64
import json
import re
from urllib.parse import parse_qs, urlsplit

import consent
import pytest
from cognito_relay import RelayResult
from freshness import Freshness
from oauth import Request, add_query
from proxy_app import App, Settings
from shared.mapping_store import Mapping
from shared.runtime_config import Urls

BASE = "https://api.example.test"
RES = f"{BASE}/mcp"
SCOPE = f"{RES}/invoke"
ISS = "https://cognito-idp.ap-southeast-2.amazonaws.com/ap-southeast-2_pool"
LOGIN = "https://login.example.test"
CID = "https://client.example/oauth/cimd.json"
CB = "https://client.example/callback"
CB2 = "https://client.example/callback2"
URLS = Urls(BASE, BASE, BASE, RES, SCOPE, ())
NOW = 1_000_000


class FakeStore:
    def __init__(self, rows=None):
        self.rows = rows if rows is not None else {}
        self.reads = 0

    def by_cimd_url(self, url, consistent=False):
        self.reads += 1
        assert consistent is True, "the proxy must read mappings strongly consistent"
        return self.rows.get(url)


class FakeRelay:
    def __init__(self, result=None):
        self.calls = []
        self.result = result or RelayResult(200, {"access_token": "eyJ.a.b", "token_type": "Bearer", "expires_in": 900})

    def token(self, form):
        self.calls.append(("token", form))
        return self.result

    def revoke(self, form):
        self.calls.append(("revoke", form))
        return self.result


def mapping(**over):
    d = dict(cimd_url=CID, cognito_client_id="shadow1", enabled=True, redirect_uris=(CB, CB2), client_name="Example client",
             cache_until=NOW + 300)
    d.update(over)
    return Mapping(**d)


def make(rows=None, *, revalidate=None, consent_on=True, test_client=False, relay=None, now=NOW):
    store = FakeStore(rows if rows is not None else {CID: mapping()})
    calls = []

    def _reval(url):
        calls.append(url)
        if revalidate is None:
            raise AssertionError("unexpected revalidation")
        return revalidate(url) if callable(revalidate) else revalidate

    clock = {"t": now}
    fresh = Freshness(store, _reval, retry_after_seconds=10, now=lambda: clock["t"])
    settings = Settings(token_issuer=ISS, login_base_url=LOGIN, show_consent=consent_on, consent_cookie_max_age=300,
                        metadata_cache_seconds=300, test_client_enabled=test_client,
                        test_client_path="/test-client/metadata.json", test_client_name="Test client")
    relay = relay or FakeRelay()
    app = App(settings, lambda: URLS, fresh, relay)
    return app, store, relay, calls, clock


def get(app, path, **query):
    return app.handle(Request("GET", path, query, {}, {}, ""))


def post(app, path, form, cookies=None):
    from urllib.parse import urlencode
    return app.handle(Request("POST", path, {}, {"content-type": "application/x-www-form-urlencoded"}, cookies or {}, urlencode(form)))


def authz(**over):
    q = {"response_type": "code", "client_id": CID, "redirect_uri": CB, "scope": SCOPE, "state": "xyz",
         "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "code_challenge_method": "S256", "resource": RES}
    for k, v in over.items():
        if v is None:
            q.pop(k, None)
        else:
            q[k] = v
    return q


def location_params(resp):
    loc = resp.headers["location"]
    return loc.split("?")[0], {k: v[0] for k, v in parse_qs(urlsplit(loc).query, keep_blank_values=True).items()}


def csp_directives(resp) -> dict[str, list[str]]:
    """Parse Content-Security-Policy into {directive: [sources]} so tests can assert exact source lists."""
    out = {}
    for part in resp.headers["content-security-policy"].split(";"):
        name, *sources = part.split()
        out[name] = sources
    return out


def nonce_of(sources: list[str]) -> str:
    """Given a directive's source list that must be exactly one nonce, return the nonce value."""
    assert len(sources) == 1 and sources[0].startswith("'nonce-") and sources[0].endswith("'"), sources
    return sources[0][len("'nonce-"):-1]


# ---- metadata
def test_metadata_advertises_facade_issuer_and_cognito_jwks():
    app, *_ = make()
    for path in ("/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"):
        r = get(app, path)
        assert r.status == 200 and r.headers["cache-control"] == "public, max-age=300"
        md = json.loads(r.body)
        assert md["issuer"] == BASE and md["authorization_endpoint"] == f"{BASE}/authorize"
        assert md["token_endpoint"] == f"{BASE}/token" and md["revocation_endpoint"] == f"{BASE}/revoke"
        assert md["jwks_uri"] == f"{ISS}/.well-known/jwks.json"  # tokens are Cognito's; the AS URL is ours
        assert md["client_id_metadata_document_supported"] is True and md["resource_indicators_supported"] is True
        assert md["code_challenge_methods_supported"] == ["S256"] and md["token_endpoint_auth_methods_supported"] == ["none"]
        assert md["scopes_supported"] == [SCOPE]  # openid is accepted if asked for, never advertised
        # not an OpenID Provider configuration: ID tokens carry the Cognito issuer, so no OIDC members on either path
        assert not {"subject_types_supported", "id_token_signing_alg_values_supported", "userinfo_endpoint"} & md.keys()
        assert md["issuer"] != ISS
    assert get(app, "/nope").status == 404


# ---- /authorize: non-redirectable failures (client_id / redirect_uri) render an error page, never a redirect
@pytest.mark.parametrize("over,needle", [
    ({"client_id": None}, "client_id is required"),
    ({"client_id": "http://client.example/x"}, "scheme must be https"),
    ({"client_id": "https://client.example/x?y=1"}, "query"),
    ({"client_id": "https://unknown.example/cimd.json"}, "invalid_client"),
    ({"redirect_uri": "https://evil.example/cb"}, "not one of the client"),
    ({"redirect_uri": None}, "redirect_uri is required"),  # two URIs registered → required
])
def test_authorize_rejects_without_redirect(over, needle):
    app, *_ = make()
    r = get(app, "/authorize", **authz(**over))
    assert r.status == 400 and "location" not in r.headers and r.headers["content-type"].startswith("text/html")
    assert csp_directives(r) == {"default-src": ["'none'"], "frame-ancestors": ["'none'"]}
    assert needle in r.body


def test_authorize_disabled_client_is_invalid_client_without_redirect():
    app, *_ = make({CID: mapping(enabled=False)})
    r = get(app, "/authorize", **authz())
    assert r.status == 400 and "invalid_client" in r.body and "location" not in r.headers


def test_authorize_single_registered_uri_may_be_omitted():
    app, *_ = make({CID: mapping(redirect_uris=(CB,))}, consent_on=False)
    r = get(app, "/authorize", **authz(redirect_uri=None))
    assert r.status == 302 and location_params(r)[1]["redirect_uri"] == CB


# ---- /authorize: redirectable failures go back to the validated redirect_uri with state
@pytest.mark.parametrize("over,error", [
    ({"response_type": "token"}, "unsupported_response_type"),
    ({"code_challenge": None}, "invalid_request"),
    ({"code_challenge": "short"}, "invalid_request"),
    ({"code_challenge_method": "plain"}, "invalid_request"),
    ({"code_challenge_method": None}, "invalid_request"),
    ({"resource": "https://other.example/mcp"}, "invalid_target"),
    ({"scope": f"{SCOPE} admin"}, "invalid_scope"),
])
def test_authorize_redirects_errors_to_client(over, error):
    app, *_ = make()
    r = get(app, "/authorize", **authz(**over))
    assert r.status == 302
    target, q = location_params(r)
    assert target == CB and q["error"] == error and q["state"] == "xyz" and q["error_description"]


def test_authorize_error_redirect_preserves_existing_query():
    assert add_query("https://c.example/cb?a=1", {"error": "x", "state": None}) == "https://c.example/cb?a=1&error=x"


# ---- happy paths
def test_authorize_without_interstitial_redirects_to_cognito_with_shadow_client_and_clients_params():
    app, *_ = make(consent_on=False)
    r = get(app, "/authorize", **authz())
    assert r.status == 302
    target, q = location_params(r)
    assert target == f"{LOGIN}/oauth2/authorize"
    assert q == {"response_type": "code", "client_id": "shadow1", "redirect_uri": CB, "scope": SCOPE, "state": "xyz",
                 "code_challenge": authz()["code_challenge"], "code_challenge_method": "S256", "resource": RES}


def test_authorize_defaults_missing_scope_and_resource():
    app, *_ = make(consent_on=False)
    r = get(app, "/authorize", **authz(scope=None, resource=None, state=None))
    _, q = location_params(r)
    assert q["scope"] == SCOPE and q["resource"] == RES and "state" not in q


def test_authorize_openid_scope_is_forwarded():
    app, *_ = make(consent_on=False)
    _, q = location_params(get(app, "/authorize", **authz(scope=f"openid {SCOPE}")))
    assert q["scope"] == f"openid {SCOPE}"


# ---- consent interstitial and CSRF
def test_consent_page_then_approve_redirects_to_cognito_and_clears_cookie():
    app, *_ = make()
    r = get(app, "/authorize", **authz())
    assert r.status == 200 and "Example client" in r.body and "client.example" in r.body and SCOPE in r.body
    # Chromium enforces form-action on the post-POST redirect: Cognito and the client's redirect origin must be allowed
    csp = csp_directives(r)
    assert csp["form-action"] == ["'self'", LOGIN, "https://client.example"]
    # the only permitted stylesheet is the page's own nonced <style> element
    assert csp["default-src"] == ["'none'"] and f'<style nonce="{nonce_of(csp["style-src"])}">' in r.body
    cookie = r.cookies[0]
    assert cookie.startswith(consent.COOKIE + "=") and "HttpOnly" in cookie and "SameSite=Strict" in cookie and "Secure" in cookie
    token = cookie.split(";")[0].split("=", 1)[1]
    assert re.search(r'name="csrf" value="([^"]+)"', r.body).group(1) == token
    fields = dict(re.findall(r'name="([a-z_]+)" value="([^"]*)"', r.body))
    r2 = post(app, "/consent", {**fields, "decision": "approve"}, cookies={consent.COOKIE: token})
    assert r2.status == 302 and location_params(r2)[0] == f"{LOGIN}/oauth2/authorize" and location_params(r2)[1]["client_id"] == "shadow1"
    assert any("Max-Age=0" in c for c in r2.cookies)


def test_consent_deny_returns_access_denied_to_client():
    app, *_ = make()
    r = post(app, "/consent", {**authz(), "csrf": "t", "decision": "deny"}, cookies={consent.COOKIE: "t"})
    _, q = location_params(r)
    assert r.status == 302 and q["error"] == "access_denied" and q["state"] == "xyz"


@pytest.mark.parametrize("cookies,field", [({}, "t"), ({consent.COOKIE: "a"}, "b"), ({consent.COOKIE: "t"}, None)])
def test_consent_csrf_mismatch_is_rejected_before_any_revalidation(cookies, field):
    # stale mapping: a successful validation would call the registrar; a forged POST must not get that far
    app, store, relay, calls, clock = make({CID: mapping(cache_until=NOW - 1)}, revalidate={"fresh": True, "enabled": True})
    form = {**authz(), "decision": "approve"}
    if field is not None:
        form["csrf"] = field
    r = post(app, "/consent", form, cookies=cookies)
    assert r.status == 400 and "location" not in r.headers and "could not be verified" in r.body
    assert calls == []


def test_consent_tampered_redirect_uri_is_rejected():
    app, *_ = make()
    r = post(app, "/consent", {**authz(redirect_uri="https://evil.example/cb"), "csrf": "t", "decision": "approve"},
             cookies={consent.COOKIE: "t"})
    assert r.status == 400 and "location" not in r.headers


def test_consent_requires_form_content_type():
    app, *_ = make()
    r = app.handle(Request("POST", "/consent", {}, {"content-type": "application/json"}, {}, "{}"))
    assert r.status == 400 and "x-www-form-urlencoded" in r.body


# ---- authorization-time freshness contract
def test_fresh_mapping_does_not_call_registrar():
    app, store, relay, calls, clock = make(consent_on=False)
    assert get(app, "/authorize", **authz()).status == 302 and calls == []


def test_stale_mapping_revalidated_and_authorizes_when_fresh():
    rows = {CID: mapping(cache_until=NOW - 1)}
    app, store, relay, calls, clock = make(rows, revalidate={"status": "ok", "fresh": True, "enabled": True}, consent_on=False)
    r = get(app, "/authorize", **authz())
    assert r.status == 302 and location_params(r)[0].startswith(LOGIN) and calls == [CID]
    assert store.reads == 2  # re-read after revalidation: the registrar may have rotated the shadow client


def test_stale_no_cache_document_authorizes_current_request_even_though_cache_until_stays_now():
    # registrar stores cache_until=now for no-cache/no-store; fresh=true still authorizes THIS request
    rows = {CID: mapping(cache_until=NOW)}
    app, store, relay, calls, clock = make(rows, revalidate={"status": "ok", "fresh": True, "enabled": True}, consent_on=False)
    assert get(app, "/authorize", **authz()).status == 302 and calls == [CID]
    assert get(app, "/authorize", **authz()).status == 302 and calls == [CID, CID]  # and revalidates again next time


def test_rotation_during_revalidation_is_picked_up():
    rows = {CID: mapping(cache_until=NOW - 1)}
    def reval(url):
        rows[CID] = mapping(cognito_client_id="shadow2", cache_until=NOW + 300)
        return {"status": "ok", "fresh": True, "enabled": True}
    app, *_ = make(rows, revalidate=reval, consent_on=False)
    assert location_params(get(app, "/authorize", **authz()))[1]["client_id"] == "shadow2"


def test_redirect_uri_removed_during_revalidation_is_not_redirected_to():
    rows = {CID: mapping(cache_until=NOW - 1)}
    def reval(url):
        rows[CID] = mapping(redirect_uris=(CB2,), cache_until=NOW + 300)
        return {"status": "ok", "fresh": True, "enabled": True}
    app, *_ = make(rows, revalidate=reval, consent_on=False)
    r = get(app, "/authorize", **authz(redirect_uri=CB))
    assert r.status == 400 and "location" not in r.headers


@pytest.mark.parametrize("result", [
    {"status": "ok", "fresh": False, "enabled": True},          # JWKS/document could not be revalidated
    {"status": "locked", "fresh": False},                       # registrar busy: transient, says nothing about the client
    {"status": "locked", "fresh": False, "enabled": False},     # legacy shape of the same transient condition
    {"status": "error", "fresh": False},
    {"fresh": True, "enabled": True},                            # no status: not a completed reconciliation
    RuntimeError("timeout"),
    "garbage",
])
def test_stale_mapping_transient_failures_are_temporarily_unavailable_with_retry_after(result):
    rows = {CID: mapping(cache_until=NOW - 1)}
    def reval(url):
        if isinstance(result, Exception):
            raise result
        return result
    app, *_ = make(rows, revalidate=reval, consent_on=False)
    r = get(app, "/authorize", **authz())
    assert r.status == 302 and r.headers["retry-after"] == "10"
    _, q = location_params(r)
    assert q["error"] == "temporarily_unavailable" and q["state"] == "xyz"


def test_stale_mapping_not_allow_listed_is_invalid_client():
    rows = {CID: mapping(cache_until=NOW - 1)}
    app, *_ = make(rows, revalidate={"status": "not_allowed", "fresh": False, "enabled": False}, consent_on=False)
    r = get(app, "/authorize", **authz())
    assert r.status == 400 and "invalid_client" in r.body and "location" not in r.headers


def test_stale_mapping_disabled_by_revalidation_is_invalid_client():
    rows = {CID: mapping(cache_until=NOW - 1)}
    app, *_ = make(rows, revalidate={"status": "ok", "fresh": False, "enabled": False}, consent_on=False)
    r = get(app, "/authorize", **authz())
    assert r.status == 400 and "invalid_client" in r.body


# ---- /token
def test_token_authorization_code_is_mapped_and_relayed():
    app, store, relay, calls, clock = make()
    r = post(app, "/token", {"grant_type": "authorization_code", "client_id": CID, "code": "c", "code_verifier": "v" * 43,
                             "redirect_uri": CB, "resource": RES})
    assert r.status == 200 and json.loads(r.body)["access_token"] == "eyJ.a.b" and r.headers["cache-control"] == "no-store"
    assert relay.calls == [("token", {"grant_type": "authorization_code", "client_id": "shadow1", "code": "c",
                                      "code_verifier": "v" * 43, "redirect_uri": CB, "resource": RES})]


def test_token_refresh_is_relayed_with_shadow_client():
    app, store, relay, *_ = make()
    r = post(app, "/token", {"grant_type": "refresh_token", "client_id": CID, "refresh_token": "rt"})
    assert r.status == 200 and relay.calls[0][1] == {"grant_type": "refresh_token", "client_id": "shadow1", "refresh_token": "rt"}


def test_token_passes_cognito_errors_through():
    app, store, relay, *_ = make(relay=FakeRelay(RelayResult(400, {"error": "invalid_grant"})))
    r = post(app, "/token", {"grant_type": "refresh_token", "client_id": CID, "refresh_token": "rt"})
    assert r.status == 400 and json.loads(r.body) == {"error": "invalid_grant"}


@pytest.mark.parametrize("form,error,status", [
    ({"grant_type": "authorization_code", "client_id": CID, "code": "c", "code_verifier": "v", "redirect_uri": "https://evil.example/cb"}, "invalid_grant", 400),
    ({"grant_type": "authorization_code", "client_id": CID, "code": "c", "redirect_uri": CB}, "invalid_request", 400),
    ({"grant_type": "authorization_code", "client_id": "https://unknown.example/x", "code": "c", "code_verifier": "v", "redirect_uri": CB}, "invalid_client", 400),
    ({"grant_type": "client_credentials", "client_id": CID}, "unsupported_grant_type", 400),
    ({"client_id": CID}, "invalid_request", 400),
    ({"grant_type": "refresh_token", "client_id": CID}, "invalid_request", 400),
    ({"grant_type": "refresh_token", "client_id": CID, "refresh_token": "rt", "resource": "https://other.example/mcp"}, "invalid_target", 400),
])
def test_token_error_shapes(form, error, status):
    app, store, relay, *_ = make()
    r = post(app, "/token", form)
    body = json.loads(r.body)
    assert r.status == status and body["error"] == error and body["error_description"] and relay.calls == []


def test_token_stale_mapping_fails_closed_with_503_and_retry_after():
    rows = {CID: mapping(cache_until=NOW - 1)}
    app, store, relay, *_ = make(rows, revalidate={"fresh": False, "enabled": True})
    r = post(app, "/token", {"grant_type": "refresh_token", "client_id": CID, "refresh_token": "rt"})
    assert r.status == 503 and json.loads(r.body)["error"] == "temporarily_unavailable" and r.headers["retry-after"] == "10"
    assert relay.calls == []


def test_token_disabled_client_refused_immediately():
    app, store, relay, *_ = make({CID: mapping(enabled=False)})
    r = post(app, "/token", {"grant_type": "refresh_token", "client_id": CID, "refresh_token": "rt"})
    assert r.status == 400 and json.loads(r.body)["error"] == "invalid_client" and relay.calls == []


def test_repeated_parameter_is_invalid_request():
    app, *_ = make()
    r = app.handle(Request("POST", "/token", {}, {"content-type": "application/x-www-form-urlencoded"}, {},
                           f"grant_type=refresh_token&grant_type=refresh_token&client_id={CID}&refresh_token=rt"))
    assert r.status == 400 and json.loads(r.body)["error"] == "invalid_request"


# ---- /revoke
def test_revoke_maps_client_and_relays_without_freshness_gate():
    rows = {CID: mapping(cache_until=NOW - 1)}  # stale is fine for revocation
    app, store, relay, calls, clock = make(rows, relay=FakeRelay(RelayResult(200, None)))
    r = post(app, "/revoke", {"token": "rt", "client_id": CID})
    assert r.status == 200 and r.body == "" and relay.calls == [("revoke", {"token": "rt", "client_id": "shadow1"})] and calls == []


def test_revoke_requires_token_and_known_client():
    app, store, relay, *_ = make()
    assert json.loads(post(app, "/revoke", {"client_id": CID}).body)["error"] == "invalid_request"
    assert json.loads(post(app, "/revoke", {"token": "rt", "client_id": "https://unknown.example/x"}).body)["error"] == "invalid_client"
    assert relay.calls == []


# ---- test client (config-gated)
def test_test_client_disabled_by_default():
    app, *_ = make()
    assert get(app, "/test-client/metadata.json").status == 404


def test_test_client_documents():
    from validate import validate_document
    app, *_ = make(test_client=True)
    r = get(app, "/test-client/metadata.json")
    doc = json.loads(r.body)
    assert r.status == 200 and r.headers["content-type"] == "application/json" and "max-age=300" in r.headers["cache-control"]
    assert doc["client_id"] == f"{BASE}/test-client/metadata.json" and doc["redirect_uris"] == [f"{BASE}/test-client/callback"]
    assert validate_document(doc, doc["client_id"]) == []  # the registrar will accept it
    for path in ("/test-client/index.html", "/test-client/callback"):
        page = get(app, path)
        assert page.status == 200 and "text/html" in page.headers["content-type"]
        csp = csp_directives(page)
        nonce = nonce_of(csp["script-src"])
        assert nonce_of(csp["style-src"]) == nonce and csp["default-src"] == ["'none'"]
        assert f'<script nonce="{nonce}">' in page.body and f'<style nonce="{nonce}">' in page.body
        assert f'"clientId": "{doc["client_id"]}"' in page.body
    assert get(app, "/test-client/other").status == 404


# ---- HTTP API v2 event parsing and response shape
def test_request_from_event_parses_cookies_query_and_base64_body():
    event = {"rawPath": "/consent", "rawQueryString": "a=1&b=", "cookies": [f"{consent.COOKIE}=tok", "other=x"],
             "headers": {"Content-Type": "application/x-www-form-urlencoded"},
             "requestContext": {"http": {"method": "POST"}},
             "body": base64.b64encode(b"grant_type=x&client_id=y").decode(), "isBase64Encoded": True}
    req = Request.from_event(event)
    assert req.method == "POST" and req.path == "/consent" and req.query == {"a": "1", "b": ""}
    assert req.cookies == {consent.COOKIE: "tok", "other": "x"} and req.headers["content-type"].startswith("application/x-www")
    assert req.form() == {"grant_type": "x", "client_id": "y"}


def test_lambda_response_shape_includes_security_headers_and_cookies():
    app, *_ = make()
    out = get(app, "/authorize", **authz()).to_lambda()
    assert out["statusCode"] == 200 and out["cookies"] and out["headers"]["x-frame-options"] == "DENY"
    assert out["headers"]["strict-transport-security"].startswith("max-age=")
    assert "cookies" not in get(app, "/.well-known/oauth-authorization-server").to_lambda()


def test_unexpected_exception_is_server_error_not_leaked():
    app, store, *_ = make()
    def boom(url, consistent=False):
        raise KeyError("secret internal detail")
    store.by_cimd_url = boom
    r = post(app, "/token", {"grant_type": "refresh_token", "client_id": CID, "refresh_token": "rt"})
    assert r.status == 500 and json.loads(r.body) == {"error": "server_error", "error_description": "unexpected error"}
    r = get(app, "/authorize", **authz())
    assert r.status == 500 and "secret internal detail" not in r.body


def test_handle_event_turns_parse_errors_into_oauth_errors():
    app, *_ = make()
    out = app.handle_event({"rawPath": "/authorize", "rawQueryString": "client_id=a&client_id=b",
                            "requestContext": {"http": {"method": "GET"}}})
    assert out["statusCode"] == 400 and "must not be repeated" in out["body"] and "text/html" in out["headers"]["content-type"]
    out = app.handle_event({"rawPath": "/token", "rawQueryString": "x=1&x=2", "requestContext": {"http": {"method": "POST"}}})
    assert out["statusCode"] == 400 and json.loads(out["body"])["error"] == "invalid_request"
    ok = app.handle_event({"rawPath": "/.well-known/oauth-authorization-server", "requestContext": {"http": {"method": "GET"}}})
    assert ok["statusCode"] == 200
