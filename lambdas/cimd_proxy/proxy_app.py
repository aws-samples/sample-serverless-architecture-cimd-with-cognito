"""cimd-proxy application: RFC 8414 metadata, /authorize, /consent, /token, /revoke, optional test client.

Dependencies (URL provider, freshness, Cognito relay) are injected so the whole flow is unit-testable without AWS.
The proxy is stateless: the client's state and PKCE values are forwarded unchanged and nothing is persisted.
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

import consent as consent_mod
import test_client
from cognito_relay import CognitoRelay
from freshness import Freshness
from oauth import (
    AuthorizeParams,
    OAuthError,
    Request,
    Response,
    authorization_server_metadata,
    cognito_authorize_url,
    error_json,
    error_page,
    error_redirect,
    json_response,
    redirect,
    resolve_redirect_uri,
    validate_authorize,
    validate_client_id,
)
from shared.logging_setup import get_logger, log
from shared.mapping_store import Mapping
from shared.runtime_config import Urls

logger = get_logger(__name__)


@dataclass(frozen=True)
class Settings:
    token_issuer: str
    login_base_url: str
    show_consent: bool
    consent_cookie_max_age: int
    metadata_cache_seconds: int
    test_client_enabled: bool
    test_client_path: str
    test_client_name: str


class _Redirected(OAuthError):
    """Raised by the /authorize validation helper once client_id and redirect_uri are trusted: carries the RFC 6749
    error redirect that must be returned to the client instead of an error page."""

    def __init__(self, response: Response):
        super().__init__("redirect", "redirect")
        self.response = response


class App:
    def __init__(self, settings: Settings, urls: Callable[[], Urls], freshness: Freshness, relay: CognitoRelay):
        self.s, self.urls, self.fresh, self.relay = settings, urls, freshness, relay

    # ---- dispatch
    def handle_event(self, event: dict) -> dict:
        """Lambda entry: parsing errors (e.g. a repeated query parameter) get the same RFC 6749 treatment as the rest."""
        path = event.get("rawPath", "/")
        try:
            req = Request.from_event(event)
        except OAuthError as e:
            return (error_page(e) if path in ("/authorize", "/consent") else error_json(e)).to_lambda()
        return self.handle(req).to_lambda()

    def handle(self, req: Request) -> Response:
        browser = req.path in ("/authorize", "/consent")
        try:
            return self._route(req)
        except _Redirected as r:
            return r.response
        except OAuthError as e:
            return error_page(e) if browser else error_json(e)
        except Exception:  # never leak internals; RFC 6749 server_error
            logger.exception("unhandled error in %s", req.path)
            e = OAuthError("server_error", "unexpected error", status=500)
            return error_page(e) if browser else error_json(e)

    def _route(self, req: Request) -> Response:
        m, p = req.method, req.path
        if m == "GET" and p in ("/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"):
            return self.metadata()
        if m == "GET" and p == "/authorize":
            return self.authorize(req.query)
        if m == "POST" and p == "/consent":
            return self.consent(req)
        if m == "POST" and p == "/token":
            return self.token(req.form())
        if m == "POST" and p == "/revoke":
            return self.revoke(req.form())
        if m == "GET" and p.startswith("/test-client/") and self.s.test_client_enabled:
            return self.test_client(p)
        raise OAuthError("invalid_request", f"no such endpoint: {m} {p}", status=404)

    # ---- endpoints
    def metadata(self) -> Response:
        u = self.urls()
        r = json_response(200, authorization_server_metadata(u.authorization_server_url, self.s.token_issuer, u.invoke_scope))
        r.headers["cache-control"] = f"public, max-age={self.s.metadata_cache_seconds}"
        r.headers.pop("pragma", None)
        return r

    def authorize(self, params: dict[str, str]) -> Response:
        p, mapping = self._validated_authorize(params)
        if self.s.show_consent:
            return consent_mod.render(p, mapping.client_name, self.s.consent_cookie_max_age, self.s.login_base_url)
        return self._to_cognito(p, mapping)

    def consent(self, req: Request) -> Response:
        form = req.form()
        consent_mod.check_csrf(req.cookies, form)      # first: a cross-site POST must not even trigger a revalidation
        p, mapping = self._validated_authorize(form)  # the form is a carrier; trust nothing in it
        if form.get("decision") != "approve":
            log(logger, logging.INFO, "consent denied", client_id=p.client_id)
            r = error_redirect(p.redirect_uri, OAuthError("access_denied", "the user denied the request"), p.state)
        else:
            r = self._to_cognito(p, mapping)
        r.cookies.append(consent_mod.clear_cookie())
        return r

    def token(self, form: dict[str, str]) -> Response:
        grant = form.get("grant_type", "")
        client_id = validate_client_id(form)
        mapping = self.fresh.fresh_mapping(client_id)
        if grant == "authorization_code":
            for k in ("code", "code_verifier", "redirect_uri"):
                if not form.get(k):
                    raise OAuthError("invalid_request", f"{k} is required")
            if form["redirect_uri"] not in mapping.redirect_uris:
                raise OAuthError("invalid_grant", "redirect_uri is not one of the client's registered redirect_uris")
            upstream = {"grant_type": grant, "client_id": mapping.cognito_client_id, "code": form["code"],
                        "code_verifier": form["code_verifier"], "redirect_uri": form["redirect_uri"]}
        elif grant == "refresh_token":
            if not form.get("refresh_token"):
                raise OAuthError("invalid_request", "refresh_token is required")
            upstream = {"grant_type": grant, "client_id": mapping.cognito_client_id, "refresh_token": form["refresh_token"]}
        elif not grant:
            raise OAuthError("invalid_request", "grant_type is required")
        else:
            raise OAuthError("unsupported_grant_type", f"grant_type {grant!r} is not supported")
        if form.get("resource"):
            u = self.urls()
            if form["resource"] != u.resource_url:
                raise OAuthError("invalid_target", "resource must be the MCP server URL")
            upstream["resource"] = form["resource"]
        result = self.relay.token(upstream)
        log(logger, logging.INFO, "token request relayed", client_id=client_id, grant_type=grant, status=result.status,
            upstream_error=(result.body or {}).get("error"))
        return json_response(result.status, result.body or {})

    def revoke(self, form: dict[str, str]) -> Response:
        if not form.get("token"):
            raise OAuthError("invalid_request", "token is required")
        client_id = validate_client_id(form)
        mapping = self.fresh.enabled_mapping(client_id)  # revocation is safe; no freshness gate
        result = self.relay.revoke({"token": form["token"], "client_id": mapping.cognito_client_id})
        log(logger, logging.INFO, "revocation relayed", client_id=client_id, status=result.status)
        if result.body is None:
            return Response(result.status, "", {"cache-control": "no-store"})
        return json_response(result.status, result.body)

    def test_client(self, path: str) -> Response:
        u = self.urls()
        if path == self.s.test_client_path:
            return test_client.cimd_document(u.public_base_url, path, self.s.test_client_name, self.s.metadata_cache_seconds)
        if path in (test_client.INDEX_PATH, test_client.CALLBACK_PATH):
            return test_client.page(u.public_base_url, self.s.test_client_path, u.resource_url, u.invoke_scope)
        raise OAuthError("invalid_request", "no such test client document", status=404)

    # ---- shared /authorize + /consent validation: RFC 6749 §4.1.2.1 order (client_id and redirect_uri first, never
    #      redirected on failure; everything after that is redirected to the validated redirect_uri with state)
    def _validated_authorize(self, params: dict[str, str]) -> tuple[AuthorizeParams, Mapping]:
        u = self.urls()
        client_id = validate_client_id(params)                  # not redirectable
        mapping = self.fresh.enabled_mapping(client_id)          # not redirectable: unknown/disabled client
        redirect_uri = resolve_redirect_uri(params, mapping.redirect_uris)  # not redirectable
        try:
            p = validate_authorize(params, client_id=client_id, redirect_uri=redirect_uri,
                                   resource_url=u.resource_url, invoke_scope=u.invoke_scope)
            mapping = self.fresh.fresh_mapping(client_id, mapping)  # may raise temporarily_unavailable (redirectable)
        except OAuthError as e:
            if e.redirectable:
                log(logger, logging.WARNING, "authorization request rejected", client_id=client_id, error=e.error,
                    description=e.description)
                raise _Redirected(error_redirect(redirect_uri, e, params.get("state") or None)) from e
            raise
        if p.redirect_uri not in mapping.redirect_uris:
            # the document changed during revalidation: the URI we validated a moment ago is no longer registered
            raise OAuthError("invalid_request", "redirect_uri is not one of the client's registered redirect_uris")
        return p, mapping

    def _to_cognito(self, p: AuthorizeParams, mapping: Mapping) -> Response:
        log(logger, logging.INFO, "redirecting to Cognito", client_id=p.client_id, cognito_client_id=mapping.cognito_client_id,
            redirect_host=urlsplit(p.redirect_uri).hostname, scope=p.scope)
        return redirect(cognito_authorize_url(self.s.login_base_url, mapping.cognito_client_id, p))
