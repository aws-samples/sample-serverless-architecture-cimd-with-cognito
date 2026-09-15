"""OAuth 2.1 / CIMD request parsing, validation, and error shaping for the proxy.

Pure functions: no AWS calls. The proxy is translation only; Cognito remains the authority for PKCE verification,
exact redirect_uri matching, and token issuance. Everything here is a pre-check that produces RFC 6749 error shapes.
"""
from __future__ import annotations

import base64
import html
import json
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from shared.cimd_url import validate_client_id_url

_CODE_CHALLENGE_RE = re.compile(r"^[A-Za-z0-9._~-]{43,128}$")
AUTHORIZE_FIELDS = ("response_type", "client_id", "redirect_uri", "scope", "state", "code_challenge",
                    "code_challenge_method", "resource")
NO_STORE = {"cache-control": "no-store", "pragma": "no-cache"}
SECURITY_HEADERS = {
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "x-frame-options": "DENY",
}


class OAuthError(Exception):
    """RFC 6749 error. `redirectable` says whether /authorize may deliver it to the client's redirect_uri
    (only after client_id AND redirect_uri have been validated, §4.1.2.1)."""

    def __init__(self, error: str, description: str, *, status: int = 400, redirectable: bool = False,
                 retry_after: int | None = None):
        super().__init__(f"{error}: {description}")
        self.error, self.description, self.status = error, description, status
        self.redirectable, self.retry_after = redirectable, retry_after


@dataclass(frozen=True)
class Request:
    method: str
    path: str
    query: dict[str, str]
    headers: dict[str, str]  # lower-cased names
    cookies: dict[str, str]
    body: str

    @classmethod
    def from_event(cls, event: dict) -> Request:
        """HTTP API payload format 2.0."""
        body = event.get("body") or ""
        if event.get("isBase64Encoded"):
            body = base64.b64decode(body).decode("utf-8", "replace")
        cookies: dict[str, str] = {}
        for c in event.get("cookies") or []:
            k, _, v = c.partition("=")
            cookies[k.strip()] = v
        return cls(
            method=event.get("requestContext", {}).get("http", {}).get("method", "GET").upper(),
            path=event.get("rawPath", "/"),
            query=single_valued(parse_qsl(event.get("rawQueryString") or "", keep_blank_values=True)),
            headers={k.lower(): v for k, v in (event.get("headers") or {}).items()},
            cookies=cookies,
            body=body,
        )

    def form(self) -> dict[str, str]:
        ctype = self.headers.get("content-type", "").split(";")[0].strip().lower()
        if ctype != "application/x-www-form-urlencoded":
            raise OAuthError("invalid_request", "content-type must be application/x-www-form-urlencoded")
        return single_valued(parse_qsl(self.body, keep_blank_values=True))


@dataclass
class Response:
    status: int
    body: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    cookies: list[str] = field(default_factory=list)

    def to_lambda(self) -> dict:
        out = {"statusCode": self.status, "headers": {**SECURITY_HEADERS, **self.headers}, "body": self.body}
        if self.cookies:
            out["cookies"] = self.cookies
        return out


def single_valued(pairs: list[tuple[str, str]]) -> dict[str, str]:
    """RFC 6749 §3.1/§3.2: parameters MUST NOT be included more than once."""
    out: dict[str, str] = {}
    for k, v in pairs:
        if k in out:
            raise OAuthError("invalid_request", f"parameter {k!r} must not be repeated")
        out[k] = v
    return out


# ---- responses
def json_response(status: int, payload: dict, extra_headers: dict[str, str] | None = None) -> Response:
    return Response(status, json.dumps(payload), {"content-type": "application/json", **NO_STORE, **(extra_headers or {})})


def error_json(err: OAuthError) -> Response:
    headers = {"retry-after": str(err.retry_after)} if err.retry_after is not None else {}
    return json_response(err.status, {"error": err.error, "error_description": err.description}, headers)


def error_page(err: OAuthError) -> Response:
    """Browser-facing error for /authorize and /consent when redirecting is not allowed (bad client_id/redirect_uri/CSRF)."""
    body = ("<!doctype html><html><head><meta charset='utf-8'><title>Authorization error</title></head><body>"
            f"<h1>Authorization request rejected</h1><p><code>{html.escape(err.error)}</code>: "
            f"{html.escape(err.description)}</p></body></html>")
    headers = {"content-type": "text/html; charset=utf-8", **NO_STORE,
               "content-security-policy": "default-src 'none'; frame-ancestors 'none'"}
    if err.retry_after is not None:
        headers["retry-after"] = str(err.retry_after)
    return Response(err.status, body, headers)


def redirect(location: str, cookies: list[str] | None = None) -> Response:
    return Response(302, "", {"location": location, **NO_STORE}, cookies or [])


def add_query(url: str, params: dict[str, str | None]) -> str:
    """Append parameters to a redirect_uri that may already carry a query string (RFC 6749 §4.1.2)."""
    parts = urlsplit(url)
    existing = parse_qsl(parts.query, keep_blank_values=True)
    merged = existing + [(k, v) for k, v in params.items() if v is not None]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(merged), parts.fragment))


def error_redirect(redirect_uri: str, err: OAuthError, state: str | None) -> Response:
    r = redirect(add_query(redirect_uri, {"error": err.error, "error_description": err.description, "state": state}))
    if err.retry_after is not None:
        r.headers["retry-after"] = str(err.retry_after)
    return r


# ---- /authorize parameter validation
@dataclass(frozen=True)
class AuthorizeParams:
    client_id: str
    redirect_uri: str
    scope: str
    state: str | None
    code_challenge: str
    resource: str

    def as_form_fields(self) -> dict[str, str]:
        fields = {"response_type": "code", "client_id": self.client_id, "redirect_uri": self.redirect_uri,
                  "scope": self.scope, "code_challenge": self.code_challenge, "code_challenge_method": "S256",
                  "resource": self.resource}
        if self.state is not None:
            fields["state"] = self.state
        return fields


def validate_client_id(params: dict[str, str]) -> str:
    client_id = params.get("client_id", "")
    if not client_id:
        raise OAuthError("invalid_request", "client_id is required")
    problem = validate_client_id_url(client_id)
    if problem:
        raise OAuthError("invalid_request", f"client_id must be a CIMD client identifier URL: {problem}")
    return client_id


def resolve_redirect_uri(params: dict[str, str], registered: tuple[str, ...]) -> str:
    """RFC 6749 §3.1.2.3: required when several URIs are registered; exact string comparison against the document."""
    given = params.get("redirect_uri")
    if not given:
        if len(registered) == 1:
            return registered[0]
        raise OAuthError("invalid_request", "redirect_uri is required")
    if given not in registered:
        raise OAuthError("invalid_request", "redirect_uri is not one of the client's registered redirect_uris")
    return given


def validate_authorize(params: dict[str, str], *, client_id: str, redirect_uri: str, resource_url: str,
                       invoke_scope: str) -> AuthorizeParams:
    """Everything after client_id/redirect_uri; errors raised here are redirectable (§4.1.2.1)."""
    def fail(error: str, description: str) -> OAuthError:
        return OAuthError(error, description, redirectable=True)

    if params.get("response_type") != "code":
        raise fail("unsupported_response_type", "response_type must be 'code'")
    challenge = params.get("code_challenge", "")
    if not challenge:
        raise fail("invalid_request", "code_challenge is required (PKCE)")
    if not _CODE_CHALLENGE_RE.match(challenge):
        raise fail("invalid_request", "code_challenge is malformed")
    if params.get("code_challenge_method") != "S256":
        raise fail("invalid_request", "code_challenge_method must be 'S256'")
    resource = params.get("resource") or resource_url  # RFC 8707; absent → the one resource this AS fronts
    if resource != resource_url:
        raise fail("invalid_target", "resource must be the MCP server URL advertised in its protected resource metadata")
    scopes = [s for s in params.get("scope", "").split(" ") if s]
    allowed = {"openid", invoke_scope}
    unknown = [s for s in scopes if s not in allowed]
    if unknown:
        raise fail("invalid_scope", f"unsupported scope(s): {' '.join(unknown)}")
    if not scopes:
        scopes = [invoke_scope]
    state = params.get("state")
    return AuthorizeParams(client_id=client_id, redirect_uri=redirect_uri, scope=" ".join(scopes),
                           state=state if state else None, code_challenge=challenge, resource=resource)


def cognito_authorize_url(login_base_url: str, shadow_client_id: str, p: AuthorizeParams) -> str:
    """Only ever redirects to the configured Cognito login domain (no open redirect)."""
    q = {"response_type": "code", "client_id": shadow_client_id, "redirect_uri": p.redirect_uri, "scope": p.scope,
         "code_challenge": p.code_challenge, "code_challenge_method": "S256", "resource": p.resource}
    if p.state is not None:
        q["state"] = p.state
    return f"{login_base_url.rstrip('/')}/oauth2/authorize?{urlencode(q)}"


# ---- RFC 8414 metadata
def authorization_server_metadata(authorization_server_url: str, token_issuer: str, invoke_scope: str) -> dict:
    """RFC 8414 document. Served unchanged at /.well-known/openid-configuration too, purely as an MCP discovery fallback
    (clients probe that path): it is NOT an OpenID Provider configuration. ID tokens, when a client asks for `openid`,
    are Cognito's and carry the Cognito issuer, so no OIDC members (subject types, id_token algs) and no `openid` scope
    are advertised here. This is a deliberate, documented exception to OIDC Discovery's issuer-consistency rule."""
    base = authorization_server_url.rstrip("/")
    return {
        "issuer": base,
        "authorization_endpoint": f"{base}/authorize",
        "token_endpoint": f"{base}/token",
        "revocation_endpoint": f"{base}/revoke",
        "jwks_uri": f"{token_issuer.rstrip('/')}/.well-known/jwks.json",
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "revocation_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": [invoke_scope],
        "client_id_metadata_document_supported": True,
        "resource_indicators_supported": True,
    }
