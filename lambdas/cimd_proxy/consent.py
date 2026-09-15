"""Consent interstitial: shows who is asking for what, then re-posts every OAuth parameter.

CSRF: double-submit cookie. A random token is set as a `__Host-` cookie (Secure, HttpOnly, SameSite=Strict, Path=/)
and embedded in the form; POST /consent requires both to match. No signing key, so "no secrets" still holds.
Every parameter is fully re-validated on POST; the form is a carrier, not a source of trust.
"""
from __future__ import annotations

import hmac
import html
import secrets
from urllib.parse import urlsplit

from oauth import NO_STORE, AuthorizeParams, OAuthError, Response

COOKIE = "__Host-cimd_consent"


def _origin(url: str) -> str:
    u = urlsplit(url)
    return f"{u.scheme}://{u.netloc}"


def _csp(p: AuthorizeParams, login_base_url: str, nonce: str) -> str:
    """Chromium applies form-action to the redirect that follows the POST, so the two legitimate destinations of
    /consent (the Cognito login domain on approve, the client's redirect_uri on deny) must be listed explicitly.
    style-src permits only the page's own nonced <style> element."""
    return (f"default-src 'none'; style-src 'nonce-{nonce}'; frame-ancestors 'none'; "
            f"form-action 'self' {_origin(login_base_url)} {_origin(p.redirect_uri)}")

_PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Authorize {client_name}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style nonce="{nonce}">
body{{font-family:system-ui,sans-serif;max-width:36rem;margin:3rem auto;padding:0 1rem;color:#1a1a1a}}
dl{{display:grid;grid-template-columns:max-content 1fr;gap:.4rem 1rem}}dt{{font-weight:600}}dd{{margin:0;word-break:break-all}}
code{{background:#f2f2f2;padding:.1rem .3rem;border-radius:3px}}
.actions{{display:flex;gap:1rem;margin-top:2rem}}button{{font:inherit;padding:.6rem 1.4rem;border-radius:6px;border:1px solid #888;cursor:pointer}}
.approve{{background:#1d4ed8;color:#fff;border-color:#1d4ed8}}
</style></head><body>
<h1>Allow <strong>{client_name}</strong> to access your MCP server?</h1>
<p>The application identified by <code>{client_host}</code> is asking to act on your behalf.</p>
<dl>
<dt>Client</dt><dd>{client_name}<br><small>{client_id}</small></dd>
<dt>Resource</dt><dd>{resource}</dd>
<dt>Permissions</dt><dd>{scopes}</dd>
<dt>Return to</dt><dd>{redirect_host}</dd>
</dl>
<p>After you approve, you will sign in with your account. Only the application's registered return address
can receive the result.</p>
<form method="post" action="/consent">
{hidden}
<input type="hidden" name="csrf" value="{csrf}">
<div class="actions">
<button class="approve" type="submit" name="decision" value="approve">Approve and sign in</button>
<button type="submit" name="decision" value="deny">Deny</button>
</div></form></body></html>"""


def issue_cookie(token: str, max_age: int) -> str:
    return f"{COOKIE}={token}; Path=/; Max-Age={max_age}; Secure; HttpOnly; SameSite=Strict"


def clear_cookie() -> str:
    return f"{COOKIE}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict"


def render(p: AuthorizeParams, client_name: str, cookie_max_age: int, login_base_url: str,
           token: str | None = None) -> Response:
    token = token or secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(16)
    hidden = "\n".join(f'<input type="hidden" name="{html.escape(k)}" value="{html.escape(v, quote=True)}">'
                       for k, v in p.as_form_fields().items())
    body = _PAGE.format(
        client_name=html.escape(client_name or urlsplit(p.client_id).hostname or p.client_id),
        client_host=html.escape(urlsplit(p.client_id).hostname or ""),
        client_id=html.escape(p.client_id),
        resource=html.escape(p.resource),
        scopes=", ".join(f"<code>{html.escape(s)}</code>" for s in p.scope.split(" ")),
        redirect_host=html.escape(urlsplit(p.redirect_uri).hostname or p.redirect_uri),
        hidden=hidden, csrf=html.escape(token, quote=True), nonce=nonce,
    )
    return Response(200, body, {"content-type": "text/html; charset=utf-8",
                                "content-security-policy": _csp(p, login_base_url, nonce), **NO_STORE},
                    [issue_cookie(token, cookie_max_age)])


def check_csrf(cookies: dict[str, str], form: dict[str, str]) -> None:
    cookie, field = cookies.get(COOKIE, ""), form.get("csrf", "")
    if not cookie or not field or not hmac.compare_digest(cookie.encode(), field.encode()):
        raise OAuthError("invalid_request", "consent form could not be verified (expired or cross-site submission); "
                                            "restart the authorization from the client")
