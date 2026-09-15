"""Built-in CIMD test client (config-gated: testClient.enabled, off by default).

Three same-origin documents under /test-client/:
  <testClient.path>   the CIMD document (client_id = its own URL) that the registrar fetches and registers
  index.html          a page that generates PKCE and starts /authorize
  callback            the registered redirect_uri; exchanges the code at /token and calls the MCP tool
Same origin means no CORS and no localhost redirect (the registrar accepts https redirect_uris only). The page never
displays raw tokens, only decoded claims.
"""
from __future__ import annotations

import json
import secrets

from oauth import NO_STORE, Response, json_response

CALLBACK_PATH = "/test-client/callback"
INDEX_PATH = "/test-client/index.html"


def cimd_document(public_base_url: str, path: str, client_name: str, cache_seconds: int) -> Response:
    base = public_base_url.rstrip("/")
    doc = {
        "client_id": f"{base}{path}",
        "client_name": client_name,
        "client_uri": f"{base}{INDEX_PATH}",
        "redirect_uris": [f"{base}{CALLBACK_PATH}"],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    }
    r = json_response(200, doc)
    r.headers["cache-control"] = f"public, max-age={cache_seconds}"
    r.headers.pop("pragma", None)
    return r


def page(public_base_url: str, path: str, resource_url: str, invoke_scope: str) -> Response:
    base = public_base_url.rstrip("/")
    cfg = {"clientId": f"{base}{path}", "redirectUri": f"{base}{CALLBACK_PATH}", "resource": resource_url,
           "scope": invoke_scope, "authorize": f"{base}/authorize", "token": f"{base}/token", "revoke": f"{base}/revoke",
           "index": f"{base}{INDEX_PATH}"}
    nonce = secrets.token_urlsafe(16)
    # Inside a <script> element entities are NOT decoded, so JSON-escape '<' instead of HTML-escaping.
    body = _PAGE.replace("__CFG__", json.dumps(cfg).replace("<", "\\u003c")).replace("__NONCE__", nonce)
    csp = (f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; connect-src 'self'; "
           "form-action 'none'; frame-ancestors 'none'")
    return Response(200, body, {"content-type": "text/html; charset=utf-8", "content-security-policy": csp, **NO_STORE})


_PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>CIMD test client</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style nonce="__NONCE__">
body{font-family:system-ui,sans-serif;max-width:48rem;margin:2rem auto;padding:0 1rem;color:#1a1a1a}
pre{background:#f6f6f6;padding:.8rem;border-radius:6px;overflow:auto;font-size:.85rem;white-space:pre-wrap;word-break:break-all}
button{font:inherit;padding:.5rem 1.2rem;border-radius:6px;border:1px solid #888;cursor:pointer;margin:.2rem}
.ok{color:#15803d}.err{color:#b91c1c}small{color:#555}
</style></head><body>
<h1>CIMD test client</h1>
<p><small>This page is a public OAuth client whose <code>client_id</code> is the URL of a Client ID Metadata Document
served by this same host. It performs authorization code + PKCE through the CIMD proxy, receives Cognito-issued
tokens, and calls the MCP server. Raw tokens are never displayed.</small></p>
<div id="controls"></div>
<div id="log"></div>
<script type="application/json" id="cfg">__CFG__</script>
<script nonce="__NONCE__">
(() => {
  const cfg = JSON.parse(document.getElementById('cfg').textContent);
  const log = document.getElementById('log'), controls = document.getElementById('controls');
  const say = (title, obj, cls) => { const h = document.createElement('h3'); h.textContent = title; if (cls) h.className = cls;
    const p = document.createElement('pre'); p.textContent = typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2);
    log.append(h, p); };
  const button = (label, fn) => { const b = document.createElement('button'); b.textContent = label; b.onclick = fn; controls.append(b); return b; };
  const b64url = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
  const rand = (n) => b64url(crypto.getRandomValues(new Uint8Array(n)));
  const claims = (jwt) => { try { return JSON.parse(atob(jwt.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'))); } catch { return null; } };
  const form = (o) => new URLSearchParams(o).toString();
  const summarize = (t) => ({ error: t.error, error_description: t.error_description, token_type: t.token_type, expires_in: t.expires_in, scope: t.scope,
    access_token: t.access_token ? { claims: claims(t.access_token) } : undefined,
    id_token: t.id_token ? { claims: claims(t.id_token) } : undefined,
    refresh_token: t.refresh_token ? '[present, ' + t.refresh_token.length + ' chars]' : undefined });

  async function post(url, body, headers) {
    const r = await fetch(url, { method: 'POST', headers, body });
    const text = await r.text(); let json = null; try { json = JSON.parse(text); } catch {}
    return { status: r.status, json, text, headers: Object.fromEntries(r.headers.entries()) };
  }
  const tokenPost = (o) => post(cfg.token, form(o), { 'content-type': 'application/x-www-form-urlencoded' });
  const mcp = (token, method, params) => post(cfg.resource, JSON.stringify({ jsonrpc: '2.0', id: 1, method, params: params || {} }),
    { 'content-type': 'application/json', accept: 'application/json, text/event-stream', authorization: 'Bearer ' + token });

  async function start() {
    const verifier = rand(32), state = rand(16);
    const challenge = b64url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)));
    sessionStorage.setItem('cimd_test_client', JSON.stringify({ verifier, state }));
    location.assign(cfg.authorize + '?' + form({ response_type: 'code', client_id: cfg.clientId, redirect_uri: cfg.redirectUri,
      scope: cfg.scope, state, code_challenge: challenge, code_challenge_method: 'S256', resource: cfg.resource }));
  }

  async function callTool(token) {
    const list = await mcp(token, 'tools/list');
    say('POST ' + cfg.resource + ' tools/list → ' + list.status, list.json || list.text, list.status === 200 ? 'ok' : 'err');
    const tool = list.json && list.json.result && list.json.result.tools && list.json.result.tools[0];
    if (!tool) return;
    const call = await mcp(token, 'tools/call', { name: tool.name, arguments: {} });
    say('tools/call ' + tool.name + ' → ' + call.status, call.json || call.text, call.status === 200 ? 'ok' : 'err');
  }

  async function callback() {
    const q = new URLSearchParams(location.search);
    const saved = JSON.parse(sessionStorage.getItem('cimd_test_client') || 'null');
    if (q.get('error')) { say('Authorization error', Object.fromEntries(q.entries()), 'err'); return; }
    if (!saved || q.get('state') !== saved.state) { say('State mismatch', { expected: saved && saved.state, got: q.get('state') }, 'err'); return; }
    say('Authorization response', { code: '[present]', state: q.get('state') }, 'ok');
    const t = await tokenPost({ grant_type: 'authorization_code', client_id: cfg.clientId, code: q.get('code'),
      redirect_uri: cfg.redirectUri, code_verifier: saved.verifier, resource: cfg.resource });
    say('POST /token (authorization_code) → ' + t.status, t.json ? summarize(t.json) : t.text, t.status === 200 ? 'ok' : 'err');
    if (t.status !== 200) return;
    let tokens = t.json;
    history.replaceState(null, '', location.pathname);
    await callTool(tokens.access_token);
    button('Call tool again', () => callTool(tokens.access_token));
    button('Refresh tokens', async () => {
      const r = await tokenPost({ grant_type: 'refresh_token', client_id: cfg.clientId, refresh_token: tokens.refresh_token });
      say('POST /token (refresh_token) → ' + r.status, r.json ? summarize(r.json) : r.text, r.status === 200 ? 'ok' : 'err');
      if (r.status === 200) tokens = { ...tokens, ...r.json };
    });
    button('Revoke refresh token', async () => {
      const r = await post(cfg.revoke, form({ token: tokens.refresh_token, client_id: cfg.clientId }), { 'content-type': 'application/x-www-form-urlencoded' });
      say('POST /revoke → ' + r.status, r.json || r.text || '(empty body)', r.status === 200 ? 'ok' : 'err');
    });
    button('Start over', () => location.assign(cfg.index));
  }

  if (location.pathname.endsWith('/callback')) { callback().catch((e) => say('Unexpected error', String(e), 'err')); }
  else { say('Client', cfg); button('Sign in and authorize', () => start().catch((e) => say('Unexpected error', String(e), 'err'))); }
})();
</script></body></html>"""
