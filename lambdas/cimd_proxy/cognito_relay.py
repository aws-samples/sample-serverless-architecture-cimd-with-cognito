"""Forward token and revocation requests to the Cognito Managed Login domain (stdlib only, TLS verified).

The proxy swaps the CIMD client_id for the shadow app client id and passes everything else through unchanged.
Cognito's status code and JSON body are returned to the client as-is (RFC 6749 §5.2 error shapes are Cognito's).
"""
from __future__ import annotations

import http.client
import json
import ssl
from dataclasses import dataclass
from urllib.parse import urlencode, urlsplit

from oauth import OAuthError


@dataclass(frozen=True)
class RelayResult:
    status: int
    body: dict | None  # None for an empty body (revocation success)


class CognitoRelay:
    def __init__(self, login_base_url: str, timeout_seconds: float, retry_after_seconds: int):
        u = urlsplit(login_base_url)
        if u.scheme != "https" or not u.hostname:
            raise ValueError("Cognito login base URL must be https")
        self.host, self.port, self.base_path = u.hostname, u.port or 443, u.path.rstrip("/")
        self.timeout, self.retry_after = timeout_seconds, retry_after_seconds
        self._ctx = ssl.create_default_context()

    def token(self, form: dict[str, str]) -> RelayResult:
        return self._post("/oauth2/token", form)

    def revoke(self, form: dict[str, str]) -> RelayResult:
        return self._post("/oauth2/revoke", form)

    def _post(self, path: str, form: dict[str, str]) -> RelayResult:
        body = urlencode(form)
        conn = http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout, context=self._ctx)
        try:
            conn.request("POST", f"{self.base_path}{path}", body=body,
                         headers={"content-type": "application/x-www-form-urlencoded", "accept": "application/json",
                                  "content-length": str(len(body))})
            resp = conn.getresponse()
            raw = resp.read()
        except (OSError, http.client.HTTPException) as e:
            raise OAuthError("temporarily_unavailable", f"token issuer unreachable: {type(e).__name__}", status=503,
                             retry_after=self.retry_after) from e
        finally:
            conn.close()
        if not raw.strip():
            return RelayResult(resp.status, None)
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as e:
            raise OAuthError("server_error", "token issuer returned a non-JSON response", status=502) from e
        return RelayResult(resp.status, parsed if isinstance(parsed, dict) else {"error": "server_error"})
