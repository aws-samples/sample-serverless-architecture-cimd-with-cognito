"""CIMD document validation (draft-02 §4, MCP client-registration)."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from urllib.parse import urlsplit

from fetcher import is_routable_unicast
from shared.cimd_url import CONTROL_OR_SPACE

PRIVATE_JWK_MEMBERS = {"d", "p", "q", "dp", "dq", "qi", "k", "oth"}

MAX_REDIRECT_URI_LENGTH = 2048
"""Per-URI cap. Cognito rejects over-long callback URLs anyway; failing here keeps the error on our side of the
control plane and bounds what a document can push into the mapping table and the consent page."""

HOST_SYNTAX = re.compile(r"^[a-z0-9.:-]+$")
"""Hosts must already be in ASCII form: letters, digits, hyphen, dot, and colon for IPv6 literals.

This is deliberately a syntax allow-list rather than an attempt to reproduce browser host normalisation.
`urlsplit` lowercases the host and stops there, while WHATWG percent-decodes it and applies UTS-46 mapping -- so
`foo.local%68ost`, and a fullwidth-Latin spelling of `foo.localhost`, are both `foo.localhost` to a browser but
arbitrary public-looking names to every rule below. Refusing the characters that make the two disagree closes
that whole class without modelling either normaliser. Internationalised names remain expressible in punycode
(`xn--...`), which is LDH and therefore accepted.
"""

LOOPBACK_NAMES = frozenset({"localhost", "ip6-localhost", "ip6-loopback"})
"""Names that resolve to the loopback interface on essentially every host (RFC 6761 §6.3 reserves `localhost`)."""

SPECIAL_USE_SUFFIXES = ("localhost", "local", "localdomain", "internal", "home.arpa", "intranet", "lan", "private")
"""Suffixes that never resolve globally: RFC 6761 special-use names, RFC 8375 `home.arpa`, and the conventional
private-network suffixes. `.example`, `.test` and `.invalid` are deliberately NOT here -- they cannot resolve to
anything either, but they are what documentation and test fixtures use, so refusing them would be noise."""


def redirect_uri_error(r: object) -> str | None:
    """Reject anything that is not an absolute https URL naming a public host.

    Beyond the draft-02 §4 rules this also refuses userinfo (a `https://good.example@evil.example/cb` form that
    reads as the legitimate host to a human on the consent page) and IP-literal hosts that are loopback,
    private, link-local or otherwise not globally routable. Cognito would refuse to *register* most of these,
    but the stored redirect_uris are also what the proxy pre-checks and what the consent page shows.
    """
    if not isinstance(r, str):
        return "must be a string"
    if len(r) > MAX_REDIRECT_URI_LENGTH:
        return f"exceeds {MAX_REDIRECT_URI_LENGTH} characters"
    # Syntax first, because the parsers disagree. WHATWG (every browser) treats a backslash in the authority as
    # a '/' terminator, so `https://127.0.0.1\public.example/cb` has the host 127.0.0.1 in a browser, while
    # urlsplit reports the whole `127.0.0.1\public.example` as the hostname and every host rule below then reads
    # it as an innocuous public name. Control characters and spaces are the same class of parser-disagreement
    # lever. Reject them outright rather than trying to model two parsers.
    if "\\" in r:
        return "must not contain a backslash (browsers read it as a path separator in the authority)"
    if CONTROL_OR_SPACE.search(r):
        return "must not contain control characters or spaces"
    try:
        u = urlsplit(r)
    except ValueError:
        return "is not a valid URL"
    if u.scheme != "https":
        return "must use the https scheme (localhost and custom-scheme clients are out of scope)"
    if not u.hostname:
        return "must contain a host"
    if u.fragment:
        return "must not contain a fragment"
    if u.username is not None or u.password is not None or "@" in (u.netloc or ""):
        return "must not contain userinfo"
    try:
        _ = u.port  # raises for a non-numeric or out-of-range port
    except ValueError:
        return "has an invalid port"
    # urlsplit lowercases the host; strip the IPv6 brackets and any trailing root dot before comparing.
    host = u.hostname.strip("[]").rstrip(".")
    if not HOST_SYNTAX.match(host):
        return ("host must be ASCII letters, digits, hyphen, dot or (for IPv6 literals) colon; percent-escapes and "
                "non-ASCII are refused because browsers normalise them and this validator does not "
                "(use punycode for internationalised names)")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        pass  # not an IP literal: fall through to the name rules
    else:
        return None if is_routable_unicast(ip) else f"names the non-routable address {ip} (RFC 6890)"
    # A name, not an address. Reject the shorthand spellings that `ipaddress` refuses but browsers and
    # inet_aton still resolve to an address (`127.1`, `2130706433`, `0x7f000001`, `0177.0.0.1`): every real DNS
    # name ends in an alphabetic label.
    if not host.rsplit(".", 1)[-1][:1].isalpha():
        return "is not a DNS name and is not a canonical IP literal (shorthand numeric hosts are refused)"
    # Then reject the names that resolve to loopback or to a private network without ever being an IP literal.
    # `localhost` is the point of this check: it is the plainest loopback host there is, and an address-only
    # guard misses it entirely.
    if host in LOOPBACK_NAMES:
        return f"names the loopback host {host!r} (localhost clients are out of scope)"
    if any(host == s or host.endswith("." + s) for s in SPECIAL_USE_SUFFIXES):
        return f"is under the special-use or private-network suffix {host.rsplit('.', 1)[-1]!r}, which never resolves globally"
    if "." not in host:
        return "is a single-label host, which cannot be a globally resolvable DNS name"
    return None  # a DNS name: Cognito enforces the exact string, and the registrar never dereferences it


def validate_document(doc: dict, url: str, *, max_redirect_uris: int = 100) -> list[str]:
    errors: list[str] = []
    if doc.get("client_id") != url:
        errors.append("client_id must equal the document URL (simple string comparison)")
    name = doc.get("client_name")
    if not isinstance(name, str) or not name.strip():
        errors.append("client_name is required")
    uris = doc.get("redirect_uris")
    if not isinstance(uris, list) or not uris:
        errors.append("redirect_uris must be a non-empty list")
    else:
        if len(uris) > max_redirect_uris:
            errors.append(f"more than {max_redirect_uris} redirect_uris")
        for r in uris:
            problem = redirect_uri_error(r)
            if problem:
                errors.append(f"redirect_uri {r!r} {problem}")
    method = doc.get("token_endpoint_auth_method", "none")
    if method != "none":
        errors.append(f"token_endpoint_auth_method {method!r} not supported; only public clients ('none') in this sample")
    if "client_secret" in doc or "client_secret_expires_at" in doc:
        errors.append("client_secret must not appear in a CIMD document")
    jwks = doc.get("jwks")
    if isinstance(jwks, dict):
        for key in jwks.get("keys", []) or []:
            if isinstance(key, dict) and PRIVATE_JWK_MEMBERS & set(key):
                errors.append("jwks contains private key material")
                break
    gt = doc.get("grant_types")
    if gt is not None and (not _str_list(gt) or "authorization_code" not in gt):
        errors.append("grant_types must be a list of strings including authorization_code")
    rt = doc.get("response_types")
    if rt is not None and (not _str_list(rt) or "code" not in rt):
        errors.append("response_types must be a list of strings including code")
    if jwks is not None and (not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list)
                             or not all(isinstance(k, dict) for k in jwks["keys"])):
        errors.append("jwks must be an object with a keys array of objects")
    ju = doc.get("jwks_uri")
    if ju is not None and (not isinstance(ju, str) or not ju.startswith("https://")):
        errors.append("jwks_uri must be an https URL string")
    return errors


def _str_list(v) -> bool:
    return isinstance(v, list) and all(isinstance(x, str) for x in v)


def jwks_fingerprint(doc: dict, jwks_uri_content: dict | None = None) -> str:
    """Stable fingerprint of the client's key material (draft-02 §8.4.1): inline jwks, the jwks_uri string,
    and the CONTENT behind jwks_uri (guardedly fetched by the reconciler) so same-URL key rotations are detected."""
    material = {"jwks": doc.get("jwks"), "jwks_uri": doc.get("jwks_uri"), "jwks_uri_content": jwks_uri_content}
    return hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest()
