"""Client Identifier URL rules (draft-ietf-oauth-client-id-metadata-document-02 §3). Mirrors lib/derive.ts.

The two implementations must agree on every input, because the TypeScript one gates `cdk synth` and the Python
one gates the registrar at runtime: a URL that one accepts and the other rejects is either a deployment that
cannot register its own allow-list or a runtime that trusts something synth refused.
tests/unit/test_cimd_url.py and tests/cdk/config.test.ts share one table of cases to hold that line.
"""
from __future__ import annotations

import re
from urllib.parse import unquote, urlsplit

#: Anything below 0x21 (including space, tab, newline and NUL) or DEL. Never legitimate unencoded in a URL, and
#: a classic way to make two parsers disagree about where a component ends.
CONTROL_OR_SPACE = re.compile(r"[\x00-\x20\x7f]")
#: A '%' that does not begin a complete two-hex-digit escape.
MALFORMED_PERCENT = re.compile(r"%(?![0-9A-Fa-f]{2})")
_AUTHORITY = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://[^/?#]*")
_MAX_DECODES = 4

#: The authority must already be ASCII: letters, digits, hyphen, dot, plus colon and brackets for a port or an
#: IPv6 literal. Checked against the RAW text, not a parsed host, because that is where the two implementations
#: diverge: WHATWG percent-decodes the host and applies UTS-46 mapping, so `x.local%68ost` and a fullwidth-Latin
#: `example.com` arrive there as `x.localhost` and `example.com`, while `urlsplit` keeps them verbatim. Left
#: unchecked, synth would validate one host and the registrar would fetch another. Punycode (`xn--...`) is LDH
#: and still accepted.
HOST_SYNTAX = re.compile(r"^[A-Za-z0-9.:\[\]-]+$")


def raw_path(value: str) -> str:
    """The path text exactly as written, before any parser normalises dot segments away. Mirrors rawPath()."""
    return re.split(r"[?#]", _AUTHORITY.sub("", value), maxsplit=1)[0]


def segment_error(seg: str) -> str | None:
    """Reject dot segments and encoded separators under any amount of percent-decoding. Mirrors segmentError().

    Decoding repeatedly (bounded) rejects `%252e%252e`, which decodes to `%2e%2e` and then to `..`, and
    `%252F`, which decodes to `/`: a proxy or CDN that decodes once before forwarding would otherwise turn a
    URL this accepted into a real traversal. Malformed percent-escapes are refused rather than guessed, which
    is also what `decodeURIComponent` does in the TypeScript mirror -- hence `errors="strict"`, since
    `unquote` is otherwise lenient and the two would diverge on inputs like `%25FF` and `%25C0%25AE`.
    """
    for _ in range(_MAX_DECODES):
        if seg in (".", ".."):
            return "must not contain dot segments"
        if "/" in seg or "\\" in seg:
            return "must not contain encoded path separators"
        if MALFORMED_PERCENT.search(seg):
            return "must not contain a malformed percent-escape"
        try:
            decoded = unquote(seg, errors="strict")
        except UnicodeDecodeError:
            return "must not contain a malformed percent-escape"
        if decoded == seg:
            return None
        seg = decoded
    return "must not be percent-encoded this deeply"


def validate_client_id_url(value: str) -> str | None:
    """Return an error message, or None when the URL is an acceptable CIMD client_id."""
    if CONTROL_OR_SPACE.search(value):
        return "must not contain control characters or spaces"
    # WHATWG (every browser, and lib/derive.ts) treats a backslash in the authority as a '/' terminator, so
    # `https://127.0.0.1\evil.example/x` has the host 127.0.0.1 there while urlsplit reports the whole
    # `127.0.0.1\evil.example` as the hostname. Rejecting it keeps the two implementations in agreement.
    if "\\" in value:
        return "must not contain a backslash"
    try:
        u = urlsplit(value)
    except ValueError:
        return "not a valid URL"
    if u.scheme != "https":
        return "scheme must be https"
    if u.username is not None or u.password is not None or "@" in (u.netloc or ""):
        return "must not contain userinfo"
    if not u.hostname:
        return "must contain a host"
    if not HOST_SYNTAX.match(u.netloc or ""):
        return "host must be ASCII (letters, digits, hyphen, dot; use punycode for internationalised names)"
    if not u.path or u.path == "/":
        return "must contain a path component"
    for seg in raw_path(value).split("/"):
        problem = segment_error(seg)
        if problem:
            return problem
    try:
        _ = u.port  # raises ValueError for a non-numeric or out-of-range port
    except ValueError:
        return "invalid port"
    if u.query:
        return "must not contain a query component"
    if u.fragment:
        return "must not contain a fragment"
    return None
