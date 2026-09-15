"""CIMD document validation rules, redirect_uri hardening (https, no userinfo, no non-routable IP literals, length
cap) and the key-material fingerprint that drives shadow-client rotation."""
import pytest
from validate import jwks_fingerprint, validate_document

URL = "https://c.example/m"


def fullwidth(s: str) -> str:
    """ASCII -> fullwidth Latin. Composed, not written literally, so this file carries no ambiguous characters."""
    return "".join(chr(ord(c) - 0x20 + 0xFF00) for c in s)


def doc(**over):
    d = {"client_id": URL, "client_name": "Client", "redirect_uris": ["https://c.example/cb"]}
    d.update(over)
    return d


def test_valid_minimal():
    assert validate_document(doc(), URL) == []


def test_rules():
    assert any("client_id" in e for e in validate_document(doc(client_id="https://other/x"), URL))
    assert any("client_name" in e for e in validate_document(doc(client_name=""), URL))
    assert any("redirect_uris" in e for e in validate_document(doc(redirect_uris=[]), URL))
    assert any("https" in e for e in validate_document(doc(redirect_uris=["http://localhost:1234/cb"]), URL))
    # nosec B106 below: these are not credentials. "client_secret_basic" is an OAuth auth-method name and "x" is a
    # placeholder; both test that the validator REJECTS documents carrying a client secret.
    assert any("token_endpoint_auth_method" in e for e in validate_document(doc(token_endpoint_auth_method="client_secret_basic"), URL))  # nosec B106
    assert any("client_secret" in e for e in validate_document(doc(client_secret="x"), URL))  # nosec B106
    assert any("private key" in e for e in validate_document(doc(jwks={"keys": [{"kty": "RSA", "n": "x", "e": "AQAB", "d": "secret"}]}), URL))
    assert any("authorization_code" in e for e in validate_document(doc(grant_types=["client_credentials"]), URL))
    assert any("response_types" in e for e in validate_document(doc(response_types=["token"]), URL))
    assert any("more than" in e for e in validate_document(doc(redirect_uris=[f"https://c.example/{i}" for i in range(3)]), URL, max_redirect_uris=2))


@pytest.mark.parametrize("uri,fragment_of_error", [
    ("https://c.example/cb", None),
    ("http://c.example/cb", "https"),
    ("https://c.example/cb#x", "fragment"),
    # Reads as the legitimate host to a human scanning the consent page; the real host is evil.example.
    ("https://c.example@evil.example/cb", "userinfo"),
    ("https://user:pw@c.example/cb", "userinfo"),
    ("https://c.example:99999/cb", "invalid port"),
    # IP-literal hosts that are not globally routable: SSRF-shaped callbacks and localhost smuggling.
    ("https://127.0.0.1/cb", "non-routable"),
    ("https://10.0.0.1/cb", "non-routable"),
    ("https://169.254.169.254/cb", "non-routable"),
    ("https://[::1]/cb", "non-routable"),
    ("https://224.0.0.1/cb", "non-routable"),
    ("https://0.0.0.0/cb", "non-routable"),
    ("https://[fec0::1]/cb", "non-routable"),  # IPv6 site-local reports is_global
    # Shorthand numeric hosts: ipaddress refuses to parse these, but browsers and inet_aton resolve every one of
    # them to 127.0.0.1, so treating an unparseable host as "must be a DNS name" would let loopback straight back in.
    ("https://127.1/cb", "not a DNS name"),
    ("https://2130706433/cb", "not a DNS name"),
    ("https://0x7f000001/cb", "not a DNS name"),
    ("https://0177.0.0.1/cb", "not a DNS name"),
    ("https://[::ffff:127.0.0.1]/cb", "non-routable"),  # IPv4-mapped IPv6 loopback
    ("https://[::ffff:10.0.0.1]/cb", "non-routable"),
    ("https://127.0.0.1./cb", "non-routable"),          # trailing root dot, stripped before parsing
    # Loopback and private-network *names*. An address-only guard misses every one of these, and `localhost` is
    # the plainest loopback host there is.
    ("https://localhost/cb", "loopback host"),
    ("https://LOCALHOST/cb", "loopback host"),
    ("https://localhost./cb", "loopback host"),
    ("https://ip6-localhost/cb", "loopback host"),
    ("https://ip6-loopback/cb", "loopback host"),
    ("https://foo.localhost/cb", "special-use"),
    ("https://api.localdomain/cb", "special-use"),
    ("https://svc.internal/cb", "special-use"),
    ("https://printer.local/cb", "special-use"),
    ("https://router.home.arpa/cb", "special-use"),
    ("https://box.lan/cb", "special-use"),
    ("https://intranet/cb", "special-use"),
    ("https://myhost/cb", "single-label"),              # no dot: cannot resolve globally
    # Hosts a browser normalises and urlsplit does not: percent-escapes and non-ASCII. Each of these reads as an
    # arbitrary public name to every suffix rule above, but resolves to localhost in a browser.
    ("https://foo.local%68ost/cb", "host must be ASCII"),
    ("https://printer.loc%61l/cb", "host must be ASCII"),
    (f"https://foo.{fullwidth('localhost')}/cb", "host must be ASCII"),
    ("https://xn--bcher-kva.example/cb", None),          # punycode: already ASCII, still accepted
    # Documentation and fixture suffixes stay usable: they cannot resolve either, but refusing them is noise.
    ("https://c.example/cb", None),
    ("https://a.example.com/cb", None),
    ("https://93.184.216.34/cb", None),  # a public IP literal is odd but not a security problem
    ("https://c.example/" + "a" * 3000, "exceeds"),
    (123, "must be a string"),
])
def test_redirect_uri_rules(uri, fragment_of_error):
    errors = validate_document(doc(redirect_uris=[uri]), URL)
    if fragment_of_error is None:
        assert errors == []
    else:
        assert any(fragment_of_error in e for e in errors), errors


def test_json_types_enforced():
    assert validate_document(doc(grant_types="authorization_code"), URL)
    assert validate_document(doc(response_types=[1]), URL)
    assert validate_document(doc(jwks={"keys": "nope"}), URL)
    assert validate_document(doc(jwks={"keys": ["str"]}), URL)
    assert validate_document(doc(jwks_uri="http://c.example/jwks"), URL)
    assert validate_document(doc(redirect_uris=[123]), URL)
    assert validate_document(doc(grant_types=["authorization_code"], response_types=["code"], jwks={"keys": [{"kty": "RSA"}]}), URL) == []


def test_fingerprint_changes_with_keys_and_content():
    a = jwks_fingerprint(doc())
    b = jwks_fingerprint(doc(jwks_uri="https://c.example/jwks"))
    c = jwks_fingerprint(doc(jwks_uri="https://c.example/jwks"), {"keys": [{"kid": "1"}]})
    d = jwks_fingerprint(doc(jwks_uri="https://c.example/jwks"), {"keys": [{"kid": "2"}]})
    assert len({a, b, c, d}) == 4 and jwks_fingerprint(doc()) == a
