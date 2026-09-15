"""Client identifier URL rules: every MUST / MUST NOT of the CIMD draft as a table test, including percent-encoded dot
segments, userinfo, query, fragment, and invalid ports. Mirrors lib/derive.ts validateCimdUrl."""
import json
import pathlib

import pytest
from shared.cimd_url import validate_client_id_url as v


@pytest.mark.parametrize("url,expected", [
    ("https://claude.ai/oauth/mcp-oauth-client-metadata", None),
    ("http://claude.ai/oauth/x", "scheme must be https"),
    ("https://claude.ai", "must contain a path component"),
    ("https://claude.ai/", "must contain a path component"),
    ("https://user@claude.ai/x", "must not contain userinfo"),
    ("https://claude.ai/a/../b", "must not contain dot segments"),
    ("https://claude.ai/./b", "must not contain dot segments"),
    ("https://claude.ai/a/%2e%2e/b", "must not contain dot segments"),
    ("https://claude.ai/%2E/b", "must not contain dot segments"),
    ("https://claude.ai/a/%2E%2e/b", "must not contain dot segments"),
    # Double- and triple-encoded: a proxy or CDN that decodes once before forwarding would turn an accepted
    # URL into a real traversal, so the check decodes repeatedly rather than once.
    ("https://claude.ai/a/%252e%252e/b", "must not contain dot segments"),
    ("https://claude.ai/a/%252E/b", "must not contain dot segments"),
    ("https://claude.ai/a/%25252e/b", "must not contain dot segments"),
    ("https://claude.ai/a/%2545/b", None),  # decodes to %45 then E: not a dot segment, still accepted
    ("https://claude.ai:8443/oauth/x", None),
    ("https://claude.ai:99999/oauth/x", "invalid port"),
    ("https://claude.ai/x?y=1", "must not contain a query component"),
    ("https://claude.ai/x#frag", "must not contain a fragment"),
])
def test_rules(url, expected):
    assert v(url) == expected


def _verdicts():
    path = pathlib.Path(__file__).resolve().parents[1] / "fixtures" / "cimd-url-verdicts.json"
    return [(c["url"], c["verdict"]) for c in json.loads(path.read_text())["cases"]]


@pytest.mark.parametrize("url,verdict", _verdicts())
def test_agrees_with_the_typescript_mirror(url, verdict):
    """Shared verdict table, also asserted by tests/cdk/config.test.ts against lib/derive.ts.

    A URL the two disagree on is either a deployment whose synth-time allow-list check refuses a URL the
    registrar would accept, or the reverse. Regenerate with tests/fixtures/gen_cases.py, which refuses to write
    the table while the two implementations differ.
    """
    assert ("accept" if v(url) is None else "reject") == verdict
