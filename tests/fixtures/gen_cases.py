"""Regenerates the shared client-identifier-URL verdict table consumed by both validator test suites.

The table records only accept/reject, not the error text: `urlsplit` and the WHATWG `URL` parser disagree about
*which* rule a malformed URL breaks first (`https://claude.ai:99999/x` is "invalid port" to one and "not a valid
URL" to the other), and that is a difference between the two languages' URL parsers rather than a difference in
this project's policy. What must never differ is the decision.

Run after changing either validator, then review the diff:
    python3 tests/fixtures/gen_cases.py
"""
import json
import pathlib
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "lambdas"))


def fullwidth(s: str) -> str:
    """ASCII -> fullwidth Latin (U+FF01..U+FF5E). Composed rather than written literally so the source carries no
    visually ambiguous characters; browsers map these back to ASCII via UTS-46, `urlsplit` does not."""
    return "".join(chr(ord(c) - 0x20 + 0xFF00) for c in s)

CASES = [
    # baseline
    "https://claude.ai/oauth/mcp-oauth-client-metadata",
    "https://claude.ai/oauth/mcp-oauth-client-metadata/",
    "https://claude.ai:8443/oauth/x",
    # scheme, authority, path presence
    "http://claude.ai/oauth/x",
    "ftp://claude.ai/x",
    "not-a-url",
    "https://claude.ai",
    "https://claude.ai/",
    "https://user@claude.ai/x",
    "https://user:pw@claude.ai/x",
    "https://claude.ai:99999/oauth/x",
    "https://claude.ai/x?y=1",
    "https://claude.ai/x#frag",
    "https://127.0.0.1/x",
    # dot segments, plain and single-encoded
    "https://claude.ai/a/../b",
    "https://claude.ai/./b",
    "https://claude.ai/a/%2e%2e/b",
    "https://claude.ai/%2E/b",
    "https://claude.ai/a/%2E%2e/b",
    # double- and triple-encoded dot segments
    "https://claude.ai/a/%252e%252e/b",
    "https://claude.ai/a/%252E/b",
    "https://claude.ai/a/%25252e/b",
    # encoded path separators, which decode into dot segments a splitter never sees
    "https://claude.ai/a/%252F%252F%252e%252e%252F/b",
    "https://claude.ai/a/%2F/b",
    "https://claude.ai/a/%5C/b",
    "https://claude.ai/a/..%2f/b",
    # malformed percent-escapes: unquote is lenient, decodeURIComponent throws; both must refuse
    "https://claude.ai/a/100%25/b",
    "https://claude.ai/a/%25FF/b",
    "https://claude.ai/a/%25C0%25AE/b",
    "https://claude.ai/a/%80/b",
    "https://claude.ai/a/%/b",
    "https://claude.ai/a/%2/b",
    # well-formed escapes that are not dot segments: must still be accepted
    "https://claude.ai/a/%2545/b",
    "https://claude.ai/a/%E2%82%AC/b",
    "https://claude.ai/%20/b",
    # Backslash in the authority: WHATWG rewrites it to '/', so a browser and lib/derive.ts see the host
    # 127.0.0.1 while urlsplit keeps the whole string as the hostname. Both must refuse.
    "https://127.0.0.1\\claude.ai/x",
    "https://claude.ai\\evil.example/x",
    "https://claude.ai/a\\b/c",
    # Hosts WHATWG normalises and urlsplit does not: percent-escapes and fullwidth Latin. Both implementations
    # accepted these before, but they disagreed about the resulting HOST, so synth validated one name and the
    # registrar would have fetched another.
    "https://x.local%68ost/a",
    f"https://{fullwidth('example')}.com/a",
    "https://xn--bcher-kva.example/a",  # punycode: ASCII already, must stay accepted
    # control characters and spaces, the classic parser-disagreement lever
    "https://claude.ai/ ",
    "https://claude.ai/x ",
    "https://claude.ai/\t%252e\t/b",
    "https://claude.ai/\x00",
    "https://claude.ai/a b/c",
]

TS_PROBE = """
import * as fs from 'fs';
import { validateCimdUrl } from '../../lib/derive';
const cases = JSON.parse(fs.readFileSync(process.argv[2], 'utf8')) as string[];
const out: Record<string, string> = {};
for (const u of cases) out[u] = validateCimdUrl(u) === undefined ? 'accept' : 'reject';
fs.writeFileSync(process.argv[3], JSON.stringify(out));
"""


def main() -> int:
    from shared.cimd_url import validate_client_id_url

    tmp_cases = REPO / "tests" / "fixtures" / ".cases.tmp.json"
    tmp_ts = REPO / "tests" / "fixtures" / ".ts.tmp.json"
    probe = REPO / "tests" / "fixtures" / ".probe.tmp.ts"
    tmp_cases.write_text(json.dumps(CASES))
    probe.write_text(TS_PROBE)
    try:
        subprocess.run(["npx", "ts-node", str(probe), str(tmp_cases), str(tmp_ts)], cwd=REPO, check=True)
        ts = json.loads(tmp_ts.read_text())
    finally:
        for p in (tmp_cases, tmp_ts, probe):
            p.unlink(missing_ok=True)

    py = {u: ("accept" if validate_client_id_url(u) is None else "reject") for u in CASES}
    diverged = [u for u in CASES if py[u] != ts[u]]
    if diverged:
        print("DIVERGENCE between lambdas/shared/cimd_url.py and lib/derive.ts:")
        for u in diverged:
            print(f"  {u!r}: python={py[u]} typescript={ts[u]}")
        return 1

    out = pathlib.Path(__file__).with_name("cimd-url-verdicts.json")
    out.write_text(json.dumps({"cases": [{"url": u, "verdict": py[u]} for u in CASES]}, indent=2) + "\n")
    print(f"{len(CASES)} cases, both implementations agree -> {out.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
