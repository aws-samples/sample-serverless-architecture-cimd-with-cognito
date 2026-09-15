"""Log redaction: bearer tokens, JWTs, codes, refresh tokens, state, cookies and Authorization never reach a log line,
whether they appear in the message text, an exception, or a structured field."""
import base64
import json
import logging

from shared.logging_setup import get_logger, log, redact, redact_text


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


# A JWT-shaped fixture (header.payload.signature) built at import time. It is not a credential: the "signature" is the
# literal word repeated, so nothing verifies against it. Assembled rather than pasted so secret scanners do not flag it.
JWT = ".".join([_b64url(json.dumps({"alg": "RS256", "kid": "k1"}, separators=(",", ":")).encode()),
                _b64url(json.dumps({"sub": "u1", "exp": 17}, separators=(",", ":")).encode()),
                _b64url(b"signature-signature-signature")])


def test_redact_text_patterns():
    assert "Bearer [REDACTED]" in redact_text(f"Authorization: Bearer {JWT}")
    assert JWT not in redact_text(f"token was {JWT}")
    assert redact_text("callback?code=abc123&state=xyz") == "callback?code=[REDACTED]&state=[REDACTED]"
    assert redact_text("Set-Cookie: session=abc; Path=/") == "Set-Cookie: [REDACTED]"


def test_redact_dict_keys_and_nested():
    out = redact({"Authorization": "x", "nested": {"refresh_token": "y", "ok": f"see {JWT}"}, "list": ["code=1"]})  # nosec B105
    assert out["Authorization"] == "[REDACTED]" and out["nested"]["refresh_token"] == "[REDACTED]"
    assert JWT not in out["nested"]["ok"] and out["list"] == ["code=[REDACTED]"]


def test_formatter_redacts_message_and_exception(capfd):
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
    if hasattr(root, "_cimd_configured"):
        delattr(root, "_cimd_configured")
    logger = get_logger("t")
    try:
        raise ValueError(f"bad token {JWT}")
    except ValueError:
        logger.exception(f"failed with Bearer {JWT} and code=abc")
    log(logger, logging.INFO, "structured", authorization="Bearer zzz", fine="ok")
    out = capfd.readouterr().err
    assert JWT not in out and "code=abc" not in out and "Bearer zzz" not in out
    lines = [json.loads(line) for line in out.strip().splitlines()]
    assert lines[0]["level"] == "ERROR" and "[REDACTED" in lines[0]["exc"]
    assert lines[1]["authorization"] == "[REDACTED]" and lines[1]["fine"] == "ok"
