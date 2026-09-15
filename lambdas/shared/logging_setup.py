"""Structured JSON logging with redaction of sensitive fields. No tokens, codes, cookies, or auth headers in logs."""
from __future__ import annotations

import json
import logging
import os
import re
import time

_REDACT_KEYS = {"authorization", "cookie", "set-cookie", "access_token", "id_token", "refresh_token", "code",
                "code_verifier", "client_secret", "x-origin-verify"}
_PATTERNS = [
    (re.compile(r"(?i)bearer\s+[a-z0-9._\-]+"), "Bearer [REDACTED]"),
    (re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"), "[REDACTED_JWT]"),  # any JWT
    (re.compile(r"(?i)\b(code|code_verifier|refresh_token|access_token|id_token|client_secret|state)=([^&\s\"']+)"), r"\1=[REDACTED]"),
    (re.compile(r"(?i)(set-cookie|cookie):\s*[^\n]+"), r"\1: [REDACTED]"),
]


def redact_text(text: str) -> str:
    for pattern, repl in _PATTERNS:
        text = pattern.sub(repl, text)
    return text


def redact(value):
    if isinstance(value, dict):
        return {k: ("[REDACTED]" if k.lower() in _REDACT_KEYS else redact(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {"ts": round(time.time(), 3), "level": record.levelname, "logger": record.name, "msg": redact_text(record.getMessage())}
        extra = getattr(record, "extra", None)
        if isinstance(extra, dict):
            payload.update(redact(extra))
        if record.exc_info:
            payload["exc"] = redact_text(self.formatException(record.exc_info))
        return json.dumps(payload, default=str)


def get_logger(name: str) -> logging.Logger:
    root = logging.getLogger()
    if not getattr(root, "_cimd_configured", False):
        for h in list(root.handlers):
            root.removeHandler(h)
        handler = logging.StreamHandler()
        handler.setFormatter(_JsonFormatter())
        root.addHandler(handler)
        root.setLevel(os.environ.get("LOG_LEVEL", "INFO"))
        root._cimd_configured = True  # type: ignore[attr-defined]
    return logging.getLogger(name)


def log(logger: logging.Logger, level: int, msg: str, **fields) -> None:
    logger.log(level, msg, extra={"extra": fields})
