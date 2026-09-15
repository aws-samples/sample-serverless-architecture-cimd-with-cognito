"""Registrar entry point: CloudFormation custom resource (Create/Update/Delete) and EventBridge schedule."""
from __future__ import annotations

import json
import logging
import os
import time
import uuid

from cognito_ops import CognitoOps
from reconcile import Reconciler, Settings
from shared.logging_setup import get_logger, log
from shared.runtime_config import get_urls
from store import LockHeld, Store

logger = get_logger(__name__)


def _settings() -> Settings:
    urls = get_urls()
    allowed = list(json.loads(os.environ["ALLOWED_CLIENTS"]))
    if os.environ.get("TEST_CLIENT_ENABLED", "false").lower() == "true":
        # The built-in test client's CIMD document is served by cimd-proxy at publicBaseUrl + path; that URL is only
        # known at runtime (SSM), so it is appended here rather than in config.
        test_client_url = urls.public_base_url.rstrip("/") + os.environ["TEST_CLIENT_PATH"]
        if test_client_url not in allowed:
            allowed.append(test_client_url)
    return Settings(
        allowed_clients=allowed,
        invoke_scope=urls.invoke_scope,
        access_minutes=int(os.environ["ACCESS_TOKEN_MINUTES"]),
        refresh_days=int(os.environ["REFRESH_TOKEN_DAYS"]),
        fetch_timeout=float(os.environ["FETCH_TIMEOUT_SECONDS"]),
        fetch_deadline=float(os.environ["FETCH_DEADLINE_SECONDS"]),
        max_bytes=int(os.environ["MAX_DOCUMENT_BYTES"]),
        cache_min_seconds=int(os.environ["CACHE_MIN_SECONDS"]),
        cache_max_seconds=int(os.environ["CACHE_MAX_SECONDS"]),
        max_redirect_uris=int(os.environ.get("MAX_REDIRECT_URIS", "100")),
        client_name_prefix=os.environ.get("CLIENT_NAME_PREFIX", "cimd"),
        max_jwks_bytes=int(os.environ.get("MAX_JWKS_BYTES", "12288")),
        max_stale_seconds=int(os.environ.get("MAX_STALE_SECONDS", str(72 * 3600))),
    )


def _with_lock(store: Store, wait_seconds: float, fn):
    owner = str(uuid.uuid4())
    ttl = int(os.environ["LOCK_TTL_SECONDS"])
    deadline = time.time() + wait_seconds
    delay = 2.0
    while True:
        try:
            store.acquire_lock(owner, ttl)
            break
        except LockHeld:
            if time.time() >= deadline:
                raise
            time.sleep(min(delay, max(0.1, deadline - time.time())))
            delay = min(delay * 2, 20)
    try:
        return fn()
    finally:
        store.release_lock(owner)


def handler(event, context):
    store = Store(os.environ["TABLE_NAME"])
    cognito = CognitoOps(os.environ["USER_POOL_ID"])
    settings = _settings()
    rec = Reconciler(settings, store, cognito)

    if "RequestType" in event:  # CloudFormation custom resource via CDK Provider framework
        req = event["RequestType"]
        wait = float(os.environ.get("LOCK_WAIT_SECONDS", "240"))
        if req == "Delete":
            summary = _with_lock(store, wait, rec.delete_all)
        else:
            summary = _with_lock(store, wait, lambda: rec.run(force=True))
        log(logger, logging.INFO, "custom resource run complete", request_type=req, summary=vars(summary))
        if summary.errors and req != "Delete":
            # fail the deployment loudly on unrecoverable errors for allow-listed clients
            raise RuntimeError("registrar errors: " + "; ".join(summary.errors))
        return {"PhysicalResourceId": "cimd-registrar", "Data": {"created": summary.created, "deleted": summary.deleted}}

    if event.get("action") == "revalidate":  # synchronous call from cimd-proxy on a stale mapping; fail closed on timeout
        url = event.get("cimd_url", "")
        wait = float(os.environ.get("REVALIDATE_LOCK_WAIT_SECONDS", "3"))
        try:
            result = _with_lock(store, wait, lambda: rec.revalidate_one(url))
        except LockHeld:
            # Transient: nothing was validated and nothing is known about the client. No `enabled` claim.
            return {"status": "locked", "fresh": False}
        log(logger, logging.INFO, "on-demand revalidation", cimd_url=url, result=result)
        return result

    # EventBridge schedule: skip if another run holds the lock
    try:
        summary = _with_lock(store, 0, lambda: rec.run(force=False))
    except LockHeld:
        log(logger, logging.INFO, "registrar locked; skipping scheduled run")
        return {"status": "locked"}
    log(logger, logging.INFO, "scheduled run complete", summary=vars(summary))
    return {"status": "ok", **vars(summary)}
