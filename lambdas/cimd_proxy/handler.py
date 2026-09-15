"""cimd-proxy Lambda entry point (HTTP API payload 2.0). Wires AWS clients into the pure App."""
from __future__ import annotations

import os

from cognito_relay import CognitoRelay
from freshness import Freshness, lambda_revalidator
from proxy_app import App, Settings
from shared.logging_setup import get_logger
from shared.mapping_store import MappingStore
from shared.runtime_config import get_urls

logger = get_logger(__name__)
_app: App | None = None


def _build() -> App:
    env = os.environ
    settings = Settings(
        token_issuer=env["TOKEN_ISSUER"],
        login_base_url=env["COGNITO_LOGIN_BASE_URL"],
        show_consent=env.get("SHOW_CONSENT_INTERSTITIAL", "true").lower() == "true",
        consent_cookie_max_age=int(env["CONSENT_COOKIE_MAX_AGE_SECONDS"]),
        metadata_cache_seconds=int(env["METADATA_CACHE_SECONDS"]),
        test_client_enabled=env.get("TEST_CLIENT_ENABLED", "false").lower() == "true",
        test_client_path=env.get("TEST_CLIENT_PATH", "/test-client/metadata.json"),
        test_client_name=env.get("TEST_CLIENT_NAME", "CIMD test client"),
    )
    retry_after = int(env["UNAVAILABLE_RETRY_AFTER_SECONDS"])
    freshness = Freshness(
        MappingStore(env["TABLE_NAME"]),
        lambda_revalidator(env["REGISTRAR_FUNCTION_NAME"], float(env["REVALIDATE_TIMEOUT_SECONDS"])),
        retry_after_seconds=retry_after,
    )
    relay = CognitoRelay(settings.login_base_url, float(env["COGNITO_TIMEOUT_SECONDS"]), retry_after)
    return App(settings, get_urls, freshness, relay)


def handler(event, _context):
    global _app
    if _app is None:
        _app = _build()
    return _app.handle_event(event)
