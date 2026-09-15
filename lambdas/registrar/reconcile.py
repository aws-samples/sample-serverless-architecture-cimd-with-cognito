"""Reconcile allow-listed CIMD URLs with Cognito shadow app clients and the mapping table.

Reaction matrix per URL: first sight → create app client + branding + rows; unchanged → extend cache; redirect_uris
changed → update callbacks; key material changed → rotate the app client (old refresh tokens die); document invalid →
disable; unreachable beyond max_stale_seconds → disable; removed from the allow-list → disable, then hard delete after
one access-token lifetime. All row writes are transactional so readers never see a half state.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass

from cognito_ops import CognitoOps, sanitize_client_name
from fetcher import FetchError, cache_seconds, fetch_document
from shared.cimd_url import validate_client_id_url
from shared.logging_setup import get_logger, log
from store import Store
from validate import jwks_fingerprint, redirect_uri_error, validate_document

logger = get_logger(__name__)


@dataclass
class Settings:
    allowed_clients: list[str]
    invoke_scope: str
    access_minutes: int
    refresh_days: int
    fetch_timeout: float
    fetch_deadline: float
    max_bytes: int
    cache_min_seconds: int
    cache_max_seconds: int
    max_redirect_uris: int = 100
    client_name_prefix: str = "cimd"
    max_jwks_bytes: int = 12288
    max_stale_seconds: int = 72 * 3600


@dataclass
class Summary:
    created: int = 0
    updated: int = 0
    rotated: int = 0
    disabled: int = 0
    deleted: int = 0
    branding_created: int = 0
    skipped_cached: int = 0
    not_modified: int = 0
    invalid: int = 0
    errors: list[str] = None  # type: ignore[assignment]

    def __post_init__(self):
        self.errors = []


class Reconciler:
    def __init__(self, settings: Settings, store: Store, cognito: CognitoOps, fetch=fetch_document, now=time.time):
        self.s, self.store, self.cognito, self.fetch, self.now = settings, store, cognito, fetch, now

    # ---- public
    def run(self, force: bool = False) -> Summary:
        summary = Summary()
        allowed = set(self.s.allowed_clients)
        for url in self.s.allowed_clients:
            try:
                self._reconcile_url(url, force, summary)
            except Exception as e:  # one bad client must not block the others
                summary.errors.append(f"{url}: {e}")
                log(logger, logging.ERROR, "reconcile failed for client", cimd_url=url, error=str(e))
        self._retire_removed(allowed, summary)
        self._purge_expired(summary)
        return summary

    def delete_all(self) -> Summary:
        summary = Summary()
        for row in self.store.list_clients():
            self._hard_delete(row, summary)
        return summary

    # ---- per URL
    def _reconcile_url(self, url: str, force: bool, summary: Summary) -> bool:
        """Returns validated_now: True iff THIS invocation confirmed the document (200 validated with JWKS validated,
        or 304) and left the mapping enabled. Distinct from cache freshness: a `no-cache`/`no-store` document is
        validated now but stored with cache_until=now, so the next request must revalidate again."""
        err = validate_client_id_url(url)
        if err:
            raise ValueError(f"invalid client_id URL: {err}")
        stored = self.store.get_client(url)
        now = int(self.now())
        if stored and stored.get("enabled") and not force and now < int(stored.get("cache_until", 0)):
            summary.skipped_cached += 1
            self._ensure_branding(stored, summary)
            return False

        try:
            result = self.fetch(url, max_bytes=self.s.max_bytes, timeout=self.s.fetch_timeout,
                                deadline_seconds=self.s.fetch_deadline, etag=(stored or {}).get("etag"))
        except FetchError as e:
            summary.errors.append(f"{url}: fetch failed: {e}")
            fetched_at = int((stored or {}).get("fetched_at", 0))
            if stored and stored.get("enabled") and now - fetched_at > self.s.max_stale_seconds:
                # Bounded staleness: after max_stale_seconds without a successful revalidation the client is disabled.
                self.store.set_enabled(stored, False, delete_after=None)
                summary.disabled += 1
                log(logger, logging.ERROR, "CIMD unreachable beyond max stale interval; client disabled", cimd_url=url, error=str(e))
            else:
                log(logger, logging.WARNING, "CIMD fetch failed; keeping stored state", cimd_url=url, error=str(e))
            return False

        if result.status == 304 and stored:
            # A 304 means the document did not change, but the RULES may have: a redirect URI stored by an older
            # build is otherwise never re-checked, because an unchanged document with a matching ETag never
            # reaches validate_document again. Re-apply the current redirect-URI rules to what is stored.
            stale_problems = [f"redirect_uri {r!r} {p}" for r in stored.get("redirect_uris", [])
                              if (p := redirect_uri_error(r))]
            if stale_problems:
                summary.invalid += 1
                log(logger, logging.WARNING, "stored redirect_uris no longer satisfy the current validation rules; client disabled",
                    cimd_url=url, problems=stale_problems)
                if stored.get("enabled"):
                    self.store.set_enabled(stored, False, delete_after=None)
                    summary.disabled += 1
                return False
            stored["cache_until"] = now + cache_seconds(result.headers, self.s.cache_min_seconds, self.s.cache_max_seconds)
            stored["fetched_at"] = now
            self.store.put_client(url, stored)
            summary.not_modified += 1
            self._ensure_branding(stored, summary)
            return bool(stored.get("enabled"))

        doc = result.document or {}
        problems = validate_document(doc, url, max_redirect_uris=self.s.max_redirect_uris)
        if problems:
            summary.invalid += 1
            log(logger, logging.WARNING, "CIMD document invalid; not stored", cimd_url=url, problems=problems)
            if stored and stored.get("enabled"):
                # §8.4: metadata no longer acceptable → stop serving this client
                self.store.set_enabled(stored, False, delete_after=None)
                summary.disabled += 1
            return False

        redirect_uris = list(doc["redirect_uris"])
        jwks_content, jwks_fetched_at, jwks_validated_now = self._jwks_content(doc, stored, first_sight=not stored, now=now)
        ttl = cache_seconds(result.headers, self.s.cache_min_seconds, self.s.cache_max_seconds)
        no_store = "no-store" in result.headers.get("cache-control", "").lower()
        if doc.get("jwks_uri") and not jwks_validated_now:
            # Declared key material could not be revalidated: do NOT recompute the fingerprint (a None/old content
            # comparison would be a false rotation), preserve the previous fingerprint and timestamp, and make the
            # mapping effectively stale so /authorize fails closed until JWKS validation succeeds.
            fp = (stored or {}).get("jwks_fingerprint")
            ttl = 0
            if stored and stored.get("enabled") and now - int(jwks_fetched_at or 0) > self.s.max_stale_seconds:
                self.store.set_enabled(stored, False, delete_after=None)
                summary.disabled += 1
                log(logger, logging.ERROR, "jwks_uri unvalidated beyond max stale interval; client disabled", cimd_url=url)
                return False
        else:
            fp = jwks_fingerprint(doc, jwks_content)
        # no-store: keep only the derived registration/security state (fingerprint, timestamps), never the representation.
        base = {"client_name": doc["client_name"], "redirect_uris": redirect_uris, "doc": None if no_store else doc,
                "etag": None if no_store else result.headers.get("etag"), "fetched_at": now, "cache_until": now + ttl,
                "jwks_fingerprint": fp, "jwks_uri_content": None if no_store else jwks_content, "jwks_fetched_at": jwks_fetched_at,
                "enabled": True, "delete_after": None}

        if not stored or not stored.get("cognito_client_id"):
            client_id = self._create_client(doc, redirect_uris, summary)
            self.store.put_client(url, {**base, "cognito_client_id": client_id})
            summary.created += 1
            log(logger, logging.INFO, "shadow client created", cimd_url=url, cognito_client_id=client_id)
            return jwks_validated_now

        if stored.get("jwks_fingerprint") and stored["jwks_fingerprint"] != fp:
            # §8.4.1: key material changed → rotate the app client so existing refresh tokens die
            old_id = stored["cognito_client_id"]
            new_id = self._create_client(doc, redirect_uris, summary)
            # ONE transaction: CLIENT# → new id, INDEX#new enabled, INDEX#old disabled, retired bookkeeping row
            self.store.put_client(url, {**base, "cognito_client_id": new_id}, retire_client_id=old_id,
                                  retired_delete_after=now + self.s.access_minutes * 60)
            summary.rotated += 1
            log(logger, logging.ERROR, "CIMD key material changed; shadow client rotated", cimd_url=url,
                old_client_id=old_id, new_client_id=new_id)
            return True  # rotation only happens when JWKS was validated now (fp is recomputed only in that branch)

        client_id = stored["cognito_client_id"]
        retire = None
        if not self.cognito.describe_client(client_id):
            retire = client_id  # stale id: its INDEX# row is disabled in the same transaction as the new mapping
            client_id = self._create_client(doc, redirect_uris, summary)
            log(logger, logging.WARNING, "shadow client missing in Cognito; recreated", cimd_url=url, cognito_client_id=client_id)
            summary.created += 1
        elif sorted(stored.get("redirect_uris", [])) != sorted(redirect_uris):
            self.cognito.update_callbacks(client_id, redirect_uris)
            summary.updated += 1
            log(logger, logging.WARNING, "redirect_uris changed; app client callbacks updated", cimd_url=url,
                before=stored.get("redirect_uris"), after=redirect_uris)
        self.store.put_client(url, {**base, "cognito_client_id": client_id}, retire_client_id=retire,
                              retired_delete_after=(now + self.s.access_minutes * 60) if retire else None)
        self._ensure_branding({"cognito_client_id": client_id}, summary)
        return jwks_validated_now

    # ---- helpers
    def _create_client(self, doc: dict, redirect_uris: list[str], summary: Summary) -> str:
        client_id = self.cognito.create_client(
            name=sanitize_client_name(doc["client_name"], self.s.client_name_prefix),
            redirect_uris=redirect_uris, scopes=["openid", self.s.invoke_scope],
            access_minutes=self.s.access_minutes, refresh_days=self.s.refresh_days)
        if self.cognito.ensure_branding(client_id):
            summary.branding_created += 1
        return client_id

    def _ensure_branding(self, row: dict, summary: Summary) -> None:
        if row.get("cognito_client_id") and self.cognito.ensure_branding(row["cognito_client_id"]):
            summary.branding_created += 1
            log(logger, logging.WARNING, "managed login branding was missing; created", cognito_client_id=row["cognito_client_id"])

    def _jwks_content(self, doc: dict, stored: dict | None, *, first_sight: bool, now: int) -> tuple[dict | None, int | None, bool]:
        """Guardedly fetch the JWKS behind jwks_uri (same SSRF, redirect, and size controls) so key rotation behind an
        unchanged URL is detected (§8.4.1). Returns (content, fetched_at, validated_now). On first sight a declared
        jwks_uri MUST be fetchable, otherwise registration is refused. On revalidation a fetch failure returns the stored
        timestamp and validated_now=False; the caller then keeps the previous fingerprint and marks the mapping stale."""
        uri = doc.get("jwks_uri")
        if not isinstance(uri, str):
            return None, None, True
        try:
            return self.fetch(uri, max_bytes=self.s.max_jwks_bytes, timeout=self.s.fetch_timeout,
                              deadline_seconds=self.s.fetch_deadline).document, now, True
        except FetchError as e:
            if first_sight:
                raise ValueError(f"declared jwks_uri could not be validated at registration: {e}") from e
            log(logger, logging.WARNING, "jwks_uri fetch failed; mapping marked stale until key material is revalidated",
                jwks_uri=uri, error=str(e))
            return (stored or {}).get("jwks_uri_content"), (stored or {}).get("jwks_fetched_at"), False

    # ---- authorization-time freshness (called synchronously by the proxy on a stale mapping)
    def revalidate_one(self, url: str) -> dict:
        """Force revalidation of one allow-listed URL and report whether the CURRENT authorization may proceed.

        `fresh` means "validated by this invocation and enabled" (validated_now), not "the stored entry is still
        cacheable". The two differ for `no-cache`/`no-store` documents: they authorize the request that triggered the
        revalidation, but are stored with cache_until=now so the proxy must revalidate again on the next request.
        Any fetch/validation/JWKS failure or exception yields fresh=false (fail closed)."""
        summary = Summary()
        if url not in self.s.allowed_clients:
            return {"status": "not_allowed", "fresh": False, "enabled": False}
        try:
            validated_now = self._reconcile_url(url, True, summary)
        except Exception as e:  # e.g. Cognito/DynamoDB error mid-reaction: never authorize on an unconfirmed mapping
            summary.errors.append(f"{url}: {e}")
            log(logger, logging.ERROR, "on-demand revalidation failed", cimd_url=url, error=str(e))
            validated_now = False
        row = self.store.get_client(url) or {}
        enabled = bool(row.get("enabled"))
        return {"status": "ok", "fresh": validated_now and enabled, "enabled": enabled, "errors": summary.errors}

    def _retire_removed(self, allowed: set[str], summary: Summary) -> None:
        now = int(self.now())
        for row in self.store.list_clients():
            url = row["cimd_url"]
            if url in allowed or url.startswith("retired://") or url.startswith("fixture://"):
                continue
            if row.get("enabled"):
                self.store.set_enabled(row, False, delete_after=now + self.s.access_minutes * 60)
                summary.disabled += 1
                log(logger, logging.INFO, "client removed from allow-list; disabled, deletion scheduled", cimd_url=url)

    def _purge_expired(self, summary: Summary) -> None:
        now = int(self.now())
        for row in self.store.list_clients():
            da = row.get("delete_after")
            if not row.get("enabled") and da is not None and int(da) <= now:
                self._hard_delete(row, summary)

    def _hard_delete(self, row: dict, summary: Summary) -> None:
        cid = row.get("cognito_client_id")
        if cid and not row["cimd_url"].startswith("fixture://"):
            self.cognito.delete_branding(cid)
            self.cognito.delete_client(cid)
        self.store.delete_client_rows(row)
        summary.deleted += 1
        log(logger, logging.INFO, "shadow client and rows deleted", cimd_url=row["cimd_url"], cognito_client_id=cid)
