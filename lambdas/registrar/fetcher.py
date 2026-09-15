"""Guarded CIMD fetch (draft-02 §5, §8.6, §8.7): HTTPS only, every resolved address must be globally routable,
connection pinned to the checked address with SNI/Host set to the URL host, no redirects, streaming size cap,
strict content type, and a wall-clock deadline over the whole exchange. Resolver and connection factory are
injectable for tests."""
from __future__ import annotations

import contextlib
import http.client
import ipaddress
import json
import socket
import ssl
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from urllib.parse import urlsplit


class FetchError(Exception):
    pass


@dataclass
class FetchResult:
    status: int
    body: bytes
    headers: dict[str, str]
    document: dict | None


def default_resolver(host: str, port: int = 443) -> list[str]:
    infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    return sorted({info[4][0] for info in infos})


def call_with_deadline(fn: Callable[[], object], seconds: float, what: str, thread_name: str) -> object:
    """Run `fn` on a daemon thread and stop waiting for it after `seconds`.

    This is the only way to put a hard bound on the blocking work in a guarded fetch, because the pieces that
    block do not accept a timeout that covers them:

    - `socket.getaddrinfo` takes no timeout argument at all.
    - `HTTPResponse.begin()` (inside `getresponse()`) loops on `fp.readline()` to parse the status line and
      headers, and chunked decoding loops on `fp.readline()` for each chunk-size line. A per-socket timeout
      never fires while a peer drips one byte per recv, so those loops can run for as long as the peer likes
      and no clock check placed around them is ever reached.

    The abandoned thread keeps running until its syscall returns -- a blocking syscall cannot be cancelled --
    but it is a daemon, it holds no lock, and its result is discarded. The caller closes the socket on the way
    out, which is what actually unblocks it. The registrar's DynamoDB lock is released by the main thread, so a
    stuck fetch cannot block the next run.
    """
    box: dict = {}

    def run() -> None:
        try:
            box["value"] = fn()
        except BaseException as e:  # re-raised on the calling thread below
            box["error"] = e

    thread = threading.Thread(target=run, daemon=True, name=thread_name)
    thread.start()
    thread.join(seconds)
    if thread.is_alive():
        raise FetchError(f"{what} did not complete within {seconds:.3g}s; abandoned")
    if "error" in box:
        raise box["error"]
    return box["value"]


def is_routable_unicast(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True only for globally routable unicast addresses.

    `is_global` alone is not sufficient. Verified on CPython 3.12: multicast (224.0.0.0/4, ff00::/8), the
    reserved ranges (240.0.0.0/4), the unspecified address and IPv6 site-local (fec0::/10, deprecated but still
    resolvable) all report `is_global == True`. Each is excluded explicitly.
    """
    return not (
        not ip.is_global
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or ip.is_loopback
        or ip.is_link_local
        or getattr(ip, "is_site_local", False)
    )


def check_addresses(host: str, addresses: Iterable[str]) -> None:
    """Every resolved address must be a globally routable unicast address."""
    addrs = list(addresses)
    if not addrs:
        raise FetchError(f"{host}: no addresses resolved")
    for a in addrs:
        if not is_routable_unicast(ipaddress.ip_address(a.split("%")[0])):
            raise FetchError(f"{host}: resolves to special-use address {a} (RFC 6890); refusing to fetch")


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connects to a pre-validated IP while presenting the URL host for SNI and certificate validation."""

    def __init__(self, ip: str, host: str, port: int, timeout: float):
        super().__init__(ip, port, timeout=timeout, context=ssl.create_default_context())
        self._sni_host = host

    def connect(self) -> None:  # pragma: no cover - exercised in deployed tests
        sock = socket.create_connection((self.host, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self._sni_host)


def default_connection_factory(ip: str, host: str, port: int, timeout: float) -> http.client.HTTPConnection:
    return PinnedHTTPSConnection(ip, host, port, timeout)


EXCHANGE_THREAD_NAME = "cimd-fetch-exchange"
"""Exchange workers are named so tests can assert they actually terminate, not merely that the caller returned.

Distinct from the resolver's name on purpose: an abandoned DNS worker holds no socket and nothing can interrupt
`getaddrinfo`, so it is expected to outlive the fetch. An abandoned *exchange* worker holds a descriptor and must
not survive cleanup, and a test that could not tell the two apart would never be able to assert that.
"""

RESOLVER_THREAD_NAME = "cimd-fetch-dns"


def hard_close(sock: object) -> None:
    """Interrupt then release a socket. `shutdown` is what wakes a blocked recv; closing the fd alone does not."""
    if sock is None:
        return
    with contextlib.suppress(OSError, AttributeError):
        sock.shutdown(socket.SHUT_RDWR)  # type: ignore[attr-defined]
    with contextlib.suppress(OSError, AttributeError):
        sock.close()  # type: ignore[attr-defined]


class TransportHandle:
    """Makes abandonment sticky, so a connection established *after* the deadline is still closed and unused.

    Capturing the socket once `connect()` returns is not enough. `PinnedHTTPSConnection.connect` assigns
    `self.sock` only after `wrap_socket` returns, so throughout the TCP connect and the TLS handshake there is
    nothing for cleanup to find: the budget could expire mid-handshake, cleanup would see no transport, and the
    worker would then finish the handshake and **send the request to a host the caller had already given up on**.
    Verified: with a 250 ms deadline and a 400 ms handshake, the caller returned at 256 ms and the request still
    went out.

    Registration and cancellation share a lock, so whichever happens second performs the close and the worker
    always learns it was abandoned before it can send anything.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sock: object = None
        self._cancelled = False

    def adopt(self, sock: object) -> None:
        """Register a freshly established socket. Raises if the fetch was abandoned while it was being built."""
        with self._lock:
            self._sock = sock
            cancelled = self._cancelled
        if cancelled:
            hard_close(sock)
            raise FetchError("fetch was abandoned while the connection was being established")

    def cancel(self) -> None:
        with self._lock:
            self._cancelled = True
            sock = self._sock
        hard_close(sock)


def release_connection(conn: http.client.HTTPConnection, handle: TransportHandle) -> None:
    """Interrupt and release a connection without ever blocking the caller.

    `conn.close()` must NOT be used on the abandonment path. It calls `HTTPResponse.close()`, which acquires the
    buffered reader's lock that the abandoned worker is still holding inside `readline()` -- so the cleanup
    inherits exactly the block the deadline just escaped. Measured against a peer dripping one prolonged
    chunk-size line: a 150 ms budget took 21.6 s, effectively all of it inside `close()`.

    Three transports are dealt with, and none of them is redundant:

    - `handle`, which the worker registers as soon as the socket exists and which stays cancelled afterwards, so a
      connection completed after the deadline is closed too (see TransportHandle).
    - `conn.sock`, for the ordinary keep-alive case.
    - `conn.close()` on a daemon thread, so even a transport that ignores the shutdown cannot make cleanup
      outlast the deadline. On a `Connection: close` response `getresponse()` has already handed the socket to the
      HTTPResponse and cleared `conn.sock`, which is why the handle exists at all.
    """
    handle.cancel()
    hard_close(getattr(conn, "sock", None))

    def close_quietly() -> None:
        with contextlib.suppress(Exception):
            conn.close()

    threading.Thread(target=close_quietly, daemon=True, name=f"{EXCHANGE_THREAD_NAME}-close").start()


def fetch_document(url: str, *, max_bytes: int, timeout: float, etag: str | None = None,
                   deadline_seconds: float | None = None,
                   resolver: Callable[[str, int], list[str]] = default_resolver,
                   connection_factory: Callable[[str, str, int, float], http.client.HTTPConnection] = default_connection_factory) -> FetchResult:
    """Fetch a JSON object (CIMD document or JWKS) with the §5/§8.6/§8.7 guards. Uses the URL's declared port.

    `timeout` is the per-socket timeout; `deadline_seconds` is the total wall-clock budget for resolution,
    connect, request and the whole response body. Without the budget a server that drips one byte just inside
    every socket timeout holds the registrar for as long as it likes. Omitting `deadline_seconds` applies the
    strictest reading, `timeout` as the total budget, so a caller that forgets it fails safe.

    The budget is *enforced*, not merely observed afterwards: resolution runs on a thread we stop waiting for
    (`socket.getaddrinfo` accepts no timeout), the connect timeout is capped by what is left, and the socket
    timeout is re-tightened to the remaining budget before every read. Otherwise a single blocking read could
    still overrun by a whole `timeout` before anything noticed.
    """
    start = time.monotonic()
    budget = float(timeout if deadline_seconds is None else deadline_seconds)

    def remaining() -> float:
        left = budget - (time.monotonic() - start)
        if left <= 0:
            raise FetchError(f"fetch exceeded its {budget:g}s wall-clock deadline; aborted")
        return left

    u = urlsplit(url)
    if u.scheme != "https" or not u.hostname:
        raise FetchError("only https URLs are fetched")
    host = u.hostname
    try:
        port = u.port or 443
    except ValueError as e:
        raise FetchError("invalid port") from e
    addresses = call_with_deadline(lambda: resolver(host, port), remaining(), f"DNS resolution of {host}",
                                  RESOLVER_THREAD_NAME)
    check_addresses(host, addresses)
    path = (u.path or "/") + (f"?{u.query}" if u.query else "")
    host_header = host if port == 443 else f"{host}:{port}"
    headers = {"Host": host_header, "Accept": "application/json", "User-Agent": "cimd-registrar/1.0"}
    if etag:
        headers["If-None-Match"] = etag

    handle = TransportHandle()

    def exchange(conn: http.client.HTTPConnection) -> tuple[dict[str, str], bytes | None]:
        """The whole blocking HTTP interaction. Runs on the abandonable thread; returns (headers, body|None).

        A body of None means 304. Everything in here can block for as long as the peer chooses no matter what
        socket timeout is set, which is exactly why it runs where it can be abandoned.
        """
        try:
            connect = getattr(conn, "connect", None)
            if connect is not None:
                connect()  # explicit, so the socket exists and is registered before anything takes it over
            # Registering raises if the budget expired during the connect or the TLS handshake, which is what
            # stops an abandoned worker from sending its request anyway. See TransportHandle.
            handle.adopt(getattr(conn, "sock", None))
            conn.request("GET", path, headers=headers)
            # getresponse() parses the status line and headers with blocking readline() loops, and on a
            # `Connection: close` response it hands the socket to the HTTPResponse and clears conn.sock -- which
            # is why the capture above happens first. See release_connection.
            resp = conn.getresponse()
        except OSError as e:
            raise FetchError(f"transport error before the response was read: {e}") from e
        remaining()
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}
        if resp.status == 304 and etag:
            return resp_headers, None
        if resp.status != 200:
            raise FetchError(f"HTTP {resp.status} (redirects are never followed)")
        ctype = resp_headers.get("content-type", "")
        if "json" not in ctype.lower():
            raise FetchError(f"unexpected content-type {ctype!r}")
        body = b""
        while True:
            # Re-tighten the socket timeout to what is left of the budget on every pass, so an individual recv
            # also fails fast rather than relying solely on the thread being abandoned.
            sock = getattr(conn, "sock", None)
            if sock is not None:
                sock.settimeout(remaining())
            else:
                remaining()
            # read1, not read: read() loops on recv internally until it has the full amount requested, so a
            # server dripping one byte per recv keeps a single read() call running and the check above is never
            # reached again. read1 returns after one underlying read.
            try:
                chunk = resp.read1(min(4096, max_bytes + 1 - len(body)))
            except OSError as e:
                raise FetchError(f"response body stalled and hit the {budget:g}s wall-clock deadline: {e}") from e
            if not chunk:
                break
            body += chunk
            if len(body) > max_bytes:
                raise FetchError(f"document exceeds {max_bytes} bytes; aborted")
        remaining()
        return resp_headers, body

    conn = connection_factory(addresses[0], host, port, min(timeout, remaining()))
    try:
        resp_headers, body = call_with_deadline(  # type: ignore[misc]
            lambda: exchange(conn), remaining(), f"HTTP exchange with {host}", EXCHANGE_THREAD_NAME)
    except BaseException:
        # Never a plain conn.close() here: the worker may still hold the reader lock. See release_connection.
        release_connection(conn, handle)
        raise
    conn.close()  # success path only: the worker has finished, so this cannot block
    if body is None:
        return FetchResult(304, b"", resp_headers, None)
    try:
        document = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise FetchError(f"document is not valid JSON: {e}") from e
    if not isinstance(document, dict):
        raise FetchError("document must be a JSON object")
    return FetchResult(200, body, resp_headers, document)


def cache_seconds(headers: dict[str, str], min_seconds: int, max_seconds: int) -> int:
    """RFC 9111: max-age bounded by the configured min/max; no header → min.
    `no-store` and `no-cache` → 0: the document is still kept for §8.4 diffing, but it must be
    revalidated before any reuse, so the cache entry expires immediately. TTL 0 says nothing about whether
    the CURRENT validation succeeded; Reconciler.revalidate_one reports that separately (validated_now)."""
    directives = [d.strip().lower() for d in headers.get("cache-control", "").split(",") if d.strip()]
    if any(d in ("no-store", "no-cache") for d in directives):
        return 0
    seconds = min_seconds
    for d in directives:
        if d.startswith("max-age="):
            with contextlib.suppress(ValueError):  # malformed max-age: keep the minimum
                seconds = int(d.split("=", 1)[1])
    return max(min_seconds, min(max_seconds, seconds))
