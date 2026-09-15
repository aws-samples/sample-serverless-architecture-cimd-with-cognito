"""Guarded CIMD fetch: special-use addresses rejected after DNS, every A/AAAA answer checked, connection pinned to the
resolved IP with Host and SNI set, streaming size cap, redirects and non-200 refused, JSON content type required,
304 revalidation, RFC 9111 cache directive bounds, and the wall-clock deadline over the whole exchange."""
import http.client
import json
import socket
import threading
import time

import pytest
from fetcher import EXCHANGE_THREAD_NAME, FetchError, cache_seconds, check_addresses, fetch_document

URL = "https://client.example/oauth/meta"


class FakeResp:
    def __init__(self, status, body: bytes, headers):
        self.status, self._body, self._headers, self._pos = status, body, headers, 0

    def getheaders(self):
        return list(self._headers.items())

    def read1(self, n):
        """The fetch uses read1, not read: read() loops on recv internally, which is what let a slow-drip body
        run past the deadline inside a single call."""
        chunk = self._body[self._pos:self._pos + n]
        self._pos += n
        return chunk


class FakeConn:
    def __init__(self, resp):
        self.resp, self.requests, self.closed = resp, [], False

    def request(self, method, path, headers=None):
        self.requests.append((method, path, headers))

    def getresponse(self):
        return self.resp

    def close(self):
        self.closed = True


def factory_for(resp):
    made = {}
    def f(ip, host, port, timeout):
        made["ip"], made["host"], made["port"], made["timeout"] = ip, host, port, timeout
        made["conn"] = FakeConn(resp)
        return made["conn"]
    return f, made


def good_doc():
    return json.dumps({"client_id": URL, "client_name": "C", "redirect_uris": ["https://client.example/cb"]}).encode()


@pytest.mark.parametrize("addr", [
    "10.0.0.5", "127.0.0.1", "169.254.169.254", "192.168.1.1", "100.64.0.1", "::1", "fd00::1", "fe80::1",
    # ipaddress.is_global reports True for these, so is_global alone is not a sufficient guard.
    "224.0.0.1", "239.255.255.250", "ff02::1",  # multicast
    "240.0.0.1",                                # reserved
    "0.0.0.0", "::",                            # unspecified
    "fec0::1", "feff::1",                       # IPv6 site-local: deprecated, still resolvable, still is_global
])
def test_special_use_addresses_rejected(addr):
    with pytest.raises(FetchError, match="special-use"):
        check_addresses("h", [addr])


def test_all_answers_checked_not_just_first():
    with pytest.raises(FetchError):
        check_addresses("h", ["93.184.216.34", "10.0.0.1"])


def test_connection_pinned_to_resolved_ip_with_host_header():
    f, made = factory_for(FakeResp(200, good_doc(), {"Content-Type": "application/json", "ETag": "v1", "Cache-Control": "max-age=600"}))
    r = fetch_document(URL, max_bytes=5120, timeout=3, resolver=lambda h, p: ["93.184.216.34"], connection_factory=f)
    assert made["ip"] == "93.184.216.34" and made["host"] == "client.example"
    method, path, headers = made["conn"].requests[0]
    assert (method, path) == ("GET", "/oauth/meta") and headers["Host"] == "client.example" and headers["Accept"] == "application/json"
    assert r.status == 200 and r.document["client_id"] == URL and made["conn"].closed


def test_oversized_body_aborted_while_streaming():
    f, _ = factory_for(FakeResp(200, b"{" + b" " * 10000 + b"}", {"content-type": "application/json"}))
    with pytest.raises(FetchError, match="exceeds"):
        fetch_document(URL, max_bytes=5120, timeout=3, resolver=lambda h, p: ["93.184.216.34"], connection_factory=f)


@pytest.mark.parametrize("status", [301, 302, 307, 404, 500])
def test_non_200_rejected_including_redirects(status):
    f, _ = factory_for(FakeResp(status, b"", {"location": "https://elsewhere.example/x"}))
    with pytest.raises(FetchError, match=f"HTTP {status}"):
        fetch_document(URL, max_bytes=5120, timeout=3, resolver=lambda h, p: ["93.184.216.34"], connection_factory=f)


def test_non_json_content_type_rejected():
    f, _ = factory_for(FakeResp(200, good_doc(), {"content-type": "text/html"}))
    with pytest.raises(FetchError, match="content-type"):
        fetch_document(URL, max_bytes=5120, timeout=3, resolver=lambda h, p: ["93.184.216.34"], connection_factory=f)


def test_304_with_etag():
    f, made = factory_for(FakeResp(304, b"", {}))
    r = fetch_document(URL, max_bytes=5120, timeout=3, etag="v1", resolver=lambda h, p: ["93.184.216.34"], connection_factory=f)
    assert r.status == 304 and made["conn"].requests[0][2]["If-None-Match"] == "v1"


def test_http_url_refused():
    with pytest.raises(FetchError):
        fetch_document("http://client.example/x", max_bytes=1, timeout=1, resolver=lambda h, p: ["93.184.216.34"], connection_factory=None)


def test_wall_clock_deadline_aborts_a_slow_drip_body():
    """A server that returns one byte per read, each read inside the socket timeout, must still be cut off."""
    class DripResp(FakeResp):
        def read1(self, n):
            time.sleep(0.02)  # every read is well inside the per-socket timeout
            return super().read1(1)

    f, _ = factory_for(DripResp(200, b"{" + b" " * 10000 + b"}", {"content-type": "application/json"}))
    with pytest.raises(FetchError, match=r"wall-clock deadline|did not complete within"):
        fetch_document(URL, max_bytes=5120, timeout=30, deadline_seconds=0.1,
                       resolver=lambda h, p: ["93.184.216.34"], connection_factory=f)


def test_a_response_that_completes_after_the_deadline_is_not_accepted():
    """A blocking read cannot be interrupted mid-call, so the budget is re-checked once the body is in hand."""
    class SlowResp(FakeResp):
        def read1(self, n):
            time.sleep(0.15)  # one single read that overruns the whole budget, then returns the full body
            return super().read1(n)

    f, _ = factory_for(SlowResp(200, good_doc(), {"content-type": "application/json"}))
    with pytest.raises(FetchError, match=r"wall-clock deadline|did not complete within"):
        fetch_document(URL, max_bytes=5120, timeout=30, deadline_seconds=0.1,
                       resolver=lambda h, p: ["93.184.216.34"], connection_factory=f)


def test_dns_resolution_is_bounded_even_though_getaddrinfo_takes_no_timeout():
    """Resolution runs on a thread the fetch stops waiting for; without that it is unbounded by anything here."""
    def hanging_resolver(host, port):
        time.sleep(5)
        return ["93.184.216.34"]

    started = time.monotonic()
    with pytest.raises(FetchError, match=r"DNS resolution.*did not complete"):
        fetch_document(URL, max_bytes=5120, timeout=30, deadline_seconds=0.2,
                       resolver=hanging_resolver, connection_factory=None)
    assert time.monotonic() - started < 5  # gave up promptly rather than waiting out the resolver


def drip_server(script: list[bytes], gap: float = 0.05):
    """Serve one request, then emit `script` one item at a time with `gap` between. Returns the listening port.

    Used to prove the deadline against the paths a per-socket timeout cannot bound: every write lands well
    inside the socket timeout, so nothing times out and the blocking readline() loops inside http.client would
    otherwise run for as long as this server keeps dripping.
    """
    ready = threading.Event()
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def serve():
        ready.set()
        conn, _ = listener.accept()
        conn.recv(4096)
        try:
            for piece in script:
                conn.sendall(piece)
                time.sleep(gap)
        except OSError:
            pass
        finally:
            conn.close()
            listener.close()

    threading.Thread(target=serve, daemon=True).start()
    ready.wait()
    return port


def live_fetch_workers() -> list[threading.Thread]:
    return [t for t in threading.enumerate() if t.is_alive() and t.name.startswith(EXCHANGE_THREAD_NAME)]


def assert_deadline_enforced(port: int, budget: float = 0.3, slack: float = 0.7):
    """The fetch must fail within `budget + slack`, AND leave no worker behind.

    Two assertions, because the caller returning promptly is not the whole property. On a `Connection: close`
    response `getresponse()` transfers the socket to the HTTPResponse and clears `conn.sock`, so cleanup that
    only consults the connection interrupts nothing: the caller saw its deadline honoured while the abandoned
    worker kept reading and holding a descriptor, accumulating across invocations in a warm Lambda.

    The slack is deliberately tight. Each drip script below would take seconds to finish, so a loose bound would
    pass even against an implementation that merely notices the overrun afterwards.
    """
    def plain_connection(ip, host, p, t):
        return http.client.HTTPConnection("127.0.0.1", port, timeout=t)

    started = time.monotonic()
    with pytest.raises(FetchError):
        fetch_document(URL, max_bytes=5120, timeout=30, deadline_seconds=budget,
                       resolver=lambda h, p: ["93.184.216.34"], connection_factory=plain_connection)
    elapsed = time.monotonic() - started
    assert elapsed < budget + slack, f"deadline not enforced: took {elapsed * 1000:.0f}ms for a {budget * 1000:.0f}ms budget"

    deadline = time.monotonic() + 2.0
    while live_fetch_workers() and time.monotonic() < deadline:
        time.sleep(0.02)
    assert not live_fetch_workers(), "abandoned worker survived cleanup: it still holds a socket descriptor"
    return elapsed


def test_dripped_response_headers_cannot_outlast_the_deadline():
    """getresponse() parses the status line and headers with blocking readline() loops.

    A per-socket timeout never fires while the peer drips, and no clock check placed around getresponse() is
    reached during it -- so the whole exchange runs where it can be abandoned.
    """
    script = [b"HTTP/1.1 200 OK\r\n"] + [b"X-Pad-%d: y\r\n" % i for i in range(200)]
    assert_deadline_enforced(drip_server(script))


def test_dripped_chunk_framing_cannot_outlast_the_deadline():
    """Chunked decoding reads each chunk-size line with a blocking readline(), same problem as the headers."""
    script = [b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"]
    script += [b"1", b";pad=", b"a" * 8, b"\r\n", b" ", b"\r\n"] * 50  # dripped chunk-size line with extensions
    assert_deadline_enforced(drip_server(script))


def test_cleanup_after_abandonment_cannot_itself_block():
    """ONE prolonged, never-terminated chunk-size line: the case where cleanup inherited the block.

    conn.close() calls HTTPResponse.close(), which acquires the buffered reader's lock the abandoned worker is
    still holding inside readline() -- so closing blocked for as long as the peer kept dripping. Measured before
    the fix: 21.6 s against a 150 ms budget. The short chunk-size lines in the test above terminate quickly
    enough to hide it, which is why this case is separate.
    """
    script = [b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"]
    script += [b"1;pad="] + [b"a"] * 400  # a single chunk-size line, dripped, never terminated
    assert_deadline_enforced(drip_server(script))


def test_abandonment_during_the_handshake_stops_the_request_being_sent():
    """The budget expires while the connection is still being established.

    `PinnedHTTPSConnection.connect` assigns `self.sock` only after `wrap_socket` returns, so for the whole TCP
    connect and TLS handshake there is nothing for cleanup to find. Verified before the fix: with a 250 ms
    deadline and a 400 ms handshake the caller returned at 256 ms and the worker went on to finish connecting and
    **send its request to a host the caller had already given up on**. Cancellation has to outlive the timeout.

    The other drip tests all connect instantly, so none of them can reach this window.
    """
    got_request = threading.Event()
    ready = threading.Event()
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def serve():
        ready.set()
        conn, _ = listener.accept()
        conn.settimeout(3)
        try:
            if conn.recv(4096):
                got_request.set()
        except OSError:
            pass
        finally:
            conn.close()
            listener.close()

    threading.Thread(target=serve, daemon=True).start()
    ready.wait()

    class SlowHandshake(http.client.HTTPConnection):
        """Shaped exactly like PinnedHTTPSConnection: self.sock is assigned only after the handshake completes."""
        def connect(self):
            sock = socket.create_connection((self.host, self.port), self.timeout)
            time.sleep(0.4)  # the "TLS handshake"; self.sock stays None throughout
            self.sock = sock

    started = time.monotonic()
    with pytest.raises(FetchError):
        fetch_document(URL, max_bytes=5120, timeout=0.2, deadline_seconds=0.25,
                       resolver=lambda h, p: ["93.184.216.34"],
                       connection_factory=lambda ip, host, p, t: SlowHandshake("127.0.0.1", port, timeout=t))
    assert time.monotonic() - started < 1.0

    time.sleep(0.5)  # long enough for the abandoned handshake to have completed
    assert not got_request.is_set(), "abandoned worker still sent its request to the remote host"
    assert not live_fetch_workers(), "abandoned worker survived cleanup"


@pytest.mark.parametrize("connection_header", [b"", b"Connection: close\r\n"], ids=["keep-alive", "connection-close"])
def test_abandoned_worker_is_terminated_in_both_connection_modes(connection_header):
    """`Connection: close` is the mode where cleanup lost its grip on the transport.

    On that response `getresponse()` hands the socket to the HTTPResponse and clears `conn.sock`, so cleanup that
    consults only the connection found nothing to shut down: the caller's deadline was honoured while the worker
    kept reading. Verified before the fix: the keep-alive worker terminated and the Connection: close worker was
    still blocked 400 ms after the fetch returned.
    """
    script = [b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n"
              + connection_header + b"\r\n"]
    script += [b"1;pad="] + [b"a"] * 400
    assert_deadline_enforced(drip_server(script))


def test_dripped_body_cannot_outlast_the_deadline():
    """The ordinary case: complete headers, then a Content-Length body arriving one byte at a time."""
    script = [b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 4096\r\n\r\n"]
    script += [b" "] * 200
    assert_deadline_enforced(drip_server(script))


def test_socket_timeout_is_capped_by_the_remaining_budget():
    f, made = factory_for(FakeResp(200, good_doc(), {"content-type": "application/json"}))
    fetch_document(URL, max_bytes=5120, timeout=30, deadline_seconds=2,
                   resolver=lambda h, p: ["93.184.216.34"], connection_factory=f)
    assert made["timeout"] <= 2


def test_omitted_deadline_falls_back_to_the_socket_timeout_as_the_total_budget():
    """A caller that forgets the deadline must fail safe, not unbounded."""
    f, _ = factory_for(FakeResp(200, good_doc(), {"content-type": "application/json"}))
    with pytest.raises(FetchError, match=r"wall-clock deadline|did not complete within"):
        fetch_document(URL, max_bytes=5120, timeout=-1, resolver=lambda h, p: ["93.184.216.34"], connection_factory=f)


def test_cache_seconds_bounded():
    assert cache_seconds({"cache-control": "max-age=60"}, 300, 86400) == 300
    assert cache_seconds({"cache-control": "public, max-age=7200"}, 300, 86400) == 7200
    assert cache_seconds({"cache-control": "max-age=999999"}, 300, 86400) == 86400
    assert cache_seconds({}, 300, 86400) == 300


@pytest.mark.parametrize("cc", ["no-store", "no-cache", "public, no-cache, max-age=600", "max-age=600, no-store"])
def test_no_store_and_no_cache_are_not_reusable(cc):
    assert cache_seconds({"cache-control": cc}, 300, 86400) == 0


def test_declared_port_is_used_for_resolution_connection_and_host_header():
    f, made = factory_for(FakeResp(200, good_doc().replace(b"client.example/oauth", b"client.example:8443/oauth"), {"content-type": "application/json"}))
    seen = {}
    def resolver(h, p):
        seen["port"] = p
        return ["93.184.216.34"]
    fetch_document("https://client.example:8443/oauth/meta", max_bytes=5120, timeout=3, resolver=resolver, connection_factory=f)
    assert seen["port"] == 8443 and made["port"] == 8443
    assert made["conn"].requests[0][2]["Host"] == "client.example:8443"
