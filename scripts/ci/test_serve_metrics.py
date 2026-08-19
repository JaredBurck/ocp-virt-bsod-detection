"""Tests for scripts/lib/serve-metrics.py.

Peer-review finding F-04 (v0.25.0): this module shipped with a security-review
comment claiming its BoundedSemaphore prevented "spawning an unbounded 9th,
10th, ... thread". It did not. socketserver.ThreadingMixIn.process_request()
creates and starts the thread, and only then does the thread reach the
handler's handle() where the semaphore was acquired -- so the thread the cap
was meant to prevent already existed, and a rejected request then blocked on
the semaphore for the full socket timeout, EXTENDING its lifetime.

The module had no test file at all, which is why a mitigation that did not do
what its comment said went unnoticed. These tests pin the corrected behaviour,
and in particular assert the property the old code could not satisfy: that
excess connections do not create worker threads.
"""
from __future__ import annotations

import http.client
import importlib.util
import socket
import threading
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "scripts" / "lib" / "serve-metrics.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("serve_metrics", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sm = _load_module()


@pytest.fixture
def metrics_file(tmp_path):
    f = tmp_path / "metrics.prom"
    f.write_text("# HELP bsod_test gauge\nbsod_test 1\n")
    return f


@pytest.fixture
def server(metrics_file):
    """A real server on an ephemeral port, torn down after each test."""
    handler = sm.make_handler(str(metrics_file), "/metrics")
    srv = sm.BoundedThreadingHTTPServer(("127.0.0.1", 0), handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv
    srv.shutdown()
    srv.server_close()
    t.join(timeout=5)


def _get(server, path):
    conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1],
                                      timeout=5)
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        return resp.status, resp.read(), dict(resp.getheaders())
    finally:
        conn.close()


class TestRouting:
    def test_metrics_path_serves_the_file(self, server, metrics_file):
        status, body, _ = _get(server, "/metrics")
        assert status == 200
        assert body == metrics_file.read_bytes()

    def test_query_string_still_matches_the_path(self, server):
        """A ServiceMonitor `params:` block or cache-buster must not 404."""
        status, _, _ = _get(server, "/metrics?cachebust=1")
        assert status == 200

    def test_healthz(self, server):
        status, body, _ = _get(server, "/healthz")
        assert status == 200
        assert body == b"ok\n"

    def test_unknown_path_404s(self, server):
        """A bare "/" must 404 so a mis-scraped path is visible in Prometheus's
        target list rather than a silently-empty 200."""
        assert _get(server, "/")[0] == 404

    def test_missing_metrics_file_is_503_not_200(self, server, metrics_file):
        """An empty scrape must never look like a successful one."""
        metrics_file.unlink()
        status, body, _ = _get(server, "/metrics")
        assert status == 503
        assert b"not yet written" in body


class TestResponseHeaders:
    def test_nosniff_on_success(self, server):
        assert _get(server, "/metrics")[2].get("X-Content-Type-Options") == "nosniff"

    @pytest.mark.parametrize("path", ["/", "/healthz", "/nope"])
    def test_nosniff_on_every_path(self, server, path):
        assert _get(server, path)[2].get("X-Content-Type-Options") == "nosniff"

    def test_prometheus_content_type(self, server):
        headers = _get(server, "/metrics")[2]
        assert headers["Content-Type"] == sm.CONTENT_TYPE

    def test_404_does_not_reflect_the_request_target(self, server):
        """F-04: client-controlled bytes are not echoed into the body."""
        status, body, _ = _get(server, "/<script>alert(1)</script>")
        assert status == 404
        assert b"script" not in body
        assert body == b"not found\n"


class TestConcurrencyBound:
    def test_slot_is_taken_before_the_thread_exists(self, metrics_file):
        """The core F-04 assertion.

        The old code acquired its semaphore inside handle(), by which point
        ThreadingMixIn had already created the thread. Here process_request()
        must consume a slot BEFORE delegating to the threading layer, so a
        server with zero free slots creates no worker thread at all.
        """
        handler = sm.make_handler(str(metrics_file), "/metrics")
        srv = sm.BoundedThreadingHTTPServer(("127.0.0.1", 0), handler,
                                            max_concurrent=1)
        try:
            spawned = []
            original = sm.ThreadingHTTPServer.process_request

            def spy(self, request, client_address):
                spawned.append(1)
                return original(self, request, client_address)

            sm.ThreadingHTTPServer.process_request = spy
            try:
                # Exhaust the single slot without ever releasing it.
                assert srv._slots.acquire(blocking=False) is True
                client, server_side = socket.socketpair()
                try:
                    srv.process_request(server_side, ("127.0.0.1", 1234))
                    # No thread was created...
                    assert spawned == []
                    # ...and the caller got a 503 rather than a hang.
                    client.settimeout(5)
                    assert b"503" in client.recv(4096)
                finally:
                    client.close()
            finally:
                sm.ThreadingHTTPServer.process_request = original
        finally:
            srv.server_close()

    def test_slots_are_returned_after_each_request(self, server):
        """Sequential scrapes must not leak the budget.

        A release that did not pair with its acquire would exhaust the cap
        after MAX_CONCURRENT_REQUESTS scrapes and start 503-ing Prometheus --
        an outage caused by the mitigation itself.
        """
        for _ in range(sm.MAX_CONCURRENT_REQUESTS * 3):
            assert _get(server, "/metrics")[0] == 200

    def test_bounded_semaphore_would_catch_an_over_release(self, metrics_file):
        """Why BoundedSemaphore and not Semaphore.

        An unpaired release is an accounting bug that would silently RAISE the
        ceiling. BoundedSemaphore turns it into an immediate error instead.
        """
        handler = sm.make_handler(str(metrics_file), "/metrics")
        srv = sm.BoundedThreadingHTTPServer(("127.0.0.1", 0), handler,
                                            max_concurrent=2)
        try:
            with pytest.raises(ValueError):
                srv._slots.release()
        finally:
            srv.server_close()

    def test_concurrent_requests_all_succeed_under_the_cap(self, server):
        """Normal operation (one scraper + probes) must not be throttled."""
        results = []
        lock = threading.Lock()

        def worker():
            status = _get(server, "/metrics")[0]
            with lock:
                results.append(status)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)
        assert results == [200] * 4


class TestHandlerContract:
    def test_protocol_version_is_pinned(self):
        """A slot is held per REQUEST only while keep-alive is off.

        Switching to HTTP/1.1 would make one slot span a whole idle-capable
        session -- a much easier budget to exhaust. Pinned so the change has
        to be deliberate.
        """
        handler = sm.make_handler("/nonexistent", "/metrics")
        assert handler.protocol_version == "HTTP/1.0"

    def test_socket_timeout_is_set(self):
        """Bounds how long a slowloris client can hold a worker."""
        handler = sm.make_handler("/nonexistent", "/metrics")
        assert handler.timeout == sm.REQUEST_SOCKET_TIMEOUT_SECONDS
