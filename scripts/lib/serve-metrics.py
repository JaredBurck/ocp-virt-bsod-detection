#!/usr/bin/env python3
"""Minimal stdlib-only HTTP server for scripts/cnv-bsod-fleet-exporter.sh.

Issue K (docs/info/peer-reviews/v0.19.0/issues/gitlab-issue-drafts-open-after-
remediation.md): before this, the framework had exactly one precedent for
"turn our own script's output into a Prometheus metric"
(windows-exporter/bsod-textfile-collector.ps1), and it is guest-side, running
under windows_exporter's own textfile collector -- there was nothing
equivalent for cluster-side gate-verdict data (R-27, "continuous gate-verdict
export", was deferred with no design at all; see CHANGELOG.md's Wave 3 entry).

This is deliberately NOT a general-purpose web server: it serves exactly one
path (default /metrics) by re-reading a single file from disk on every
request, and returns 404 for anything else (including a bare "/", so a
mis-scraped ServiceMonitor path is a visible 404 in Prometheus's target list,
not a silently-empty 200). No third-party dependencies -- the exporter image
this runs in is a small, purpose-built ubi9-minimal image
(Dockerfile.gate-exporter), and pulling in a full metrics client library
for one file's worth of gauges would be disproportionate.

Concurrency note: re-reading the file per request (rather than caching) means
a request during scripts/cnv-bsod-fleet-exporter.sh's atomic write (write
to a temp file, then os.replace() into place) either sees the old complete
file or the new complete file, never a half-written one -- os.replace() is
atomic on POSIX filesystems, which is exactly why the exporter script uses it
instead of writing the metrics file in place.

Usage:
    python3 serve-metrics.py --file /var/run/bsod-metrics/metrics.prom \
        --port 8080 [--path /metrics]
"""
from __future__ import annotations

import argparse
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

# Prometheus text exposition format, https://prometheus.io/docs/instrumenting/exposition_formats/
CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"

# Security-review finding (2026-08-04), corrected by peer-review F-04
# (v0.25.0): the NetworkPolicy is this endpoint's only real access control
# (see exporter/networkpolicy.yaml) -- if it is missing or the CNI does not
# enforce it, an unbounded ThreadingHTTPServer (a new, uncapped thread per
# connection, no socket timeout) is a cheap thread/memory-exhaustion DoS
# against a 256Mi-limited pod from any other pod on the cluster.
#
# WHAT F-04 FOUND. The original mitigation acquired a BoundedSemaphore inside
# the request handler's handle() method and claimed in its comment to prevent
# "spawning an unbounded 9th, 10th, ... thread". It did no such thing.
# socketserver.ThreadingMixIn.process_request() creates and STARTS the thread,
# and only then does the thread call finish_request -> handler __init__ ->
# setup() -> handle(). By the time the semaphore was consulted the thread it
# was supposed to prevent already existed. Worse, a rejected request then sat
# blocking on the semaphore for the full socket timeout, so the "mitigation"
# EXTENDED each attacker thread's lifetime rather than shortening it, and 8
# slow connections could starve the legitimate Prometheus scrape.
#
# The cap is therefore applied at ACCEPT time now (see BoundedThreadingHTTPServer
# below), before any thread exists. Rejection is non-blocking on purpose:
# process_request() runs on the single-threaded accept loop, so waiting there
# for a slot would stall accepting every other connection -- turning a bounded
# queue into a self-inflicted outage.
#
# This remains defense-in-depth UNDER the NetworkPolicy, not a substitute for
# it. One Prometheus scraper plus one liveness/readiness probe is 2 concurrent
# connections at most in normal operation, so a small fixed cap costs nothing
# in the expected case and bounds the worst case.
MAX_CONCURRENT_REQUESTS = 8
REQUEST_SOCKET_TIMEOUT_SECONDS = 10

# Minimal, correctly-framed 503 for a connection refused before it is given a
# worker. Written directly to the socket because no handler (and therefore no
# self.wfile) exists yet at this point in the accept path.
_BUSY_BODY = b"# too many concurrent requests\n"
_BUSY_RESPONSE = (
    b"HTTP/1.1 503 Service Unavailable\r\n"
    b"Content-Type: text/plain\r\n"
    b"X-Content-Type-Options: nosniff\r\n"
    b"Retry-After: 5\r\n"
    b"Connection: close\r\n"
    b"Content-Length: " + str(len(_BUSY_BODY)).encode() + b"\r\n"
    b"\r\n" + _BUSY_BODY
)


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer with a hard ceiling on concurrent worker threads.

    The slot is taken in process_request() -- which runs BEFORE the thread is
    created -- and returned in shutdown_request(), which ThreadingMixIn's
    process_request_thread() always runs in a `finally`. That pairs exactly one
    release with one acquire.

    The rejection path deliberately does NOT call shutdown_request(): it never
    acquired a slot, and socketserver only calls shutdown_request() itself when
    process_request() RAISES (see BaseServer._handle_request_noblock), so
    returning normally here leaves the socket ours to close. Releasing a slot
    that was never taken would also raise ValueError from BoundedSemaphore --
    which is precisely the accounting bug that shape of code invites, and the
    reason the acquire/release pair is kept in these two methods only.
    """

    def __init__(self, *args, max_concurrent: int = MAX_CONCURRENT_REQUESTS,
                 **kwargs):
        self._slots = threading.BoundedSemaphore(max_concurrent)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            try:
                request.sendall(_BUSY_RESPONSE)
            except OSError:
                pass  # client already gone -- nothing left to say
            self.close_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            # The thread was never started, so shutdown_request() will not run
            # and the slot would leak. Give it back before propagating.
            self._slots.release()
            raise

    def shutdown_request(self, request):
        try:
            super().shutdown_request(request)
        finally:
            self._slots.release()


def make_handler(metrics_path: str, serve_path: str):
    class MetricsHandler(BaseHTTPRequestHandler):
        # HTTP/1.0 is the BaseHTTPRequestHandler default, but state it: it
        # means keep-alive is off, so one connection serves exactly one request
        # and a concurrency slot is held per REQUEST. Switching to HTTP/1.1
        # would silently make a slot span a whole idle-capable session, which
        # is a different (and much easier to exhaust) budget. Change this only
        # deliberately.
        protocol_version = "HTTP/1.0"

        # Bounds how long a slow/stalled client (deliberate slowloris-style
        # connection or just a bad network path) can hold this thread open
        # waiting on the request line/headers -- socketserver.StreamRequestHandler
        # applies this as connection.settimeout() in setup(), before dispatch.
        timeout = REQUEST_SOCKET_TIMEOUT_SECONDS

        # Quiet by default -- one line per scrape at the default 30s interval
        # is tolerable, but this exporter is meant to run for the life of the
        # pod, and BaseHTTPRequestHandler's default log_message writes to
        # stderr, which `oc logs` would otherwise accumulate indefinitely.
        def log_message(self, format, *args):  # noqa: A002 (stdlib signature)
            pass

        def _send(self, code: int, content_type: str, body: bytes,
                  extra_headers: tuple = ()):
            """Every response goes out through here.

            Centralised so the security headers cannot be forgotten on a new
            branch -- nosniff in particular, because these bodies are
            attacker-influenceable only in the 404 case but are served as
            text/plain to clients this server does not control.
            """
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(body)))
            for key, value in extra_headers:
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)

        def _read_metrics(self) -> bytes | None:
            try:
                with open(metrics_path, "rb") as f:
                    return f.read()
            except OSError:
                return None

        def do_GET(self):  # noqa: N802 (stdlib method name)
            # Compare only the path component, not the raw request target --
            # `self.path` includes any query string verbatim (e.g. a future
            # ServiceMonitor `params:` block, or a client appending a cache-
            # busting `?t=...`), which a plain string-equality check against
            # serve_path would silently 404 even though the request is for
            # the right resource.
            request_path = urlsplit(self.path).path
            if request_path == "/healthz":
                self._send(200, "text/plain", b"ok\n")
                return
            if request_path == serve_path:
                body = self._read_metrics()
                if body is None:
                    self._send(
                        503, "text/plain",
                        b"# metrics file not yet written by the collector loop\n")
                    return
                self._send(200, CONTENT_TYPE, body)
                return
            # F-04: the request target is deliberately NOT echoed back. It added
            # no diagnostic value the access log could not carry, and reflecting
            # client-controlled bytes into a response body is a habit worth not
            # having even where (as here) the content type makes it inert.
            self._send(404, "text/plain", b"not found\n")

    return MetricsHandler


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", required=True,
                        help="Path to the Prometheus text-format metrics file to serve")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--path", default="/metrics",
                        help="URL path to serve the metrics file on (default: /metrics)")
    args = parser.parse_args()

    handler_cls = make_handler(args.file, args.path)
    # Threaded so a stalled/slow scrape client cannot block a concurrent
    # liveness probe (or a second Prometheus replica) from being served -- each
    # request only does one file read, so there is no shared mutable state a
    # second thread could race on. Bounded (F-04) so "threaded" does not mean
    # "one thread per attacker connection".
    server = BoundedThreadingHTTPServer(("0.0.0.0", args.port), handler_cls)  # noqa: S104
    print(f"serve-metrics.py: serving {args.file!r} on 0.0.0.0:{args.port}{args.path}",
          file=sys.stderr, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
