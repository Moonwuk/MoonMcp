"""A tiny built-in OAST callback catcher (stdlib only).

The strongest confirmation signal for a *blind* vulnerability is an out-of-band
callback — but that normally means depending on a third party (interactsh,
Burp Collaborator). This is a self-hosted alternative: a threaded HTTP listener
that records every request it receives, keyed by the correlation **token**
embedded in the request (path segment, ``?token=`` query, or a host sub-label).

**Reachability caveat:** the target must be able to reach this listener, so it is
for engagements where that holds — you run MoonMCP on a host the target can call
(a public IP, or an internal/authorised network), or you tunnel the port. For
external-only targets with no reachable address, keep using a public interactsh.
"""

from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

_MAX = 2000  # ring-buffer cap on recorded interactions


def _extract_token(path: str, host: str) -> str:
    """Pull the correlation token from the path (/<tok>/…), ``?token=`` or the
    first host label (<tok>.domain)."""

    sp = urlsplit(path)
    seg = sp.path.strip("/").split("/", 1)[0]
    if seg:
        return seg.lower()
    qs = parse_qs(sp.query)
    if qs.get("token"):
        return qs["token"][0].lower()
    label = (host or "").split(":", 1)[0].split(".", 1)[0]
    return label.lower()


class CallbackServer:
    """A threaded HTTP callback collector recording interactions by token."""

    def __init__(self, host: str = "0.0.0.0", port: int = 0,
                 advertise_host: str | None = None) -> None:
        self._host = host
        self._want_port = port
        self._advertise = advertise_host or (host if host not in ("0.0.0.0", "") else "127.0.0.1")
        self._interactions: list[dict] = []
        self._lock = threading.Lock()
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._port = port

    def start(self) -> None:
        server = self

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):  # silence
                pass

            def _record(self, method: str) -> None:
                host = self.headers.get("Host", "")
                body = b""
                try:
                    n = int(self.headers.get("Content-Length", 0) or 0)
                    if 0 < n <= 8192:
                        body = self.rfile.read(n)
                except (ValueError, OSError):
                    body = b""
                server.record({
                    "protocol": "http",
                    "method": method,
                    "path": self.path,
                    "token": _extract_token(self.path, host),
                    "remote_addr": self.client_address[0],
                    "host": host,
                    "user_agent": self.headers.get("User-Agent", ""),
                    "body": body.decode("utf-8", "replace")[:512],
                    "at": time.time(),
                })
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"ok")

            def do_GET(self):
                self._record("GET")

            def do_POST(self):
                self._record("POST")

            def do_PUT(self):
                self._record("PUT")

            def do_HEAD(self):
                self._record("HEAD")

        self._httpd = ThreadingHTTPServer((self._host, self._want_port), _Handler)
        self._port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    @property
    def port(self) -> int:
        return self._port

    @property
    def running(self) -> bool:
        return self._httpd is not None

    def base(self) -> str:
        """The ``host:port`` to advertise in canary URLs."""
        return f"{self._advertise}:{self._port}"

    def record(self, interaction: dict) -> None:
        with self._lock:
            self._interactions.append(interaction)
            if len(self._interactions) > _MAX:
                self._interactions = self._interactions[-_MAX:]

    def interactions(self, token: str | None = None) -> list[dict]:
        with self._lock:
            if not token:
                return list(self._interactions)
            t = token.strip().lower()
            return [i for i in self._interactions if i.get("token") == t]

    def stop(self) -> None:
        if self._httpd is not None:
            try:
                self._httpd.shutdown()
                self._httpd.server_close()
            except Exception:
                pass
            self._httpd = None
