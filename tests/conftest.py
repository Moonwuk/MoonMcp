import http.server
import socketserver
import threading

import pytest

from moonmcp import server as srv
from moonmcp.context import build_context


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):  # silence
        pass

    def do_GET(self):
        if self.path == "/echo":
            # Echo the request headers back as JSON (used to verify auth context).
            import json as _json
            payload = _json.dumps({k.lower(): v for k, v in self.headers.items()}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(payload)
            return
        if self.path == "/robots.txt":
            body = b"User-agent: *\nDisallow: /admin\nDisallow: /secret\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/only-secret":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
            return
        if self.path == "/redirect-out":
            # Redirect to an out-of-scope host — MoonMCP must refuse to follow.
            self.send_response(302)
            self.send_header("Location", "http://evil.example/pwned")
            self.end_headers()
            return
        if self.path.rstrip("/") in ("/admin",):
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"forbidden")
            return
        if self.path == "/missing":
            self.send_response(404)
            self.end_headers()
            return
        body = b"<html><head><title>Local</title></head><body>hello react-root</body></html>"
        self.send_response(200)
        self.send_header("Server", "nginx/1.25.1")
        self.send_header("X-Powered-By", "Express")
        self.send_header("Set-Cookie", "sid=1; Path=/")
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def local_server():
    httpd = socketserver.TCPServer(("127.0.0.1", 0), _Handler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}", port
    finally:
        httpd.shutdown()


@pytest.fixture()
def fresh_context(monkeypatch):
    """Give the server module a fresh, in-scope context for 127.0.0.1."""

    ctx = build_context()
    # Local-server tests target 127.0.0.1, so disable the private-IP SSRF guard.
    ctx.scope.block_private = False
    ctx.scope.add("127.0.0.1")
    monkeypatch.setattr(srv, "_CTX", ctx)
    return ctx
