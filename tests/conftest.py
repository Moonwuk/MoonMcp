import http.server
import socketserver
import threading

import pytest

from moonmcp import server as srv
from moonmcp.context import build_context


class _Handler(http.server.BaseHTTPRequestHandler):
    _lb = 0   # /lb backend rotation counter
    _rl = 0   # /rl rate-limit counter

    def log_message(self, *args):  # silence
        pass

    def _nosqli_reply(self, text: str, ctype: str):
        # DELIBERATELY VULNERABLE login: a plain scalar `user` is denied (401), but
        # an operator OBJECT ($ne/$gt/$nin, or $where returning true) bypasses auth
        # (200 + a session cookie + a longer "records" body). $where:false stays 401,
        # giving the boolean oracle its differential.
        from urllib.parse import parse_qs
        operator = where_false = False
        if "json" in ctype:
            import json as _json
            try:
                v = _json.loads(text).get("user")
            except Exception:
                v = None
            if isinstance(v, dict):
                where_false = v.get("$where") == "return false"
                operator = not where_false
        else:
            operator = any("[$" in k for k in parse_qs(text))
        if operator and not where_false:
            body = (b"<html>welcome admin! records: alice bob carol dave "
                    b"erin frank grace heidi ivan</html>")
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Set-Cookie", "session=itsme; Path=/; HttpOnly")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            body = b"<html>invalid credentials</html>"
            self.send_response(401)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def do_POST(self):
        # drain the request body so the socket stays clean
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if self.path.startswith("/nosqli-safe"):
            # NOT vulnerable: identical 200 regardless of operator vs scalar.
            body = b"<html>login page</html>"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/nosqli"):
            self._nosqli_reply(raw.decode("utf-8", "replace"),
                               self.headers.get("Content-Type", ""))
            return
        self.send_response(404)
        self.end_headers()

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
        if self.path.startswith("/reflect"):
            # Reflect the value of ?name= into the body (reflected-param signal) and
            # add a chunk of text when ?admin is present (length-change signal).
            from urllib.parse import parse_qs, urlparse
            qs = parse_qs(urlparse(self.path).query)
            body = b"<html>base"
            if "name" in qs:
                body += b" name=" + qs["name"][0].encode("utf-8", "replace")
            if "admin" in qs:
                body += b" ADMIN-PANEL-VISIBLE-EXTRA-CONTENT-BLOCK-XYZ"
            body += b"</html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/ssti"):
            # DELIBERATELY VULNERABLE (eval target): "renders" a Jinja2-style
            # {{7331*7}} expression by echoing the evaluated result.
            from urllib.parse import parse_qs, urlparse
            name = (parse_qs(urlparse(self.path).query).get("name") or [""])[0]
            out = name.replace("{{7331*7}}", "51317") if "{{" in name else name
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"<html>hello " + out.encode("utf-8", "replace") + b"</html>")
            return
        if self.path.startswith("/sqli"):
            # DELIBERATELY VULNERABLE: a single quote yields a MySQL error; the
            # boolean pair yields different-length bodies.
            from urllib.parse import parse_qs, urlparse
            q = (parse_qs(urlparse(self.path).query).get("q") or [""])[0]
            if "'" in q and "'1'='1" not in q and "'1'='2" not in q:
                body = b"Database error: You have an error in your SQL syntax; check the MySQL manual"
            elif "'1'='1" in q:
                body = b"<html>results: alice bob carol dave erin frank grace</html>"
            else:
                body = b"<html>results:</html>"
            self.send_response(200)
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/ssrf"):
            # DELIBERATELY VULNERABLE: fetches the ?url= param server-side.
            from urllib.parse import parse_qs, urlparse
            url = (parse_qs(urlparse(self.path).query).get("url") or [""])[0]
            if url.startswith("http://") or url.startswith("https://"):
                try:
                    import urllib.request
                    urllib.request.urlopen(url, timeout=2).read(64)
                except Exception:
                    pass
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"<html>fetched</html>")
            return
        if self.path.startswith("/cache"):
            # DELIBERATELY VULNERABLE: reflects the unkeyed X-Forwarded-Host header
            # and marks the response cacheable.
            xfh = self.headers.get("X-Forwarded-Host", "")
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Cache-Control", "public, max-age=60")
            self.end_headers()
            self.wfile.write(b"<html><link href='//" + xfh.encode("utf-8", "replace")
                             + b"/style.css'></html>")
            return
        if self.path.startswith("/lb"):
            # Two backends behind an LB with a Server-version mismatch (patch drift).
            type(self)._lb += 1
            if type(self)._lb % 2 == 0:
                server_hdr, backend = "nginx/1.24.0", "node-a"
            else:
                server_hdr, backend = "nginx/1.25.1", "node-b"
            # send_response_only avoids the handler's default Server header so our
            # injected version is the authoritative one.
            self.send_response_only(200)
            self.send_header("Server", server_hdr)
            self.send_header("X-Backend-Server", backend)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
            return
        if self.path.startswith("/vhost"):
            # Serves the same app for any Host AND reflects it into a link.
            host = self.headers.get("Host", "")
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><a href='//" + host.encode("utf-8", "replace")
                             + b"/next'>go</a></html>")
            return
        if self.path.startswith("/edge"):
            # Looks like it sits behind Cloudflare with a cache layer.
            self.send_response_only(200)
            self.send_header("Server", "cloudflare")
            self.send_header("CF-RAY", "8a1b2c3d4e5f-FRA")
            self.send_header("CF-Cache-Status", "HIT")
            self.send_header("Via", "1.1 varnish, 1.1 cloudflare")
            self.send_header("Age", "42")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
            return
        if self.path.startswith("/rl"):
            # Rate limit that keys on the (spoofable) X-Forwarded-For header.
            if self.headers.get("X-Forwarded-For"):
                type(self)._rl = 0  # per-IP bypass
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")
                return
            type(self)._rl += 1
            if type(self)._rl > 5:
                self.send_response(429)
                self.send_header("Retry-After", "30")
                self.end_headers()
                self.wfile.write(b"slow down")
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
            return
        if self.path == "/spa":
            body = (b"<html><head><script src=\"/static/app.js\"></script></head>"
                    b"<body><script>fetch('/api/v2/users');var u='/api/v2/orders';"
                    b"</script></body></html>")
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/static/app.js":
            body = (b"const base='/api/internal/config';"
                    b"fetch('/api/v1/admin/users?id=1');\n"
                    b"//# sourceMappingURL=app.js.map\n")
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/openapi.json":
            import json as _json
            spec = {
                "openapi": "3.0.0",
                "info": {"title": "Demo API", "version": "1.2.3"},
                "servers": [{"url": "https://api.demo.test/v1"}],
                "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
                "security": [{"bearer": []}],
                "paths": {
                    "/users/{id}": {
                        "get": {"operationId": "getUser",
                                "parameters": [{"name": "id", "in": "path", "required": True,
                                                "schema": {"type": "integer"}}]},
                        "delete": {"operationId": "delUser", "security": []},
                    },
                    "/public/health": {"get": {"operationId": "health", "security": []}},
                },
            }
            payload = _json.dumps(spec).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(payload)
            return
        if self.path == "/app":
            # A tiny interactive page: fill #q, click #go → writes #out + localStorage.
            body = (
                b"<title>App</title><input id='q'>"
                b"<button id='go' onclick=\"document.getElementById('out').innerText="
                b"'clicked:'+document.getElementById('q').value;"
                b"localStorage.setItem('token','t0ken');console.log('go-clicked')\">Go</button>"
                b"<div id='out'></div>"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)
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
        if self.path in ("/r1", "/r2"):
            # A same-host redirect chain: /r1 -> /r2 -> / (all in scope).
            self.send_response(302)
            self.send_header("Location", "/r2" if self.path == "/r1" else "/")
            self.end_headers()
            return
        if self.path.startswith("/bucket"):
            # Mock cloud-bucket endpoint: 200 for 'acme-backup', 403 for
            # 'acme-private', 404 otherwise — to test status classification.
            from urllib.parse import parse_qs, urlparse
            name = (parse_qs(urlparse(self.path).query).get("name") or [""])[0]
            code = 200 if name == "acme-backup" else 403 if name == "acme-private" else 404
            self.send_response(code)
            self.end_headers()
            return
        if self.path.startswith("/oast-poll"):
            # A mock OAST poll endpoint returning one interaction.
            from urllib.parse import parse_qs, urlparse
            tok = (parse_qs(urlparse(self.path).query).get("token") or [""])[0]
            payload = ('{"interactions":[{"protocol":"http","from":"203.0.113.9","token":"'
                       + tok + '"}]}').encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(payload)
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
