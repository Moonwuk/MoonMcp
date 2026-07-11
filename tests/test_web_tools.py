"""Tests for the web-app recon tools (offline + local-server integration)."""

import base64
import http.server
import json
import socketserver
import threading

import pytest

from moonmcp import server as srv
from moonmcp.context import build_context
from moonmcp.recon.secrets import scan_text
from moonmcp.web.jwt import analyze_jwt


# --- offline: JWT --------------------------------------------------------
def _mk_jwt(header, payload, sig="abc"):
    def enc(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{enc(header)}.{enc(payload)}.{sig}"


def test_jwt_alg_none_flagged():
    tok = _mk_jwt({"alg": "none", "typ": "JWT"}, {"sub": "1"}, sig="")
    a = analyze_jwt(tok)
    assert a.valid_structure
    assert a.algorithm == "none"
    assert any("alg=none" in i for i in a.issues)


def test_jwt_hs256_and_missing_exp():
    tok = _mk_jwt({"alg": "HS256"}, {"sub": "1"})
    a = analyze_jwt(tok)
    assert any("symmetric" in i for i in a.issues)
    assert any("exp" in i for i in a.issues)


def test_jwt_expired_with_clock():
    tok = _mk_jwt({"alg": "RS256"}, {"exp": 1000})
    a = analyze_jwt(tok, now_epoch=2000)
    assert any("EXPIRED" in i for i in a.issues)


def test_jwt_invalid():
    assert analyze_jwt("not-a-jwt").valid_structure is False


def test_jwt_non_object_segments_do_not_crash():
    # header decodes to a JSON array [], payload to {} — must not raise.
    a = analyze_jwt("W10.e30.x")
    assert a.valid_structure is False
    assert "JSON objects" in (a.error or "")


def test_jwt_null_alg_not_reported_as_none():
    tok = _mk_jwt({"alg": None}, {"sub": "1"})
    a = analyze_jwt(tok)
    assert a.algorithm is None
    assert not any("alg=none" in i for i in a.issues)


# --- offline: secret scanning -------------------------------------------
def test_secret_scan_detects_high_signal():
    text = (
        'aws_key="AKIAIOSFODNN7EXAMPLE" '
        'gh = "ghp_' + "a" * 36 + '" '
        'stripe="sk_live_' + "a" * 30 + '"'
    )
    hits = scan_text(text, source="t")
    types = {h.type for h in hits}
    assert "AWS Access Key ID" in types
    assert "GitHub PAT" in types
    assert "Stripe Secret Key" in types
    # values are redacted
    assert all("EXAMPLE" not in h.redacted or "…" in h.redacted for h in hits)


def test_secret_scan_filters_placeholders():
    text = 'api_key = "your_api_key_here"\npassword = "changeme"'
    hits = scan_text(text)
    assert hits == []  # placeholders filtered by the generic high-FP gate


def test_secret_scan_ignores_asset_filename_hash():
    h = "a" * 32
    # a Mailgun-shaped token that is really a cache-busting filename hash → suppressed…
    assert scan_text(f'<script src="/assets/key-{h}.js"></script>') == []
    # …but the same token NOT followed by an asset extension is still reported.
    assert any(x.type == "Mailgun Key" for x in scan_text(f'MAILGUN="key-{h}"'))


# --- local server integration -------------------------------------------
class _WebHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body=b"", headers=None):
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_OPTIONS(self):
        self._send(200, headers={"Allow": "GET, POST, OPTIONS, PUT"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        _ = self.rfile.read(length)
        if self.path == "/graphql":
            self._send(200, json.dumps({
                "data": {"__typename": "Query", "__schema": {
                    "queryType": {"name": "Query"},
                    "types": [{"name": "Query", "kind": "OBJECT"}, {"name": "User", "kind": "OBJECT"}],
                }}
            }).encode(), {"Content-Type": "application/json"})
            return
        self._send(404)

    def do_GET(self):
        # Exposed .git artefacts
        if self.path == "/.git/HEAD":
            self._send(200, b"ref: refs/heads/main\n", {"Content-Type": "text/plain"})
            return
        if self.path == "/.git/config":
            self._send(200, b"[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://github.com/acme/secret.git\n",
                       {"Content-Type": "text/plain"})
            return
        # Open redirect: bounce to whatever ?next=/?url= says
        from urllib.parse import parse_qs, urlsplit
        qs = parse_qs(urlsplit(self.path).query)
        target = (qs.get("next") or qs.get("url") or [None])[0]
        if target:
            self._send(302, b"", {"Location": target})
            return
        origin = self.headers.get("Origin")
        headers = {"Server": "cloudflare", "Content-Type": "text/html"}
        if origin:  # reflect the origin (misconfiguration)
            headers["Access-Control-Allow-Origin"] = origin
            headers["Access-Control-Allow-Credentials"] = "true"
        body = (
            b"<html><head><title>T</title></head><body>"
            b'<a href="/about?id=1">a</a><a href="https://ext.example/x">e</a>'
            b'<form action="/login" method="post"><input name="user"><input name="pw"></form>'
            b'<script src="/app.js"></script></body></html>'
        )
        self._send(200, body, headers)


@pytest.fixture()
def web_server():
    httpd = socketserver.TCPServer(("127.0.0.1", 0), _WebHandler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        httpd.shutdown()


@pytest.fixture()
def web_ctx(monkeypatch):
    ctx = build_context()
    ctx.scope.block_private = False
    ctx.scope.add("127.0.0.1")
    monkeypatch.setattr(srv, "_CTX", ctx)
    return ctx


@pytest.mark.asyncio
async def test_cors_audit_flags_reflection(web_server, web_ctx):
    res = await srv.cors_audit(target=web_server)
    assert res.get("reflects_arbitrary_origin") is True
    assert res.get("allows_credentials") is True
    assert any(f["severity"] == "high" for f in res.get("findings", []))


@pytest.mark.asyncio
async def test_graphql_introspection(web_server, web_ctx):
    res = await srv.graphql_check(target=web_server)
    eps = res.get("endpoints", [])
    assert any(e["url"].endswith("/graphql") and e.get("introspection_enabled") for e in eps)


@pytest.mark.asyncio
async def test_http_methods_allow(web_server, web_ctx):
    res = await srv.http_methods(target=web_server)
    assert "PUT" in res.get("allow_header", [])


@pytest.mark.asyncio
async def test_crawl_extracts_surface(web_server, web_ctx):
    res = await srv.crawl(target=web_server)
    assert "user" in res.get("parameters", []) or "id" in res.get("parameters", [])
    assert any("ext.example" in h for h in res.get("external_hosts", []))
    assert any(f["action"].endswith("/login") for f in res.get("forms", []))


@pytest.mark.asyncio
async def test_waf_detect_cloudflare(web_server, web_ctx):
    res = await srv.waf_detect(target=web_server)
    assert "Cloudflare" in res.get("detected", [])


@pytest.mark.asyncio
async def test_open_redirect_detected(web_server, web_ctx):
    res = await srv.open_redirect(target=web_server)
    assert res.get("vulnerable") is True
    assert any(f["parameter"] in ("next", "url") for f in res.get("findings", []))


@pytest.mark.asyncio
async def test_vcs_exposure_confirms_git(web_server, web_ctx):
    res = await srv.vcs_exposure(target=web_server)
    assert res.get("git_exposed") is True
    assert res.get("git_remote", "").endswith("secret.git")


@pytest.mark.asyncio
async def test_screenshot_degrades_without_playwright(web_server, web_ctx):
    # Playwright is not a hard dependency; the tool must degrade, not crash.
    from moonmcp.web.screenshot import playwright_available
    res = await srv.screenshot(target=web_server)
    if playwright_available():
        assert "available" in res
    else:
        assert res["available"] is False
        assert "install_hint" in res


@pytest.mark.asyncio
async def test_new_tools_registered():
    tools = {t.name for t in await srv.mcp.list_tools()}
    for name in ("crawl", "extract_secrets", "cors_audit", "graphql_check",
                 "waf_detect", "takeover_check", "email_security", "jwt_analyze",
                 "http_methods", "open_redirect", "vcs_exposure", "screenshot", "report",
                 "analyze_binary"):
        assert name in tools
