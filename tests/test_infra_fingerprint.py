"""Tests for infra recon + fingerprinting: murmur3/favicon, ASN parsers,
behaviour probe, WAF efficacy, and TLS profiling."""

import asyncio
import http.server
import json
import socketserver
import ssl
import subprocess
import threading

import pytest

from moonmcp import server as srv
from moonmcp.context import build_context
from moonmcp.recon.favicon import favicon_hash, murmur3_32


# --- murmur3 / favicon (offline, correctness-critical) -------------------
def test_murmur3_known_vectors():
    # Canonical MurmurHash3 x86_32 vectors.
    assert murmur3_32(b"", 0) == 0
    assert murmur3_32(b"", 1) == 1364076727  # 0x514E28B7
    # Determinism.
    assert murmur3_32(b"moonmcp", 0) == murmur3_32(b"moonmcp", 0)


def test_favicon_hash_is_signed_int_and_stable():
    h = favicon_hash(b"\x89PNG\r\n\x1a\n" + b"icon-bytes" * 20)
    assert isinstance(h, int)
    assert -(2**31) <= h < 2**31
    assert favicon_hash(b"same") == favicon_hash(b"same")


# --- ASN / ip_intel parser (offline via fake client) --------------------
class _FakeResp:
    def __init__(self, body, status=200):
        self._b = body.encode() if isinstance(body, str) else body
        self.status = status
        self.error = None
        self.body = self._b

    def text(self, limit=None):
        return self._b.decode()


class _FakeClient:
    def __init__(self, body, status=200):
        self._resp = _FakeResp(body, status)

    async def fetch(self, url, **kw):
        return self._resp


def test_ip_intel_parses_and_detects_cloud():
    from moonmcp.intel.asn import ip_intel

    body = json.dumps({
        "status": "success", "country": "United States", "city": "Ashburn",
        "isp": "Amazon.com", "org": "AWS EC2", "as": "AS16509 Amazon.com, Inc.",
        "asname": "AMAZON-02", "reverse": "ec2-1-2-3-4.compute.amazonaws.com",
        "hosting": True, "query": "1.2.3.4",
    })
    r = asyncio.run(ip_intel(_FakeClient(body), "1.2.3.4"))
    assert r.asn == "AS16509"
    assert r.cloud == "AWS"
    assert r.is_hosting is True
    assert r.country == "United States"


def test_ip_intel_rejects_hostname():
    from moonmcp.intel.asn import ip_intel

    r = asyncio.run(ip_intel(_FakeClient("{}"), "example.com"))
    assert r.error and "IP address" in r.error


def test_reverse_ip_parses_domain_list():
    from moonmcp.intel.asn import reverse_ip

    r = asyncio.run(reverse_ip(_FakeClient("a.example\nb.example\nc.example\n"), "1.2.3.4"))
    assert r.count == 3
    assert "a.example" in r.domains


# --- behaviour + WAF efficacy (local server integration) ----------------
class _BehaviorHandler(http.server.BaseHTTPRequestHandler):
    server_version = "TestSrv"

    def log_message(self, *a):
        pass

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, POST, OPTIONS")
        self.end_headers()

    def do_GET(self):
        # Reflect Host header (host-header injection signal)
        host = self.headers.get("Host", "")
        xfh = self.headers.get("X-Forwarded-Host", "")
        # WAF: block obvious attack markers with 403
        if any(tok in self.path.lower() for tok in ("<script>", "script", "or ", "etc/passwd", "%00", "{{")):
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"Request blocked by security policy")
            return
        if "does-not-exist" in self.path:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"<html><body>Custom 404 page not found here friend</body></html>" + b"x" * 300)
            return
        body = f"<html><body>home host={host} xfh={xfh}</body></html>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def behavior_server():
    httpd = socketserver.TCPServer(("127.0.0.1", 0), _BehaviorHandler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        httpd.shutdown()


@pytest.fixture()
def infra_ctx(monkeypatch):
    ctx = build_context()
    ctx.scope.block_private = False
    ctx.scope.add("127.0.0.1")
    monkeypatch.setattr(srv, "_CTX", ctx)
    return ctx


@pytest.mark.asyncio
async def test_behavior_probe_detects_reflection_and_404(behavior_server, infra_ctx):
    res = await srv.behavior_probe(target=behavior_server)
    assert res.get("host_header_reflected") is True
    assert res.get("xforwarded_host_reflected") is True
    assert res.get("custom_404") is True
    assert "GET" in res.get("allowed_methods", [])


@pytest.mark.asyncio
async def test_waf_efficacy_reports_protection(behavior_server, infra_ctx):
    res = await srv.waf_efficacy(target=behavior_server)
    # The test server blocks the attack markers, so several categories are protected.
    assert res.get("protected_categories")
    assert "xss" in res.get("protected_categories", []) or "sqli" in res.get("protected_categories", [])


# --- TLS fingerprint (local TLS server) ---------------------------------
def _make_selfsigned(certfile, keyfile):
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", keyfile,
         "-out", certfile, "-days", "1", "-nodes", "-subj", "/CN=localhost"],
        check=True, capture_output=True,
    )


@pytest.mark.asyncio
async def test_tls_fingerprint_against_local_server(tmp_path, infra_ctx):
    if not _have_openssl():
        pytest.skip("openssl not available")
    cert = str(tmp_path / "c.pem")
    key = str(tmp_path / "k.pem")
    _make_selfsigned(cert, key)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    ctx.set_alpn_protocols(["h2", "http/1.1"])

    srv_sock = socketserver.TCPServer(("127.0.0.1", 0), None)
    port = srv_sock.server_address[1]
    srv_sock.server_close()

    import socket
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(10)
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                listener.settimeout(0.5)
                conn, _ = listener.accept()
            except (OSError, TimeoutError):
                continue
            try:
                tls = ctx.wrap_socket(conn, server_side=True)
                tls.close()
            except (ssl.SSLError, OSError):
                try:
                    conn.close()
                except OSError:
                    pass

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    try:
        res = await srv.tls_fingerprint(target=f"127.0.0.1:{port}")
        assert res.get("supported_versions"), res
        assert any(v.startswith("TLSv1.2") or v.startswith("TLSv1.3")
                   for v in res.get("supported_versions", []))
    finally:
        stop.set()
        listener.close()


def _have_openssl():
    try:
        subprocess.run(["openssl", "version"], check=True, capture_output=True)
        return True
    except (OSError, subprocess.CalledProcessError):
        return False


@pytest.mark.asyncio
async def test_new_infra_tools_registered():
    tools = {t.name for t in await srv.mcp.list_tools()}
    for name in ("ip_intel", "reverse_ip", "origin_discovery", "favicon_hash",
                 "tls_fingerprint", "behavior_probe", "waf_efficacy"):
        assert name in tools
