import http.server
import socketserver
import threading

import pytest

from moonmcp import server as srv
from moonmcp.context import build_context
from moonmcp.findings import FindingsStore
from moonmcp.web.desync import _status_of


# --- findings store (offline) -------------------------------------------
def test_findings_store_add_list_clear_summary():
    s = FindingsStore()
    s.add(target="a.example", severity="low", title="l")
    s.add(target="a.example", severity="critical", title="c")
    s.add(target="b.example", severity="high", title="h")
    # severity-ranked: critical before high before low
    titles = [f.title for f in s.list()]
    assert titles[0] == "c"
    assert s.list(target="a.example")[0].severity == "critical"
    assert s.list(severity="high")[0].title == "h"
    summ = s.summary()
    assert summ["total"] == 3
    assert summ["by_severity"]["critical"] == 1
    assert s.clear(target="a.example") == 2
    assert s.summary()["total"] == 1


def test_findings_invalid_severity_defaults_info():
    s = FindingsStore()
    f = s.add(target="x", severity="bogus", title="t")
    assert f.severity == "info"


@pytest.mark.asyncio
async def test_findings_tools_roundtrip():
    ctx = build_context()
    srv._CTX = ctx
    try:
        await srv.add_finding(target="x.example", severity="high", title="XSS", detail="reflected")
        listing = await srv.list_findings()
        assert listing["summary"]["total"] == 1
        assert listing["findings"][0]["title"] == "XSS"
        cleared = await srv.clear_findings()
        assert cleared["removed"] == 1
    finally:
        srv._CTX = None


# --- desync status parser (offline) -------------------------------------
def test_status_parser():
    assert _status_of(b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n") == (200, "nginx")
    assert _status_of(b"HTTP/1.1 403 Forbidden\r\n\r\n")[0] == 403
    assert _status_of(b"garbage")[0] is None


# --- desync probe (local raw HTTP server) -------------------------------
class _H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        # Reject ambiguous CL+TE framing with 400 (well-behaved server).
        if self.headers.get("Transfer-Encoding") and self.headers.get("Content-Length"):
            self.send_response(400)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Server", "TestSrv")
        self.end_headers()
        self.wfile.write(b"ok")


@pytest.fixture()
def raw_server():
    httpd = socketserver.TCPServer(("127.0.0.1", 0), _H)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        httpd.shutdown()


@pytest.fixture()
def ctx_fixture(monkeypatch):
    ctx = build_context()
    ctx.scope.block_private = False
    ctx.scope.add("127.0.0.1")
    monkeypatch.setattr(srv, "_CTX", ctx)
    return ctx


@pytest.mark.asyncio
async def test_desync_probe_baseline_and_framing(raw_server, ctx_fixture):
    res = await srv.desync_probe(target=raw_server)
    assert res.get("baseline_status") == 200
    probes = res.get("probes", {})
    # The well-behaved server rejects the ambiguous CL+TE request.
    assert probes.get("cl.te-dual") == 400
    assert {"te-tab", "te-space-before-colon", "te-nameprefix"} <= set(probes)
    assert res.get("risk") in ("low", "review")
    # The naive stdlib server ignores obfuscated TE (serves 200), which the probe
    # correctly surfaces as a review indicator — no CL.TE-dual false positive.
    assert not any("both Content-Length" in i for i in res.get("indicators", []))


def test_interpret_modern_expect_ignores_clean_4xx_rejection():
    from moonmcp.web.desync import interpret_modern
    ok = {"outcome": "response", "status": 200}   # a usable baseline the fn requires
    # valid Expect → 200, malformed Expect → clean 417 (RFC-compliant reject): NOT a signal
    ind, _ = interpret_modern({
        "control": ok,
        "expect_100": {"outcome": "response", "status": 200},
        "expect_malformed": {"outcome": "response", "status": 417},
    })
    assert not any("0.CL" in i for i in ind)
    # but a malformed Expect PROCESSED differently (a 5xx, not a clean reject) IS a candidate
    ind2, _ = interpret_modern({
        "control": ok,
        "expect_100": {"outcome": "response", "status": 200},
        "expect_malformed": {"outcome": "response", "status": 501},
    })
    assert any("0.CL" in i for i in ind2)
