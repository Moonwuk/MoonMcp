import http.server
import socketserver
import threading

import pytest

from moonmcp import mcp_core
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
    mcp_core.set_context(ctx)
    try:
        await srv.add_finding(target="x.example", severity="high", title="XSS", detail="reflected")
        listing = await srv.list_findings()
        assert listing["summary"]["total"] == 1
        assert listing["findings"][0]["title"] == "XSS"
        cleared = await srv.clear_findings()
        assert cleared["removed"] == 1
    finally:
        mcp_core.set_context(None)


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
    import dataclasses as _dc
    ctx = build_context()
    ctx.scope.block_private = False
    ctx.scope.add("127.0.0.1")
    # desync_probe is intrusive-gated; dataclass defaults to False now.
    ctx.settings = _dc.replace(ctx.settings, allow_intrusive=True)
    monkeypatch.setattr(mcp_core, "_CTX", ctx)
    return ctx


@pytest.mark.asyncio
async def test_desync_probe_baseline_and_framing(raw_server, ctx_fixture):
    res = await srv.desync_probe(target=raw_server)
    assert res.get("baseline_status") == 200
    probes = res.get("probes", {})
    # The well-behaved server rejects the ambiguous CL+TE request.
    assert probes.get("cl.te-dual") == 400
    assert {"te-tab", "te-space-before-colon"} <= set(probes)
    assert "te-nameprefix" not in probes          # dropped: not an obfuscated header
    # This server ignores the obfuscated TE (serves the same 200 as clean chunked) and
    # rejects the dual framing — no differential, so NO false-positive indicators.
    assert res.get("indicators", []) == []
    assert res.get("risk") == "low"


class _DiffH(socketserver.BaseRequestHandler):
    def handle(self):
        data = b""
        try:
            data = self.request.recv(8192)
        except OSError:
            pass
        # A server that parses the space-obfuscated TE down a DIFFERENT code path,
        # producing a materially longer body than clean chunked (a real differential).
        body = b"X" * 200 if b"Transfer-Encoding : chunked" in data else b"ok"
        resp = (b"HTTP/1.1 200 OK\r\nServer: DiffSrv\r\nContent-Length: "
                + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
        try:
            self.request.sendall(resp)
        except OSError:
            pass


@pytest.fixture()
def diff_server():
    httpd = socketserver.TCPServer(("127.0.0.1", 0), _DiffH)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        httpd.shutdown()


@pytest.mark.asyncio
async def test_desync_probe_flags_accepted_differential(diff_server, ctx_fixture):
    # The obfuscated TE is accepted (200) but processed differently from canonical
    # chunked (a much longer body) — that genuine differential must be flagged, while
    # te-tab (handled like canonical) and the dual (same as canonical) stay quiet.
    res = await srv.desync_probe(target=diff_server)
    inds = " ".join(res.get("indicators", []))
    assert "te-space-before-colon" in inds and "Obfuscated Transfer-Encoding" in inds
    assert "te-tab" not in inds
    assert res.get("risk") == "review"
