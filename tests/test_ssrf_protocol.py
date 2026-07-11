"""SSRF → internal datastore reach — pure helpers + internal-port + scheme eval."""

import pytest

from moonmcp import server as srv
from moonmcp.web import ssrf_protocol as ssp


# -- pure --------------------------------------------------------------------
def test_scheme_payload():
    assert ssp.scheme_payload("gopher", "cnry.oast", "http://cnry.oast/t").startswith("gopher://cnry.oast/")
    assert ssp.scheme_payload("dict", "cnry.oast", "http://x/t").startswith("dict://cnry.oast/")
    assert ssp.scheme_payload("http", "cnry.oast", "http://cnry.oast/t") == "http://cnry.oast/t"


def test_parse_ports_and_targets():
    assert ssp.parse_ports("db") == ssp.DB_PORTS
    assert ssp.parse_ports("6379,3306") == [6379, 3306]
    tgts = dict(ssp.internal_port_targets([6379]))
    assert tgts["127.0.0.1:6379"] == "http://127.0.0.1:6379/"
    assert ssp.closed_control_url().endswith(":9/")


def test_assess_reachability():
    assert ssp.assess_reachability((200, 7), (200, 40)) is True     # big length delta
    assert ssp.assess_reachability((200, 7), (500, 7)) is True      # status differs
    assert ssp.assess_reachability((200, 7), (200, 10)) is False    # within noise band


# -- end-to-end --------------------------------------------------------------
def _open_http_port():
    import http.server
    import socketserver
    import threading

    class _H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"open-internal-service")

    httpd = socketserver.TCPServer(("127.0.0.1", 0), _H)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, port


@pytest.mark.asyncio
async def test_internal_port_reachability(local_server, fresh_context):
    base, _ = local_server
    # a SEPARATE server is the "open" internal port (fetching the test server itself
    # would deadlock its single thread); probe it + a definitely-closed one.
    httpd, open_port = _open_http_port()
    try:
        res = await srv.ssrf_protocol_probe(target=f"{base}/ssrf-proto", param="url",
                                            ports=f"{open_port},1", wait=0.5)
        assert f"127.0.0.1:{open_port}" in res["reachable_internal_ports"], res
        assert "127.0.0.1:1" not in res["reachable_internal_ports"]
        assert res["verdict"] in ("likely", "confirmed")
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.mark.asyncio
async def test_scheme_http_control_fires_via_selfhost(local_server, fresh_context):
    base, _ = local_server
    await srv.oast_selfhost(action="start", host="127.0.0.1")
    try:
        res = await srv.ssrf_protocol_probe(target=f"{base}/ssrf-proto", param="url",
                                            ports="1", wait=1.5)
        # the http control canary is dereferenced (self-host catches HTTP only)
        assert res["scheme_callbacks"].get("http", 0) >= 1, res
    finally:
        await srv.oast_selfhost(action="stop")


@pytest.mark.asyncio
async def test_ssrf_protocol_intrusive_gated(local_server, fresh_context):
    from dataclasses import replace
    base, _ = local_server
    fresh_context.settings = replace(fresh_context.settings, allow_intrusive=False)
    res = await srv.ssrf_protocol_probe(target=f"{base}/ssrf-proto", param="url")
    assert res["error"] == "disabled"


@pytest.mark.asyncio
async def test_ssrf_protocol_registered():
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "ssrf_protocol_probe" in tools
