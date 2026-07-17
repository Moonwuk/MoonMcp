"""HTTP/2 probe — h2c cleartext-upgrade / smuggling detection + DoS advisory."""

import asyncio

import pytest

from moonmcp import server as srv
from moonmcp.web import http2 as h2


# -- pure request/response --------------------------------------------------
def test_build_h2c_upgrade():
    req = h2.build_h2c_upgrade("x.test", "/app").decode()
    assert req.startswith("GET /app HTTP/1.1\r\n")
    assert "Upgrade: h2c\r\n" in req and "Connection: Upgrade, HTTP2-Settings\r\n" in req
    assert "HTTP2-Settings: " in req


def test_parse_response_and_is_h2c():
    raw = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\nConnection: Upgrade\r\n\r\n"
    status, headers = h2.parse_response(raw)
    assert status == 101 and headers["upgrade"] == "h2c"
    assert h2.is_h2c_upgrade(status, headers)
    # a normal 200 is not an upgrade
    s2, h2h = h2.parse_response(b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n")
    assert not h2.is_h2c_upgrade(s2, h2h)
    # a 101 to something else is not h2c
    assert not h2.is_h2c_upgrade(101, {"upgrade": "websocket"})


# -- assessment -------------------------------------------------------------
def test_assess_h2c_candidate():
    res = h2.assess(["h2"], 101, {"upgrade": "h2c"}, "nginx")
    assert res["verdict"] == "h2c_smuggling_candidate" and res["h2c_upgrade"] is True
    assert res["findings"][0]["kind"] == "h2c_upgrade"
    assert any(c["id"] == "CVE-2023-44487" for c in res["dos_advisory"])


def test_assess_http2_enabled_no_h2c():
    res = h2.assess(["h2"], 200, {}, "cloudflare")
    assert res["verdict"] == "http2_enabled" and res["findings"] == []
    assert res["dos_advisory"]                                   # advisory attaches for any h2


def test_assess_no_http2():
    res = h2.assess(["http/1.1"], 200, {}, "apache")
    assert res["verdict"] == "no_http2" and res["dos_advisory"] == []


def test_dos_cves_present():
    ids = {c["id"] for c in h2.DOS_CVES}
    assert "CVE-2023-44487" in ids and "CVE-2024-27316" in ids


# -- real-socket h2c handshake ----------------------------------------------
@pytest.mark.asyncio
async def test_h2c_handshake_upgrades():
    async def handle(reader, writer):
        await reader.read(4096)
        writer.write(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\n"
                     b"Connection: Upgrade\r\n\r\n")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        status, headers = await h2._h2c_handshake("127.0.0.1", port, False, "/", "127.0.0.1", 3.0)
    assert status == 101 and headers.get("upgrade") == "h2c"


@pytest.mark.asyncio
async def test_h2c_handshake_no_upgrade():
    async def handle(reader, writer):
        await reader.read(4096)
        writer.write(b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Length: 0\r\n\r\n")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        status, headers = await h2._h2c_handshake("127.0.0.1", port, False, "/", "127.0.0.1", 3.0)
    assert status == 200 and not h2.is_h2c_upgrade(status, headers)


@pytest.mark.asyncio
async def test_http2_probe_registered():
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "http2_probe" in tools
