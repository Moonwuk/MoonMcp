"""WebSocket detection probe (ws_probe) — RFC 6455 helpers + CSWSH detection."""

import pytest

from moonmcp import server as srv
from moonmcp.web import websocket as ws


def test_accept_value_matches_rfc6455_vector():
    # RFC 6455 §1.3 worked example.
    assert ws.accept_value("dGhlIHNhbXBsZSBub25jZQ==") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="


def test_frame_roundtrip():
    frame = ws.encode_text_frame("hello ws")
    # client frames MUST be masked
    assert frame[1] & 0x80
    opcode, payload, consumed = ws.decode_frame(frame)
    assert opcode == 0x1 and payload == b"hello ws" and consumed == len(frame)


def test_decode_frame_incomplete_returns_zero():
    assert ws.decode_frame(b"\x81") == (None, b"", 0)          # too short
    assert ws.decode_frame(b"\x81\x05he") == (None, b"", 0)    # payload not all here


def test_build_and_parse_handshake():
    key = ws.new_key()
    req = ws.build_handshake("h.example:8443", "/chat", key,
                             origin="https://h.example", subprotocols="chat")
    text = req.decode("latin-1")
    assert "GET /chat HTTP/1.1" in text and "Upgrade: websocket" in text
    assert f"Sec-WebSocket-Key: {key}" in text and "Origin: https://h.example" in text
    ok = (f"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
          f"Sec-WebSocket-Accept: {ws.accept_value(key)}\r\n\r\n").encode()
    parsed = ws.parse_handshake_response(ok)
    assert parsed["status"] == 101 and ws.handshake_ok(parsed, key)
    # a wrong accept fails validation
    bad = ws.parse_handshake_response(b"HTTP/1.1 101 x\r\nUpgrade: websocket\r\n"
                                      b"Sec-WebSocket-Accept: nope\r\n\r\n")
    assert not ws.handshake_ok(bad, key)


def test_split_ws_url():
    assert ws.split_ws_url("wss://h.example/chat") == ("h.example", 443, "/chat", True)
    assert ws.split_ws_url("ws://h.example:9001/x") == ("h.example", 9001, "/x", False)
    assert ws.split_ws_url("h.example") == ("h.example", 443, "/", True)   # wss assumed
    assert ws.split_ws_url("http://h.example/y") == ("h.example", 80, "/y", False)


@pytest.mark.asyncio
async def test_ws_probe_registered(fresh_context):
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "ws_probe" in tools


@pytest.mark.asyncio
async def test_ws_probe_flags_cswsh_on_lenient_endpoint(fresh_context, local_server):
    base, port = local_server
    res = await srv.ws_probe(target=f"ws://127.0.0.1:{port}/ws")
    assert res["is_websocket"] is True
    assert res["handshake"]["accept_valid"] is True
    assert res["origin_check"]["foreign_accepted"] is True
    assert any(ld["kind"] == "cswsh" for ld in res["leads"])


@pytest.mark.asyncio
async def test_ws_probe_no_cswsh_when_origin_validated(fresh_context, local_server):
    base, port = local_server
    res = await srv.ws_probe(target=f"ws://127.0.0.1:{port}/ws-strict")
    assert res["is_websocket"] is True
    assert res["origin_check"]["foreign_accepted"] is False
    assert not any(ld["kind"] == "cswsh" for ld in res["leads"])


@pytest.mark.asyncio
async def test_ws_probe_non_websocket_endpoint(fresh_context, local_server):
    base, port = local_server
    res = await srv.ws_probe(target=f"ws://127.0.0.1:{port}/echo")
    assert res["is_websocket"] is False
    assert res["review"]


@pytest.mark.asyncio
async def test_ws_probe_message_echo_optin(fresh_context, local_server):
    base, port = local_server
    res = await srv.ws_probe(target=f"ws://127.0.0.1:{port}/ws", probe_message=True)
    assert res["echo"] is not None
    assert res["echo"]["reflected"] is True
    assert any(ld["kind"] == "message_reflection" for ld in res["leads"])


@pytest.mark.asyncio
async def test_handshake_reassembles_fragmented_response(monkeypatch):
    # The 101 line and the Sec-WebSocket-Accept header arrive in SEPARATE reads —
    # the handshake must still parse (a single read() would miss the accept header).
    import asyncio

    key = "dGhlIHNhbXBsZSBub25jZQ=="
    accept = ws.accept_value(key)
    monkeypatch.setattr(ws, "new_key", lambda: key)

    class _FragReader:
        def __init__(self, chunks):
            self._chunks = list(chunks)

        async def read(self, n):
            return self._chunks.pop(0) if self._chunks else b""

    class _NullWriter:
        def write(self, d):
            pass

        async def drain(self):
            pass

        def close(self):
            pass

    async def _fake_open(*a, **k):
        return _FragReader([
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n",
            f"Connection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n".encode(),
        ]), _NullWriter()

    monkeypatch.setattr(asyncio, "open_connection", _fake_open)
    res = await ws._handshake("h", 80, False, "/", "h", 5.0, origin=None, subprotocols=None)
    assert res["ok"] is True and res["status"] == 101
