"""gRPC / gRPC-Web detection probe — framing, reflection parse, exposure findings."""

import base64

import pytest

from moonmcp import server as srv
from moonmcp.web import grpcprobe as gp


# -- protobuf/grpc-web builders for the fakes ------------------------------
def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | 0x80 if n else b)
        if not n:
            return bytes(out)


def _len_delim(field_no: int, data: bytes) -> bytes:
    return bytes([(field_no << 3) | 2]) + _varint(len(data)) + data


def _reflection_response(services):
    # ServerReflectionResponse{ list_services_response: { service: [{name}, …] } }
    list_service_response = b"".join(_len_delim(1, _len_delim(1, s.encode())) for s in services)
    return _len_delim(6, list_service_response)


def _grpc_web(status_code, data=b""):
    """A gRPC-Web response body: optional data frame + a trailer frame with grpc-status."""
    body = gp.frame_message(data) if data else b""
    trailer = f"grpc-status:{status_code}\r\ngrpc-message:\r\n".encode()
    return body + gp.frame_message(trailer, trailer=True)


# -- pure framing / parsing -------------------------------------------------
def test_frame_roundtrip_and_trailer_flag():
    frames = gp.parse_frames(gp.frame_message(b"hello") + gp.frame_message(b"gs", trailer=True))
    assert frames == [(0x00, b"hello"), (0x80, b"gs")]
    assert gp.data_payloads(frames) == [b"hello"]


def test_parse_frames_stops_on_truncation():
    good = gp.frame_message(b"abc")
    assert gp.parse_frames(good + b"\x00\x00\x00\x00\x09short") == [(0x00, b"abc")]


def test_trailer_status_from_frame_and_headers():
    frames = gp.parse_frames(_grpc_web(0))
    assert gp.trailer_status(frames, {}) == (0, "")
    # native-gRPC style: grpc-status in headers, no trailer frame
    assert gp.trailer_status([], {"grpc-status": "12", "grpc-message": "nope"}) == (12, "nope")


def test_reflection_request_wire_format():
    assert gp.reflection_request() == gp.frame_message(b"\x3a\x01*")


def test_decode_body_grpc_web_text_is_base64():
    raw = _grpc_web(0, b"xy")
    enc = base64.b64encode(raw)
    assert gp.decode_body(enc, "application/grpc-web-text") == raw
    assert gp.decode_body(raw, "application/grpc-web+proto") == raw


def test_extract_service_names():
    payload = _reflection_response(["grpc.health.v1.Health", "acme.orders.v1.Orders"])
    assert gp.extract_service_names(payload) == ["grpc.health.v1.Health", "acme.orders.v1.Orders"]
    assert gp.extract_service_names(b"\x08\x01") == []       # wrong shape → []


def test_is_grpc_response():
    assert gp.is_grpc_response("application/grpc-web+proto", None)
    assert gp.is_grpc_response("text/html", 12)              # grpc-status present
    assert not gp.is_grpc_response("text/html", None)


# -- probe against fake gRPC-Web servers ------------------------------------
class _R:
    def __init__(self, status, body, content_type="application/grpc-web+proto"):
        self.status = status
        self.body = body
        self._ct = content_type

    def headers_map(self):
        return {"content-type": self._ct}

    def text(self, limit=None):
        return (self.body or b"").decode("latin-1", "replace")


class _ReflectionApp:
    """Reflection ENABLED (v1alpha), health serving, bogus method UNIMPLEMENTED."""

    def __init__(self, services):
        self.services = services

    async def fetch(self, url, *, method="POST", body=None, headers=None, **kw):
        if gp.REFLECTION_V1ALPHA in url:
            return _R(200, _grpc_web(0, _reflection_response(self.services)))
        if gp.HEALTH_SERVICE in url:
            return _R(200, _grpc_web(0, b"\x08\x01"))         # SERVING
        return _R(200, _grpc_web(12))                          # bogus / v1 → UNIMPLEMENTED


class _V1OnlyApp:
    """Only the v1 reflection service is implemented (v1alpha UNIMPLEMENTED)."""

    async def fetch(self, url, *, method="POST", body=None, headers=None, **kw):
        if gp.REFLECTION_V1 in url and gp.REFLECTION_V1ALPHA not in url:
            return _R(200, _grpc_web(0, _reflection_response(["x.Y"])))
        return _R(200, _grpc_web(12))


class _NoReflectionApp:
    """A gRPC server with everything UNIMPLEMENTED (reflection + health off)."""

    async def fetch(self, url, *, method="POST", body=None, headers=None, **kw):
        return _R(200, _grpc_web(12))


class _NotGrpcApp:
    async def fetch(self, url, *, method="POST", body=None, headers=None, **kw):
        return _R(404, b"<html>not found</html>", content_type="text/html")


@pytest.mark.asyncio
async def test_probe_reflection_exposed_lists_services():
    res = await gp.probe_grpc(_ReflectionApp(["grpc.health.v1.Health", "acme.v1.Orders"]),
                              "https://x.test")
    assert res["is_grpc"] and res["verdict"] == "reflection_exposed"
    assert "acme.v1.Orders" in res["services"]
    kinds = {f["kind"] for f in res["findings"]}
    assert "server_reflection" in kinds and "health_service" in kinds


@pytest.mark.asyncio
async def test_probe_reflection_v1_only():
    res = await gp.probe_grpc(_V1OnlyApp(), "https://x.test")
    refl = [f for f in res["findings"] if f["kind"] == "server_reflection"]
    assert refl and refl[0]["service"] == gp.REFLECTION_V1


@pytest.mark.asyncio
async def test_probe_grpc_detected_no_reflection():
    res = await gp.probe_grpc(_NoReflectionApp(), "https://x.test")
    assert res["is_grpc"] and res["verdict"] == "grpc_detected" and res["findings"] == []


@pytest.mark.asyncio
async def test_probe_not_grpc():
    res = await gp.probe_grpc(_NotGrpcApp(), "https://x.test")
    assert res["is_grpc"] is False and res["verdict"] == "not_grpc"


# -- registration + dry_run -------------------------------------------------
@pytest.mark.asyncio
async def test_grpc_probe_registered_and_dry_run(fresh_context):
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "grpc_probe" in tools
    prev = await srv.grpc_probe(target="http://127.0.0.1", dry_run=True)
    assert prev["dry_run"] is True
    assert any("ServerReflection" in p for p in prev["payloads"])
