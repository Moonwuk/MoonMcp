"""deserialize_fingerprint (Freddy-lite) — passive serialization-marker scanner."""

import base64

import pytest

from moonmcp import server as srv
from moonmcp.recon import deserialize as desmod


def _fmts(blob: str) -> set[str]:
    return {h.format for h in desmod.detect_markers(blob)}


def test_java_serialization_raw_and_base64():
    raw = b"\xac\xed\x00\x05w\x04\x00\x00\x00\x00xp".decode("latin-1")
    assert "java-serialization" in _fmts(raw)
    b64 = base64.b64encode(b"\xac\xed\x00\x05w\x04\x00\x00\x00\x00xp").decode()
    assert b64.startswith("rO0AB")
    hits = desmod.detect_markers(b64)
    assert any(h.format == "java-serialization" and h.encoding == "base64" for h in hits)
    assert any(h.severity == "critical" for h in hits)


def test_net_viewstate_raw():
    raw = b"\xff\x01\x02\x03\x04\x05\x06\x07\x08".decode("latin-1")
    hits = desmod.detect_markers(raw)
    assert any(h.format == ".net-viewstate" for h in hits)


def test_python_pickle_protocols():
    for proto_byte in (b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05"):
        raw = (proto_byte + b"some pickled payload here").decode("latin-1")
        assert "python-pickle" in _fmts(raw)


def test_ruby_marshal():
    raw = (b"\x04\x08" + b"some marshalled payload").decode("latin-1")
    assert "ruby-marshal" in _fmts(raw)


def test_php_object_injection():
    blob = 'O:8:"stdClass":1:{s:3:"foo";s:3:"bar";}'
    hits = desmod.detect_markers(blob)
    assert any(h.format == "php-object" for h in hits)
    # a plain PHP array (a:) is NOT the object-injection signature we flag
    assert desmod.detect_markers('a:1:{i:0;s:3:"foo";}') == []


def test_fastjson_jackson_polymorphic():
    hits = desmod.detect_markers('{"@type":"com.example.Exploit","cmd":"id"}')
    assert any(h.format == "json-polymorphic" for h in hits)
    hits2 = desmod.detect_markers('{"@class":"java.util.HashMap"}')
    assert any(h.format == "json-polymorphic" for h in hits2)


def test_benign_text_has_no_hits():
    assert desmod.detect_markers("just a normal session id abc123") == []
    assert desmod.detect_markers("") == []
    assert desmod.detect_markers("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig") == []


def test_malformed_base64ish_text_never_crashes():
    # base64-alphabet-shaped but not valid base64 padding/content
    assert isinstance(desmod.detect_markers("====notvalid===="), list)


@pytest.mark.asyncio
async def test_deserialize_fingerprint_tool_registered(fresh_context):
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "deserialize_fingerprint" in tools


@pytest.mark.asyncio
async def test_deserialize_fingerprint_tool_reports_source(fresh_context):
    b64 = base64.b64encode(b"\xac\xed\x00\x05w\x04\x00\x00\x00\x00xp").decode()
    res = await srv.deserialize_fingerprint(blob=b64, source="cookie:session")
    assert res["source"] == "cookie:session"
    assert res["count"] >= 1
    assert res["findings"][0]["format"] == "java-serialization"


@pytest.mark.asyncio
async def test_deserialize_fingerprint_tool_default_source_note(fresh_context):
    res = await srv.deserialize_fingerprint(blob="benign text")
    assert "unspecified" in res["source"]
    assert res["count"] == 0
