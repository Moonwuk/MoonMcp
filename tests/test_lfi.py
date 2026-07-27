"""lfi_probe — path traversal / LFI content-disclosure, pure payload table + e2e."""

import pytest

from moonmcp import server as srv
from moonmcp.knowledge import injections as injmod
from moonmcp.web import probes as probesmod


# -- pure -----------------------------------------------------------------------
def test_lfi_payloads_cover_depths_encodings_and_windows():
    labels = {label for label, _p, _raw in probesmod.LFI_PAYLOADS}
    assert {"unix-depth1", "unix-depth3", "unix-depth6", "unix-depth8",
           "unix-null-byte", "unix-double-encoded", "windows-depth3",
           "windows-depth6"} <= labels
    by_label = {label: (p, raw) for label, p, raw in probesmod.LFI_PAYLOADS}
    assert by_label["unix-null-byte"][0].endswith("%00")
    assert by_label["unix-null-byte"][1] is True          # must not be re-encoded
    assert by_label["unix-double-encoded"][0].startswith("%25")
    assert by_label["windows-depth3"][1] is False          # normal url-encoding is fine
    # every payload targets a known, non-sensitive file only
    for _label, payload, _raw in probesmod.LFI_PAYLOADS:
        assert ("passwd" in payload.lower() or "win.ini" in payload.lower())


def test_path_traversal_signatures_registered_in_kb():
    # lfi_probe leans on the existing KB signature set — confirm it actually matches
    # real /etc/passwd and win.ini content (a regression guard for the KB itself).
    passwd_hits = injmod.match_signatures(
        "root:x:0:0:root:/root:/bin/bash\n", class_id="path-traversal")
    assert passwd_hits
    ini_hits = injmod.match_signatures(
        "; for 16-bit app support\n[fonts]\n[extensions]\n", class_id="path-traversal")
    assert ini_hits
    assert injmod.match_signatures("<html>nothing here</html>", class_id="path-traversal") == []


# -- end-to-end -------------------------------------------------------------------
@pytest.mark.asyncio
async def test_lfi_probe_registered(fresh_context):
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "lfi_probe" in tools


@pytest.mark.asyncio
async def test_lfi_probe_detects_vulnerable_endpoint(local_server, fresh_context):
    base, _ = local_server
    res = await srv.lfi_probe(target=f"{base}/lfi-vuln", param="q")
    assert res["findings"]
    assert res["verdict"] == "confirmed"
    assert any("passwd" in f["payload"] for f in res["findings"])
    # the win.ini variants must also fire (Windows-style separators included)
    assert any("win.ini" in f["payload"] for f in res["findings"])


@pytest.mark.asyncio
async def test_lfi_probe_no_hit_on_safe_endpoint(local_server, fresh_context):
    base, _ = local_server
    res = await srv.lfi_probe(target=f"{base}/lfi-safe", param="q")
    assert res["findings"] == []
    assert res["verdict"] == "unconfirmed"
    assert res["tested"] == len(probesmod.LFI_PAYLOADS)
