"""Tests for the server-side vulnerability KB, root-cause taxonomy and WAF KB."""

import pytest

from moonmcp import server as srv
from moonmcp.knowledge import vulns as vmod
from moonmcp.knowledge import waf_kb as wmod
from moonmcp.knowledge.vulns_data import ROOT_CAUSES, SERVER_SIDE_VULNS, VULN_TOOLS
from moonmcp.knowledge.waf_kb_data import WAF_ENTRIES

_POP = {"common", "uncommon", "rare"}


def test_vuln_catalog_well_formed():
    assert len(SERVER_SIDE_VULNS) >= 20
    ids = [v["id"] for v in SERVER_SIDE_VULNS]
    assert len(ids) == len(set(ids)), "duplicate vuln ids"
    rc_ids = {r["id"] for r in ROOT_CAUSES}
    for v in SERVER_SIDE_VULNS:
        assert v["id"] and v["name"] and v.get("summary")
        assert v.get("popularity") in _POP, v["id"]
        assert v.get("where_it_breaks"), f"{v['id']} missing where_it_breaks"
        # every vuln's root_cause must resolve to a taxonomy entry
        assert v.get("root_cause") in rc_ids, (v["id"], v.get("root_cause"))
        for url in v.get("references", []):
            assert url.startswith("http"), v["id"]


def test_root_cause_taxonomy():
    assert len(ROOT_CAUSES) >= 10
    ids = [r["id"] for r in ROOT_CAUSES]
    assert len(ids) == len(set(ids))
    assert "code-data-confusion" in ids
    for r in ROOT_CAUSES:
        assert r["summary"] and r.get("why_it_recurs") and r.get("systemic_fix")
    rc = vmod.get_root_cause("code-data-confusion")
    assert rc and rc["vulns_in_catalog"], "code-data-confusion should link derived vulns"


def test_vuln_queries():
    assert vmod.get_vuln("nonexistent-xyz") is None
    assert vmod.by_popularity("rare") or vmod.by_popularity("uncommon")
    assert vmod.search("ssrf") or vmod.search("smuggling")
    assert any(t["id"] for t in VULN_TOOLS)
    assert vmod.search_tools("sql")  # sqlmap-ish


def test_waf_kb():
    assert len(WAF_ENTRIES) >= 10
    cats = {w["category"] for w in WAF_ENTRIES}
    assert {"how-it-works", "fingerprint", "bypass-technique"} <= cats
    assert wmod.fingerprints() and wmod.bypasses()


def test_waf_identify():
    resp = ("HTTP/1.1 403 Forbidden\r\nServer: cloudflare\r\n"
            "CF-RAY: 7d0f00-LHR\r\nSet-Cookie: __cfduid=abc; path=/\r\n")
    matches = wmod.identify(resp)
    assert any("cloud" in m["name"].lower() or "cloudflare" in m["waf"].lower()
               for m in matches), matches
    assert wmod.identify("") == []


@pytest.mark.asyncio
async def test_tools_and_resources_registered():
    tools = {t.name for t in await srv.mcp.list_tools()}
    for n in ("vuln_info", "rootcause_info", "vuln_tools",
              "waf_info", "identify_waf"):
        assert n in tools
    assert "vuln_search" not in tools          # folded into vuln_info(query=)
    assert (await srv.vuln_info(query="ssrf"))["results"]
    resources = {str(r.uri) for r in await srv.mcp.list_resources()}
    for scheme in ("vulns://", "rootcauses://", "waf://"):
        assert any(u.startswith(scheme) for u in resources), scheme
    idx = await srv.vuln_info()
    assert idx["stats"]["vulns"] >= 20
    rc = await srv.rootcause_info(root_cause="parser-differential")
    assert rc.get("id") == "parser-differential"
    w = await srv.identify_waf(text="Server: cloudflare\nCF-RAY: abc")
    assert w["match_count"] >= 1
