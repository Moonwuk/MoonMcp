"""Tests for the privilege-escalation knowledge base (techniques + tools + matching)."""

import pytest

from moonmcp import server as srv
from moonmcp.knowledge import privesc as pe
from moonmcp.knowledge.privesc_data import PRIVESC, PRIVESC_TOOLS

_PLATFORMS = {"linux", "windows", "container", "cloud", "active-directory", "macos",
             "cross-platform"}


def test_techniques_well_formed():
    assert len(PRIVESC) >= 5
    ids = [t["id"] for t in PRIVESC]
    assert len(ids) == len(set(ids)), "duplicate technique ids"
    for t in PRIVESC:
        assert t["id"] and t["name"] and t.get("summary")
        assert t.get("platform") in _PLATFORMS, t["id"]
        assert t.get("category"), f"{t['id']} missing category"
        assert t.get("technique"), f"{t['id']} missing technique"
        for url in t.get("poc_references", []) + t.get("research_references", []):
            assert url.startswith("http"), f"{t['id']} bad url {url}"


def test_tools_well_formed():
    assert len(PRIVESC_TOOLS) >= 3
    ids = [t["id"] for t in PRIVESC_TOOLS]
    assert len(ids) == len(set(ids)), "duplicate tool ids"
    for t in PRIVESC_TOOLS:
        assert t["id"] and t["name"] and t.get("summary")
        assert t.get("platform") in _PLATFORMS, t["id"]
        if t.get("url"):
            assert t["url"].startswith("http"), t["id"]


def test_get_search_filters():
    assert pe.get_technique("nonexistent-xyz") is None
    assert pe.by_platform("linux"), "no linux techniques"
    assert pe.by_platform("windows"), "no windows techniques"
    assert "linux" in pe.platforms()
    assert pe.search("sudo") or pe.search("docker")
    # tools
    assert pe.get_tool("linpeas") is not None
    assert any(t["id"] == "gtfobins" for t in pe.search_tools("gtfo"))


def test_match_enumeration_linux_and_windows():
    # a pasted `sudo -l` snippet should flag a sudo vector
    sudo_out = "User www-data may run the following commands:\n    (root) NOPASSWD: /usr/bin/vim"
    m = pe.match_enumeration(sudo_out)
    assert any(hit["category"] == "sudo" or "sudo" in hit["technique"] for hit in m)
    # a `whoami /priv` snippet should flag token impersonation
    priv_out = "SeImpersonatePrivilege            Impersonate a client after authentication   Enabled"
    mw = pe.match_enumeration(priv_out, platform="windows")
    assert any("potato" in hit["technique"] or hit["category"] == "token-impersonation"
               for hit in mw)


@pytest.mark.asyncio
async def test_privesc_tools_registered_and_work():
    tools = {t.name for t in await srv.mcp.list_tools()}
    for name in ("privesc_info", "privesc_search", "privesc_tools", "match_privesc"):
        assert name in tools
    idx = await srv.privesc_info()
    assert idx["stats"]["techniques"] >= 5
    lin = await srv.privesc_info(platform="linux")
    assert lin["results"]
    cat = await srv.privesc_tools(query="peass")
    assert "results" in cat
    m = await srv.match_privesc(text="(root) NOPASSWD: /usr/bin/find")
    assert m["match_count"] >= 1


@pytest.mark.asyncio
async def test_privesc_resource_and_prompt():
    resources = {str(r.uri) for r in await srv.mcp.list_resources()}
    assert any(u.startswith("privesc://") for u in resources)
    prompts = {p.name for p in await srv.mcp.list_prompts()}
    assert "privesc_hunt" in prompts
    text = srv.privesc_hunt(target="10.0.0.5", platform="linux")
    assert "10.0.0.5" in text and "match_privesc" in text
