"""Tests for the techniques & notable-PoC catalog."""

import pytest

from moonmcp import server as srv
from moonmcp.knowledge import techniques as tech
from moonmcp.knowledge.techniques_data import TECHNIQUES

_VALID_CATEGORIES = {
    "web", "deserialization", "memory-corruption", "heap-exploitation",
    "code-reuse", "mitigation-bypass", "famous-cve", "language-specific",
    "kernel-lowlevel", "container-sandbox", "microarchitectural",
    "supply-chain", "unique-technique", "interpreter-level",
}


def test_catalog_well_formed():
    assert len(TECHNIQUES) >= 5
    ids = [t["id"] for t in TECHNIQUES]
    assert len(ids) == len(set(ids)), "duplicate technique ids"
    for t in TECHNIQUES:
        assert t["id"] and t["name"] and t.get("summary")
        assert t.get("category") in _VALID_CATEGORIES, t["id"]
        assert t.get("technique"), f"{t['id']} missing technique"
        assert isinstance(t.get("languages", []), list)
        # references should be URLs when present
        for url in t.get("poc_references", []) + t.get("research_references", []):
            assert url.startswith("http"), f"{t['id']} bad url {url}"


def test_get_by_id_and_cve():
    assert tech.get_technique("log4shell")["id"] == "log4shell"
    # a CVE may be referenced by several techniques; lookup returns a valid one
    hit = tech.get_technique("CVE-2021-44228")
    assert hit is not None and "CVE-2021-44228" in hit["cve"]
    assert tech.get_technique("nonexistent-xyz") is None


def test_search_and_filters():
    assert any(e["id"] == "stack-buffer-overflow-rop" for e in tech.search("rop"))
    assert tech.by_category("famous-cve")
    java = {e["id"] for e in tech.by_language("java")}
    assert "log4shell" in java
    assert "languages" in tech.stats()


@pytest.mark.asyncio
async def test_technique_tools():
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "technique_info" in tools and "technique_search" not in tools
    info = await srv.technique_info(technique="log4shell")
    assert info["id"] == "log4shell"
    idx = await srv.technique_info()
    assert idx["stats"]["techniques"] >= 5
    bylang = await srv.technique_info(language="python")
    assert "results" in bylang
    s = await srv.technique_info(query="deserialization")   # search folded into _info
    assert s["results"]
