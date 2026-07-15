"""Tests for the injection knowledge base (query API + signature matching)."""

import re

import pytest

from moonmcp import server as srv
from moonmcp.knowledge import injections as inj
from moonmcp.knowledge.injections_data import INJECTIONS


def test_kb_is_well_formed():
    assert len(INJECTIONS) >= 3
    ids = [c["id"] for c in INJECTIONS]
    assert len(ids) == len(set(ids)), "duplicate class ids"
    for c in INJECTIONS:
        assert c["id"] and c["name"] and c["summary"]
        assert c["root_causes"], f"{c['id']} missing root_causes"
        assert c["detection_payloads"], f"{c['id']} missing detection_payloads"
        assert c["signatures"], f"{c['id']} missing signatures"
        for sig in c["signatures"]:
            assert sig["type"] in ("error", "regex", "behavioral")


def test_all_regex_signatures_compile():
    for c in INJECTIONS:
        for sig in c["signatures"]:
            if sig["type"] == "regex":
                re.compile(sig["value"])  # must not raise


def test_get_and_search():
    assert inj.get_class("sqli") is not None
    assert inj.get_class("SQL Injection") is not None  # alias
    assert inj.get_class("nonexistent-xyz") is None
    assert any(r["id"] == "sqli" for r in inj.search("sql"))


def test_match_signatures_sqli():
    body = "Warning: You have an error in your SQL syntax; check the manual near ''"
    matches = inj.match_signatures(body)
    assert any(m["class"] == "sqli" and m["technology"] == "MySQL" for m in matches)


def test_match_signatures_regex_oracle():
    matches = inj.match_signatures("ORA-01756: quoted string not properly terminated")
    assert any(m["class"] == "sqli" for m in matches)


def test_match_signatures_filter_by_class():
    body = "You have an error in your SQL syntax"
    assert inj.match_signatures(body, class_id="xss") == []
    assert inj.match_signatures(body, class_id="sqli")


@pytest.mark.asyncio
async def test_injection_tools_registered_and_work():
    tools = {t.name for t in await srv.mcp.list_tools()}
    for name in ("injection_info", "match_injection_signatures"):
        assert name in tools
    assert "injection_search" not in tools     # folded into injection_info(query=)
    assert (await srv.injection_info(query="sql"))["results"]
    info = await srv.injection_info(injection_class="sqli")
    assert info["id"] == "sqli"
    idx = await srv.injection_info()
    assert idx["stats"]["classes"] >= 3
    m = await srv.match_injection_signatures(text="ORA-00933: SQL command not properly ended")
    assert m["match_count"] >= 1
