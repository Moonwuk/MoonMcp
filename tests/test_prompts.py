"""Tests for the operator system prompts exposed as MCP prompts."""

import re

import pytest

from moonmcp import prompts as pmod
from moonmcp import server as srv

_NEW_PROMPTS = {
    "bug_bounty_operator", "deep_recon", "injection_hunt",
    "technique_advisor", "triage_and_report", "safe_recon",
}


@pytest.mark.asyncio
async def test_prompts_registered():
    names = {p.name for p in await srv.mcp.list_prompts()}
    assert _NEW_PROMPTS <= names
    assert "recon_methodology" in names  # the original still there
    # every prompt carries a description (what the user sees in a picker)
    for p in await srv.mcp.list_prompts():
        assert p.description and len(p.description) > 15


def test_builders_render_and_carry_guardrails():
    for name, fn in pmod.PROMPTS.items():
        text = fn("acme.example.com")
        assert isinstance(text, str) and len(text) > 300, name
        assert "acme.example.com" in text, name
        low = text.lower()
        # scope / authorisation discipline must be present in every operator prompt
        assert "scope" in low and ("authoris" in low or "authoriz" in low), name


def test_operator_prompt_focus_arg():
    base = pmod.bug_bounty_operator("t.example")
    focused = pmod.bug_bounty_operator("t.example", focus="only the API at /v2")
    assert "ENGAGEMENT FOCUS" not in base
    assert "ENGAGEMENT FOCUS: only the API at /v2" in focused


@pytest.mark.asyncio
async def test_referenced_tools_exist():
    """Guard against drift: every `tool_name` a prompt cites must be a real tool."""

    live = {t.name for t in await srv.mcp.list_tools()}
    # non-tool backtick tokens the prompts legitimately use
    allowed = live | {
        "MOONMCP_ALLOW_INTRUSIVE", "scope_list", "scope_add", "scope_exclude",
        "findings://current", "injections://all", "techniques://all",
        "moonmcp://scope", "moonmcp://capabilities",
    }
    token = re.compile(r"`([a-z_]{4,})`")
    for name, fn in pmod.PROMPTS.items():
        text = fn("example.com", "sqli") if fn is pmod.injection_hunt else fn("example.com")
        for m in token.findall(text):
            # snake_case tokens that look like tool names must resolve
            if "_" in m and m.islower():
                assert m in allowed, f"{name} references unknown tool `{m}`"


def test_prompt_get_via_server():
    got = srv.injection_hunt(target="shop.example.com", injection_class="ssti")
    assert "shop.example.com" in got and "ssti" in got.lower()
    assert "match_injection_signatures" in got
