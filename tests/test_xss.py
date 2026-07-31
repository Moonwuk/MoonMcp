"""Reflected-XSS escape-analysis — flag UNESCAPED breakout per context, never mere reflection."""

import pytest

from moonmcp import server as srv
from moonmcp.web import xss

C = "moonxssTEST"          # a fixed canary for the pure analyzer


def _ctx(body):
    return {r.context: r for r in xss.analyze(body, C)}


# -- vulnerable: the breakout metachar survives unescaped in its context -----
def test_html_text_unescaped_is_injectable():
    r = _ctx(f"<p>hi {C}<>\"'{C} bye</p>")["html_text"]
    assert r.injectable and "<" in r.unescaped


def test_attr_double_unescaped_quote_is_injectable():
    r = _ctx(f'<input value="{C}<>"\'{C}">')["attr_double"]
    assert r.injectable and '"' in r.unescaped


def test_attr_single_unescaped_quote_is_injectable():
    r = _ctx(f"<input value='{C}<>\"'{C}'>")["attr_single"]
    assert r.injectable and "'" in r.unescaped


def test_attr_unquoted_needs_gt_to_close_tag():
    r = _ctx(f"<input value={C}<>\"'{C}>")["attr_unquoted"]
    assert r.injectable and ">" in r.unescaped


def test_script_raw_is_injectable_on_reflection():
    r = _ctx(f"<script>var q = {C}<>\"'{C};</script>")["script_raw"]
    assert r.injectable                                   # raw JS: no breakout needed


def test_script_string_injectable_when_lt_survives():
    # inside a "-quoted JS string; an unescaped '<' allows the </script> break-out.
    r = _ctx(f'<script>var q = "{C}<>"\'{C}";</script>')["script_string_double"]
    assert r.injectable and "<" in r.unescaped


# -- SAFE: reflected but the required metachar is escaped -> NOT injectable ---
def test_html_text_encoded_is_not_injectable():
    r = _ctx(f"<p>hi {C}&lt;&gt;&quot;&#39;{C}</p>")["html_text"]
    assert not r.injectable and r.unescaped == set()


def test_attr_double_encoded_quote_is_not_injectable():
    r = _ctx(f'<input value="{C}&lt;&gt;&quot;&#39;{C}">')["attr_double"]
    assert not r.injectable and '"' not in r.unescaped


def test_script_string_backslash_escaped_quote_is_not_injectable():
    # the "-quoted JS string reflects a backslash-escaped \" and a JS-unicode-escaped <.
    # The literal '"' byte is present (as \") but there is NO literal '<', so the </script>
    # route is closed and we must NOT flag — the backslash-escaped quote is inert.
    mid = "\\u003c\\u003e" + '\\"' + "'"        # literal: < > \" '
    r = _ctx(f'<script>var q = "{C}{mid}{C}";</script>')["script_string_double"]
    assert not r.injectable and "<" not in r.unescaped


def test_html_comment_reported_but_not_auto_injectable():
    r = _ctx(f"<!-- note: {C}<>\"'{C} -->")["html_comment"]
    assert r.context == "html_comment" and not r.injectable   # needs '-->', which we don't probe


def test_no_reflection_returns_nothing():
    assert xss.analyze("<p>nothing echoed here</p>", C) == []


def test_partial_encoding_only_quotes_still_safe_in_double_attr():
    # app encodes quotes but not angle brackets; a "-quoted attribute is still safe
    # (you cannot leave the attribute without an unescaped '"').
    r = _ctx(f'<input value="{C}<>&quot;&#39;{C}">')["attr_double"]
    assert not r.injectable                                   # '<'/'>' present but '"' is not


# -- end-to-end via the local server -----------------------------------------
@pytest.mark.asyncio
async def test_xss_probe_flags_unescaped_reflection(local_server, fresh_context):
    base, _ = local_server
    res = await srv.xss_probe(target=f"{base}/xss", param="q")
    assert res["verdict"] in ("likely", "confirmed")
    assert any(c["injectable"] and c["context"] == "html_text" for c in res["contexts"])


@pytest.mark.asyncio
async def test_xss_probe_does_not_flag_encoded_reflection(local_server, fresh_context):
    base, _ = local_server
    res = await srv.xss_probe(target=f"{base}/xss-safe", param="q")
    assert res["verdict"] not in ("likely", "confirmed")     # encoded reflection is not a vuln
    assert not any(c["injectable"] for c in res["contexts"])


# -- tool registration -------------------------------------------------------
@pytest.mark.asyncio
async def test_xss_probe_registered():
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "xss_probe" in tools
