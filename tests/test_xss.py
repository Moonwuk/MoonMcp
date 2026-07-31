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


def test_attr_unquoted_surviving_gt_closes_tag():
    r = _ctx(f"<input value={C}<>\"'{C}>")["attr_unquoted"]
    assert r.injectable and ">" in r.unescaped


def test_attr_unquoted_is_a_lead_even_when_gt_is_encoded():
    # FN regression: an UNQUOTED attribute is exploitable via a literal SPACE (` autofocus
    # onfocus=alert(1)`) — spaces are never HTML-encoded — even when the app encodes '<'/'>'.
    # Requiring a surviving '>' would miss this whole class, so unquoted-attr is a lead.
    r = _ctx(f"<input value={C}&lt;&gt;&quot;&#39;{C} x>")["attr_unquoted"]
    assert r.injectable and r.unescaped == set()


def test_script_unescaped_lt_is_injectable():
    # a <script> is RAWTEXT: an unescaped '<' allows the </script> break-out.
    r = _ctx(f"<script>var q = '{C}<>\"'{C}';</script>")["rawtext"]
    assert r.injectable and r.element == "script" and "<" in r.unescaped


def test_title_unescaped_lt_is_injectable_via_end_tag():
    # RCDATA: a raw '<' in <title> is genuinely injectable via </title><script> (a well-behaved
    # app HTML-encodes it — see the encoded test below — so this is a TRUE positive, not an FP).
    r = _ctx(f"<title>Results for {C}<>\"'{C}</title>")["rawtext"]
    assert r.injectable and r.element == "title" and "<" in r.unescaped


# -- SAFE: reflected but the required metachar is escaped -> NOT injectable ---
def test_html_text_encoded_is_not_injectable():
    r = _ctx(f"<p>hi {C}&lt;&gt;&quot;&#39;{C}</p>")["html_text"]
    assert not r.injectable and r.unescaped == set()


def test_attr_double_encoded_quote_is_not_injectable():
    r = _ctx(f'<input value="{C}&lt;&gt;&quot;&#39;{C}">')["attr_double"]
    assert not r.injectable and '"' not in r.unescaped


def test_script_template_island_with_encoded_specials_is_not_injectable():
    # regression (was a FP: empty requirement set): a <script type=text/template> data island
    # that HTML-encodes every special must NOT be flagged (nothing survived → no </script>).
    r = _ctx(f'<script type="text/template">{C}&lt;&gt;&quot;&#39;{C}</script>')["rawtext"]
    assert not r.injectable and r.unescaped == set()


def test_script_encoded_lt_is_not_injectable():
    # a <script> that JS-unicode-escapes '<' (\\u003c) has no literal '<' → </script> closed.
    mid = "\\u003c\\u003e" + '\\"' + "'"        # literal: < > \" '
    r = _ctx(f'<script>var q = "{C}{mid}{C}";</script>')["rawtext"]
    assert not r.injectable and "<" not in r.unescaped


def test_html_comment_reported_but_not_auto_injectable():
    r = _ctx(f"<!-- note: {C}<>\"'{C} -->")["comment"]
    assert r.context == "comment" and not r.injectable   # needs '-->', which we don't probe


def test_url_attribute_value_start_is_injectable_lead():
    # reflection AT THE START of an href value → a javascript: scheme injects with no specials.
    r = _ctx(f'<a href="{C}<>"\'{C}">x</a>')["url"]
    assert r.injectable and r.attr == "href"


def test_non_executing_url_attribute_is_not_a_javascript_lead():
    # FP regression: `<img src="javascript:...">` does NOT execute, so a value-start reflection
    # in `<img src>` must NOT be classified as a URL lead — it falls through to a "-quoted attr
    # (breakout still requires an unescaped '"'). Same for <link href>, poster, background, cite.
    ctx = _ctx(f'<img src="{C}<>&quot;&#39;{C}">')
    assert "url" not in ctx
    assert not ctx["attr_double"].injectable          # '"' is encoded → no breakout


def test_url_value_start_survives_leading_whitespace():
    # FN regression: browsers strip leading ASCII whitespace from a URL before scheme parsing,
    # so `<a href="   javascript:...">` still fires — the reflection is still the value START.
    r = _ctx(f'<a href="   {C}<>"\'{C}">x</a>')["url"]
    assert r.injectable and r.attr == "href"


def test_rawtext_lookalike_end_tag_does_not_escape_rcdata():
    # FP regression: `</textareaX` is NOT an appropriate end tag (the name must be followed by a
    # terminator), so the reflection is still inside the <textarea> RCDATA where '"'/'>' are inert
    # — you need an unescaped '<' for </textarea>. A surviving '"' must NOT read as an attr breakout.
    body = f'<textarea>hi </textareaX y="{C}>&quot;{C}">'
    assert all(not r.injectable for r in xss.analyze(body, C))
    assert _ctx(body)["rawtext"].element == "textarea"


def test_reflection_in_middle_of_url_value_is_normal_attr_not_url():
    # reflection NOT at the value start (a fixed path prefix) is a normal "-quoted attribute,
    # injectable only via '"' — NOT a javascript: scheme.
    ctx = _ctx(f'<a href="/search?q={C}&lt;&gt;&quot;&#39;{C}">x</a>')
    assert "url" not in ctx
    assert not ctx["attr_double"].injectable          # quote is encoded → safe


def test_equals_inside_quoted_value_is_not_mistaken_for_unquoted():
    # regression (was a FP): a '=' inside a "-quoted value must not restart attribute parsing
    # and misclassify a double-quoted attr as unquoted.
    r = _ctx(f'<input value="a=b&amp;c={C}&lt;&gt;&quot;&#39;{C}">')["attr_double"]
    assert not r.injectable                            # encoded quote → safe, and context is attr_double


def test_odd_canary_count_does_not_mispair_into_page_markup():
    # regression (was a FP): a fully-escaping app whose canary reflects an ODD number of times
    # (one reflection truncated) must not pair distant canaries and count the page's OWN markup
    # (</p><a href=...>) as surviving specials.
    body = (f'<p>you searched for: {C}&lt;&gt;</p>\n<a href="/home">back</a>\n'
            f'<span>{C}&lt;&gt;&quot;&#39;{C}</span>')
    assert all(not r.injectable for r in xss.analyze(body, C))


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
