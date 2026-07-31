"""interp_probe — generic differential "interpretation" prober, pure + e2e."""

import json

import pytest

from moonmcp import server as srv
from moonmcp.web import interp as interpmod


# -- pure -----------------------------------------------------------------------
def test_build_probe_fills_control_into_every_marker():
    for name, template, _tools, _desc in interpmod.MARKERS:
        probe = interpmod.build_probe("ctl123", template)
        assert "ctl123" in probe, name


def test_assess_marker_literal_passthrough_not_interpreted():
    for _name, template, _tools, _desc in interpmod.MARKERS:
        sent = interpmod.build_probe("ctl123", template)
        body = f"<html>{sent}</html>"
        res = interpmod.assess_marker("ctl123", template, body)
        assert res == {"observed": True, "interpreted": False}


def test_assess_marker_backslash_stripped_is_interpreted():
    template = dict((n, t) for n, t, *_ in interpmod.MARKERS)["backslash"]
    body = "<html>ctl123</html>"  # the trailing backslash never made it back
    res = interpmod.assess_marker("ctl123", template, body)
    assert res == {"observed": True, "interpreted": True}


def test_assess_marker_quote_doubled_is_interpreted():
    template = dict((n, t) for n, t, *_ in interpmod.MARKERS)["quote"]
    body = "<html>ctl123''</html>"  # quote doubled instead of the single sent quote
    res = interpmod.assess_marker("ctl123", template, body)
    assert res["interpreted"] is True


def test_assess_marker_null_byte_truncation_is_interpreted():
    template = dict((n, t) for n, t, *_ in interpmod.MARKERS)["null_byte"]
    body = "<html>ctl123</html>"  # truncated -- no second copy, no TAIL
    res = interpmod.assess_marker("ctl123", template, body)
    assert res["interpreted"] is True


def test_assess_marker_path_segment_collapsed_is_interpreted():
    template = dict((n, t) for n, t, *_ in interpmod.MARKERS)["path_dot_segment"]
    body = "<html>ctl123/ctl123TAIL</html>"  # /./ collapsed to /
    res = interpmod.assess_marker("ctl123", template, body)
    assert res["interpreted"] is True


def test_assess_marker_brace_stripped_is_interpreted():
    template = dict((n, t) for n, t, *_ in interpmod.MARKERS)["brace"]
    body = "<html>ctl123ctl123</html>"  # {} removed entirely
    res = interpmod.assess_marker("ctl123", template, body)
    assert res["interpreted"] is True


def test_assess_marker_json_reencoding_not_interpreted():
    # A JSON API reflects the value JSON-string-escaped: backslash -> \\ and NUL ->
    # \u0000. That is response-format serialization, NOT sink interpretation — must
    # NOT be flagged (regression for the benign-JSON-echo false "corroborated").
    bs = dict((n, t) for n, t, *_ in interpmod.MARKERS)["backslash"]
    body = json.dumps({"q": interpmod.build_probe("ctl123", bs)})   # ctl123\ -> "...ctl123\\"
    assert interpmod.assess_marker("ctl123", bs, body)["interpreted"] is False
    nb = dict((n, t) for n, t, *_ in interpmod.MARKERS)["null_byte"]
    body = json.dumps({"q": interpmod.build_probe("ctl123", nb)})   # NUL -> \u0000
    assert interpmod.assess_marker("ctl123", nb, body)["interpreted"] is False


def test_assess_marker_percent_reflection_not_interpreted():
    # A page reflecting the raw still-percent-encoded query (canonical <link>/og:url):
    # the backslash comes back as %5C, the quote as %27 — reproduced, not interpreted.
    from urllib.parse import quote
    for key in ("backslash", "quote", "brace", "path_dot_segment"):
        tmpl = dict((n, t) for n, t, *_ in interpmod.MARKERS)[key]
        sent = interpmod.build_probe("ctl123", tmpl)
        body = f'<link rel="canonical" href="/s?q={quote(sent, safe="")}">'
        assert interpmod.assess_marker("ctl123", tmpl, body)["interpreted"] is False, key


def test_assess_marker_not_observed_when_control_absent():
    _name, template, _tools, _desc = interpmod.MARKERS[0]
    res = interpmod.assess_marker("ctl123", template, "<html>unrelated content</html>")
    assert res == {"observed": False, "interpreted": False}


def test_verdict_thresholds():
    assert interpmod.verdict([{"interpreted": False}, {"interpreted": False}]) == "none"
    assert interpmod.verdict([{"interpreted": True}, {"interpreted": False}]) == "weak"
    assert interpmod.verdict([{"interpreted": True}, {"interpreted": True}]) == "corroborated"
    assert interpmod.verdict([]) == "none"


def test_suggest_next_dedupes_and_only_uses_interpreted_markers():
    hits = [
        {"marker": "backslash", "interpreted": True},
        {"marker": "quote", "interpreted": True},        # also suggests sqli_probe/cmdi_probe
        {"marker": "brace", "interpreted": False},        # not interpreted -> excluded
    ]
    suggestions = interpmod.suggest_next(hits)
    assert suggestions.count("sqli_probe") == 1            # deduped across markers
    assert "ssti_probe" not in suggestions                  # brace's suggestion excluded
    assert "nosqli_probe" in suggestions


# -- end-to-end -------------------------------------------------------------------
@pytest.mark.asyncio
async def test_interp_probe_registered(fresh_context):
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "interp_probe" in tools


@pytest.mark.asyncio
async def test_interp_probe_corroborated_on_vulnerable_endpoint(local_server, fresh_context):
    base, _ = local_server
    res = await srv.interp_probe(target=f"{base}/interp-vuln", param="q")
    assert res["verdict"] == "corroborated"
    assert res["corroborating_markers"] >= 2
    assert len(res["markers"]) == len(interpmod.MARKERS)
    assert res["suggested_next"]  # non-empty


@pytest.mark.asyncio
async def test_interp_probe_none_on_safe_endpoint(local_server, fresh_context):
    base, _ = local_server
    res = await srv.interp_probe(target=f"{base}/interp-safe", param="q")
    assert res["verdict"] == "none"
    assert res["corroborating_markers"] == 0
    assert res["suggested_next"] == []


@pytest.mark.asyncio
async def test_interp_probe_not_corroborated_on_json_echo(local_server, fresh_context):
    # A benign JSON API that reflects the value JSON-string-escaped must NOT reach the
    # top "corroborated" verdict — the \\ / \u0000 doubling is serialization, not a
    # sink interpreting the marker. Regression for the false-positive lead.
    base, _ = local_server
    res = await srv.interp_probe(target=f"{base}/interp-jsonecho", param="q")
    assert res["verdict"] != "corroborated", res
    assert res["corroborating_markers"] < 2, res
