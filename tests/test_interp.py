"""interp_probe — generic differential "interpretation" prober, pure + e2e."""

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


def test_assess_marker_json_escaping_not_interpreted():
    # In a JSON response, a backslash is serialised as \\ and a NUL as the six chars
    # backslash-u-0-0-0-0. That is mandatory JSON transport encoding, NOT value
    # interpretation, so a plain JSON echo must not fire the backslash / null-byte markers.
    markers = dict((n, t) for n, t, *_ in interpmod.MARKERS)
    bs, nb = markers["backslash"], markers["null_byte"]

    sent_bs = interpmod.build_probe("ctl123", bs)                    # ends with one backslash
    body_bs = '{"echo":"' + sent_bs.replace("\\", "\\\\") + '"}'     # JSON-doubled backslash
    assert interpmod.assess_marker("ctl123", bs, body_bs, json_body=True)["interpreted"] is False
    assert interpmod.assess_marker("ctl123", bs, body_bs)["interpreted"] is True   # non-JSON still fires

    sent_nb = interpmod.build_probe("ctl123", nb)                    # contains a raw NUL
    body_nb = '{"echo":"' + sent_nb.replace("\x00", "\\u0000") + '"}'
    assert interpmod.assess_marker("ctl123", nb, body_nb, json_body=True)["interpreted"] is False

    body_strip = '{"echo":"ctl123"}'                                 # backslash gone entirely
    assert interpmod.assess_marker("ctl123", bs, body_strip, json_body=True)["interpreted"] is True
