"""Modern desync (0.CL / TE.0 / Expect / chunk-ext) — payload + interpretation."""

import pytest

from moonmcp import server as srv
from moonmcp.web import desync as d


# -- payload construction ---------------------------------------------------
def test_payloads_are_shaped_correctly():
    p = d._modern_payloads("acme.test", "/")
    # control is a complete, terminated request
    assert p["control"].endswith(b"\r\n\r\n")
    # TE.0 probe: chunked but NO terminating 0-chunk (deliberately incomplete)
    assert b"Transfer-Encoding: chunked" in p["te0_incomplete"]
    assert not p["te0_incomplete"].rstrip().endswith(b"0")
    assert b"0\r\n\r\n" not in p["te0_incomplete"]
    # CL.0 probe: Content-Length far larger than the body actually sent
    assert b"Content-Length: 200" in p["cl_partial"] and p["cl_partial"].endswith(b"\r\nx")
    # Expect twins differ only in the malformed token
    assert b"Expect: 100-continue" in p["expect_100"]
    assert b"Expect: y 100-continue" in p["expect_malformed"]
    # chunk-extension on the terminating chunk (a complete message)
    assert b"0;moonmcp=1\r\n\r\n" in p["chunk_ext"]
    # every probe closes its own connection
    assert all(b"Connection: close" in raw for raw in p.values())


# -- interpretation (pure) --------------------------------------------------
def _resp(status):
    return {"status": status, "outcome": "response", "elapsed_ms": 40.0}


def _timeout():
    return {"status": None, "outcome": "read_timeout", "elapsed_ms": 6000.0}


def test_no_baseline_no_indicators():
    ind, risk = d.interpret_modern({"control": {"status": None, "outcome": "read_timeout"}})
    assert ind == [] and risk == "low"


def test_normal_server_no_signal():
    # server honours framing: it HANGS on the incomplete probes → no signal
    probes = {
        "control": _resp(200), "te0_incomplete": _timeout(), "cl_partial": _timeout(),
        "expect_100": _timeout(), "expect_malformed": _timeout(), "chunk_ext": _resp(200),
    }
    ind, risk = d.interpret_modern(probes)
    assert ind == [] and risk == "low"


def test_te0_candidate_flagged():
    probes = {
        "control": _resp(200), "te0_incomplete": _resp(200), "cl_partial": _timeout(),
        "expect_100": _timeout(), "expect_malformed": _timeout(), "chunk_ext": _resp(200),
    }
    ind, risk = d.interpret_modern(probes)
    assert risk == "review" and any("TE.0" in i for i in ind)


def test_cl0_candidate_flagged():
    probes = {
        "control": _resp(200), "te0_incomplete": _timeout(), "cl_partial": _resp(200),
        "expect_100": _timeout(), "expect_malformed": _timeout(), "chunk_ext": _resp(200),
    }
    ind, risk = d.interpret_modern(probes)
    assert risk == "review" and any("CL.0" in i for i in ind)


def test_rejection_is_not_a_signal():
    # a fast 4xx on the ambiguous probes = rejection, not acceptance → no signal
    probes = {
        "control": _resp(200), "te0_incomplete": _resp(400), "cl_partial": _resp(408),
        "expect_100": _timeout(), "expect_malformed": _timeout(), "chunk_ext": _resp(200),
    }
    ind, risk = d.interpret_modern(probes)
    assert ind == [] and risk == "low"


def test_expect_divergence_flagged():
    probes = {
        "control": _resp(200), "te0_incomplete": _timeout(), "cl_partial": _timeout(),
        "expect_100": {"status": 100, "outcome": "response"},
        "expect_malformed": _resp(200), "chunk_ext": _resp(200),
    }
    ind, risk = d.interpret_modern(probes)
    assert risk == "review" and any("0.CL" in i for i in ind)


def test_chunk_ext_divergence_flagged():
    # the extension-bearing request was ACCEPTED (<400) but routed differently (301) than
    # the control (200) — a chunk-extension parsing divergence
    probes = {
        "control": _resp(200), "te0_incomplete": _timeout(), "cl_partial": _timeout(),
        "expect_100": _timeout(), "expect_malformed": _timeout(), "chunk_ext": _resp(301),
    }
    ind, risk = d.interpret_modern(probes)
    assert any("chunk-extension" in i for i in ind)


# -- registration -----------------------------------------------------------
@pytest.mark.asyncio
async def test_desync_modern_tool_registered_and_intrusive():
    tools = {t.name: t for t in await srv.mcp.list_tools()}
    assert "desync_modern_probe" in tools
