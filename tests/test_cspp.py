"""Client-side prototype-pollution probe — pure helpers + live headless-browser eval.

Playwright is optional: the live tests drive a real Chromium against a deliberately-
vulnerable local SPA and skip when the browser is absent.
"""

import pytest

from moonmcp import server as srv
from moonmcp.web import browser as brmod
from moonmcp.web import cspp

_HAVE = brmod.playwright_available()
_skip_live = pytest.mark.skipif(not _HAVE, reason="Playwright/Chromium not installed")


# -- pure helpers ------------------------------------------------------------
_M = "mooncsppz_test"


def test_vectors_cover_query_and_hash_and_both_roots():
    vs = {label: (u, is_hash) for label, u, is_hash in cspp.vectors("https://x/app", _M)}
    assert any(k.startswith("query:") for k in vs) and any(k.startswith("hash:") for k in vs)
    # both roots, both notations
    assert {"query:proto_bracket", "hash:constructor_bracket",
            "query:proto_dotted", "hash:constructor_dotted"} <= set(vs)
    qurl, qhash = vs["query:proto_bracket"]
    assert qurl.split("?", 1)[1].startswith("__proto__") and qhash is False
    hurl, hhash = vs["hash:proto_bracket"]
    assert "#__proto__" in hurl and hhash is True
    assert cspp.SENTINEL in qurl and _M in qurl


def test_scripts_read_the_marker():
    assert "Object.prototype" in cspp.read_script(_M) and _M in cspp.read_script(_M)
    hs = cspp.hashchange_script(_M)
    assert "hash" in hs and _M in hs and "Promise" in hs         # fires hashchange then reads


def test_assess_is_presence_based_and_value_agnostic():
    assert cspp.assess(None, cspp.SENTINEL) is True              # clean baseline → present
    assert cspp.assess(None, True) is True                       # value-agnostic (parser set true)
    assert cspp.assess(None, "") is True                         # even an empty-string write counts
    assert cspp.assess(None, None) is False                      # nothing set
    # marker already present on a clean load ⇒ not attributable to our payload
    assert cspp.assess(cspp.SENTINEL, cspp.SENTINEL) is False


# -- live against the deliberately-vulnerable /cspp SPA ----------------------
@_skip_live
@pytest.mark.asyncio
async def test_cspp_probe_detects_pollution(local_server, fresh_context):
    base, _ = local_server
    res = await srv.cspp_probe(target=f"{base}/cspp")
    assert res["available"] is True, res
    vs = {h["vector"] for h in res["vectors"]}
    assert vs, res                                              # at least one vector polluted
    # both a query source and a hash source reach the sink
    assert any(v.startswith("query:") for v in vs) and any(v.startswith("hash:") for v in vs), res
    assert res["polluted_property"].startswith(cspp.MARKER_PREFIX)
    assert res["baseline_marker"] is None                      # not present on a clean load
    assert res["verdict"] in ("likely", "confirmed"), res


@_skip_live
@pytest.mark.asyncio
async def test_cspp_probe_no_false_positive(local_server, fresh_context):
    base, _ = local_server
    res = await srv.cspp_probe(target=f"{base}/cspp-safe")
    assert res["available"] is True, res
    assert res["vectors"] == [], res                           # hardened parser blocks the keys
    assert res["verdict"] == "unconfirmed", res


@pytest.mark.asyncio
async def test_cspp_probe_degrades_without_playwright(monkeypatch, fresh_context):
    monkeypatch.setattr(brmod, "playwright_available", lambda: False)
    res = await srv.cspp_probe(target="http://127.0.0.1:1/")
    assert res["available"] is False
    assert res.get("install_hint")


@pytest.mark.asyncio
async def test_cspp_probe_registered():
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "cspp_probe" in tools
