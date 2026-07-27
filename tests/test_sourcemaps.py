"""Source-map recovery + secret extraction."""

import json

import pytest

from moonmcp import server as srv
from moonmcp.recon import sourcemaps as sm

_GHP = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"  # a valid-shaped GitHub PAT (36 chars)

_MAP = {
    "version": 3,
    "file": "app.min.js",
    "sourceRoot": "",
    "sources": ["webpack://app/./src/config.js", "webpack://app/./node_modules/lodash/lodash.js"],
    "sourcesContent": [
        f"export const cfg = {{ token: '{_GHP}' }};  // internal config",
        "/* huge vendor lib */ module.exports = {};",
    ],
}


# -- pure helpers -----------------------------------------------------------
def test_parse_tolerates_xssi_prefix():
    raw = ")]}'\n" + json.dumps(_MAP)
    assert sm.parse_source_map(raw).get("version") == 3
    assert sm.parse_source_map("not json at all") == {}


def test_is_vendor():
    assert sm.is_vendor("webpack://app/./node_modules/lodash/lodash.js") is True
    assert sm.is_vendor("webpack://app/./src/config.js") is False


def test_recover_files_pairs_and_classifies():
    files, truncated = sm.recover_files(_MAP)
    assert truncated is False and len(files) == 2
    app = [f for f in files if not f["vendor"]]
    assert len(app) == 1 and app[0]["path"].endswith("src/config.js")
    assert app[0]["interesting"] is True   # "config" in path
    assert app[0]["recovered"] is True


def test_recover_files_handles_missing_content():
    m = {"sources": ["a.js", "b.js"], "sourcesContent": ["x=1"]}  # b.js has no content
    files, _ = sm.recover_files(m)
    assert files[0]["recovered"] is True and files[1]["recovered"] is False


# -- recover via fake client ------------------------------------------------
class _R:
    def __init__(self, status, body="", final_url=""):
        self.status = status
        self.body = body.encode() if isinstance(body, str) else body
        self.final_url = final_url or ""
        self.error = None

    def text(self, limit=None):
        return self.body.decode()


class _MapClient:
    """Serves the source map only for a `.map` URL."""

    async def fetch(self, url, **kwargs):
        if url.endswith(".map"):
            return _R(200, json.dumps(_MAP), final_url=url)
        return _R(404, "nope", final_url=url)


@pytest.mark.asyncio
async def test_recover_extracts_source_and_secret():
    res = await sm.recover(_MapClient(), "https://x.test/static/app.min.js.map")
    assert res["recovered"] is True
    assert res["app_source_count"] == 1          # vendor lodash excluded
    assert res["secret_count"] >= 1
    assert any(s["type"] == "GitHub PAT" for s in res["secrets"])
    assert all(s["file"].endswith("src/config.js") for s in res["secrets"])
    assert any("config" in p for p in res["interesting_files"])


@pytest.mark.asyncio
async def test_recover_reports_missing_map():
    class _NoMap:
        async def fetch(self, url, **kwargs):
            return _R(404, "", final_url=url)

    res = await sm.recover(_NoMap(), "https://x.test/app.js")
    assert res["recovered"] is False


# -- registration -----------------------------------------------------------
@pytest.mark.asyncio
async def test_recover_sourcemaps_tool_registered():
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "recover_sourcemaps" in tools
