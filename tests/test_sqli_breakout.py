"""The sqli_probe breakout lane: engine-error-feedback loop (Juice-Shop calibration)."""
import asyncio
import pytest


class _FakeResult:
    def __init__(self, status, body):
        self.status = status
        self.body = body.encode()

    def text(self, limit=None):
        s = self.body.decode(errors="replace")
        return s[:limit] if limit else s


class _Engine:
    """SQLite-ish engine: UNION with n != 5 columns → mismatch page; n == 5 → data."""

    async def fetch(self, url, **kw):
        q = url.split("q=")[1] if "q=" in url else ""
        if q.count("null") and q.count("null") < 5:
            return _FakeResult(500, "<title>Error: SQLITE_ERROR: SELECTs to the left "
                                    "and right of UNION do not have the same number "
                                    "of result columns</title>")
        return _FakeResult(200, '{"status":"success","data":[]}')


def test_breakout_lane_resolves_columns_and_verdict():
    pytest.importorskip("moonmcp")
    from moonmcp.context import build_context
    from moonmcp.config import Settings
    import moonmcp.server as srv

    async def run():
        st = Settings(enforce_scope=False, block_private=False, allow_intrusive=True,
                      scope=["127.0.0.1"], state_dir="/tmp/mcpstate-tests")
        ctx = build_context(st)
        ctx.http = _Engine()
        saved = srv.get_context
        srv.get_context = lambda: ctx
        try:
            return await srv.sqli_probe("http://127.0.0.1:3000/rest/products/search",
                                        "q", method="GET", breakout=True)
        finally:
            srv.get_context = saved

    r = asyncio.run(run())
    assert r["verdict"] in ("likely", "confirmed")
    assert r["score"] >= 3
    assert "sqli/union-error-based" in ",".join(r["signals"])
    lane = r["lanes"]["like_breakout"]
    assert lane["union_reachable"] is True
    assert lane["mismatch_column_counts"][:4] == [1, 2, 3, 4]
    assert lane["resolved_columns"] == 5


def test_brotli_body_decodes_when_binding_present():
    pytest.importorskip("brotli")
    from moonmcp.net.http import _decode_body
    import brotli
    raw = brotli.compress(b"<title>Error: SQLITE_ERROR: SELECTs to the left and right of UNION</title>")
    out, _trunc = _decode_body(raw, "br", 100_000)
    assert b"UNION" in out
