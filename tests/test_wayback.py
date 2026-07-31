"""Wayback CDX parsing — robust to malformed third-party rows."""

import asyncio
import json

from moonmcp.recon import wayback as wb


class _Resp:
    def __init__(self, body, status=200):
        self._b = body.encode() if isinstance(body, str) else body
        self.status = status
        self.error = None
        self.body = self._b

    def text(self, limit=None):
        return self._b.decode()


class _Client:
    def __init__(self, body, status=200):
        self._r = _Resp(body, status)

    async def fetch(self, url, **kw):
        return self._r


def test_wayback_parses_well_formed_rows():
    body = json.dumps([["original"], ["https://x.test/a"], ["https://x.test/api/key=1"]])
    r = asyncio.run(wb.fetch_wayback_urls(_Client(body), "x.test"))
    assert r.error is None
    assert "https://x.test/a" in r.urls
    assert any("api/" in u for u in r.interesting)


def test_wayback_survives_malformed_rows():
    # a MITM-able / changed CDX feed may include non-list rows or non-string cells;
    # they must be skipped, not crash with TypeError/KeyError.
    body = json.dumps([
        ["original"],
        ["https://x.test/ok"],
        123,                       # non-list row
        {"not": "a row"},          # dict row
        [None],                    # first cell not a string
        [],                        # empty row
        ["https://x.test/ok2"],
    ])
    r = asyncio.run(wb.fetch_wayback_urls(_Client(body), "x.test"))
    assert r.error is None
    assert set(r.urls) == {"https://x.test/ok", "https://x.test/ok2"}
