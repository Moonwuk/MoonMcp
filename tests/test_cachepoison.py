"""Web cache poisoning — unkeyed reflection + stateful cache-hit confirmation."""

from urllib.parse import urlsplit

import pytest

from moonmcp.web import cachepoison as cp

CANARY = "moonpc1234"
BUSTER = "mcbABCD"


# -- pure analysers ---------------------------------------------------------
def test_cache_buster_never_contains_canary():
    u = cp.with_cache_buster("http://x.test/p?a=1", BUSTER + "0")
    assert u == "http://x.test/p?a=1&cb=mcbABCD0"
    assert CANARY not in u                                # the buster must be canary-free


def test_reflects_canary_body_and_header():
    assert cp.reflects_canary(CANARY, f"x {CANARY}.moon y", {})
    assert cp.reflects_canary(CANARY, "", {"Location": f"https://{CANARY}.moon.example/"})
    assert not cp.reflects_canary(CANARY, "nothing here", {"Server": "nginx"})


def test_is_keyed_vary():
    assert cp.is_keyed("X-Forwarded-Host", {"Vary": "Accept-Encoding, X-Forwarded-Host"})
    assert cp.is_keyed("X-Host", {"Vary": "*"})
    assert not cp.is_keyed("X-Forwarded-Host", {"Vary": "Accept-Encoding"})


def test_cache_hit_signals():
    assert cp.cache_hit_signals({"Age": "30", "X-Cache": "HIT"}) == ["age: 30", "x-cache: HIT"]
    assert cp.cache_hit_signals({"Server": "x"}) == []


# -- fake apps --------------------------------------------------------------
class _R:
    def __init__(self, status, body, headers):
        self.status = status
        self._body = body.encode() if isinstance(body, str) else body
        self._h = headers

    def text(self, limit=None):
        return self._body.decode("latin-1", "replace")

    def headers_map(self):
        return dict(self._h)


_CC = {"Content-Type": "text/html", "Cache-Control": "public, max-age=60"}


class _CachingApp:
    """A shared cache keyed on URL (incl. cb) but NOT on the unkeyed header — the vulnerable case:
    the first request to a URL fills the cache, later requests to the same URL replay it."""

    def __init__(self):
        self.cache: dict = {}

    async def fetch(self, u, *, headers=None, follow_redirects=False, scope_check=None, **kw):
        if u in self.cache:
            body, h = self.cache[u]
            return _R(200, body, {**h, "Age": "30", "X-Cache": "HIT"})
        xfh = (headers or {}).get("X-Forwarded-Host", "")
        body = f"<link href='//{xfh}/s.css'>"
        self.cache[u] = (body, {**_CC, "X-Cache": "MISS"})
        return _R(200, body, {**_CC, "X-Cache": "MISS"})


class _ReflectNoCacheApp:
    """Reflects the header every request but never serves from cache (no poisoning)."""

    async def fetch(self, u, *, headers=None, **kw):
        xfh = (headers or {}).get("X-Forwarded-Host", "")
        return _R(200, f"<link href='//{xfh}/s.css'>", dict(_CC))


class _KeyedApp:
    """Reflects X-Forwarded-Host but marks it in Vary — part of the cache key, not poisonable."""

    async def fetch(self, u, *, headers=None, **kw):
        xfh = (headers or {}).get("X-Forwarded-Host", "")
        return _R(200, f"//{xfh}/s.css", {**_CC, "Vary": "X-Forwarded-Host"})


class _QueryReflectApp:
    """Reflects the whole query string (incl. the cb buster). Must NOT be read as a cache hit —
    the buster token is not the canary, so the clean request carries no canary."""

    async def fetch(self, u, *, headers=None, **kw):
        q = urlsplit(u).query
        xfh = (headers or {}).get("X-Forwarded-Host", "")
        return _R(200, f"query={q} xfh={xfh}", dict(_CC))


class _NoReflectApp:
    async def fetch(self, u, *, headers=None, **kw):
        return _R(200, "<html>static</html>", dict(_CC))


async def _run(app):
    return await cp.probe_cache_poison(app, "http://x.test/p", canary=CANARY, buster=BUSTER)


# -- probe behavior ---------------------------------------------------------
@pytest.mark.asyncio
async def test_confirmed_when_served_from_cache():
    res = await _run(_CachingApp())
    assert res["verdict"] == "confirmed"
    f = next(x for x in res["findings"] if x["header"] == "X-Forwarded-Host")
    assert f["confirmed"] is True and f["severity"] == "high" and f["cache_signals"]


@pytest.mark.asyncio
async def test_likely_when_reflected_but_not_cached():
    res = await _run(_ReflectNoCacheApp())
    assert res["verdict"] == "likely"
    f = next(x for x in res["findings"] if x["header"] == "X-Forwarded-Host")
    assert f["reflected"] is True and f["confirmed"] is False


@pytest.mark.asyncio
async def test_vary_keyed_header_is_skipped():
    res = await _run(_KeyedApp())
    assert res["verdict"] == "unconfirmed" and res["findings"] == []


@pytest.mark.asyncio
async def test_query_reflection_of_buster_does_not_false_confirm():
    # the app echoes the cb buster; because the buster is not the canary, the clean request
    # carries no canary → must stay 'likely', never 'confirmed'
    res = await _run(_QueryReflectApp())
    assert res["verdict"] == "likely"
    assert all(not f["confirmed"] for f in res["findings"])


@pytest.mark.asyncio
async def test_no_reflection_unconfirmed():
    res = await _run(_NoReflectApp())
    assert res["verdict"] == "unconfirmed" and res["findings"] == []
