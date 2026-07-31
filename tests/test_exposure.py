"""Exposed-VCS detection — soft-404 / SPA guard for the empty-signature files."""

import pytest

from moonmcp.web import exposure as exp


class _R:
    def __init__(self, status, body=b""):
        self.status = status
        self.body = body if isinstance(body, bytes) else body.encode()

    def text(self, limit=None):
        return self.body.decode("utf-8", "replace")


class _Client:
    def __init__(self, routes, default):
        self._routes = routes      # {path-suffix: _R}
        self._default = default

    async def fetch(self, url, **kw):
        for suffix, r in self._routes.items():
            if url.endswith(suffix):
                return r
        return self._default


@pytest.mark.asyncio
async def test_spa_html_fallback_is_not_git_exposed():
    # An SPA returns 200 + index.html for EVERY unknown path, including /.git/logs/HEAD.
    # That must NOT read as an exposed .git (the empty-signature false positive).
    html = _R(200, "<!doctype html><html><body>app</body></html>")
    res = await exp.check_exposure(_Client({}, html), "https://spa.test/")
    assert res.git_exposed is False
    assert all(not e.confirmed for e in res.exposed)


@pytest.mark.asyncio
async def test_plaintext_soft404_empty_signature_not_confirmed():
    # A soft-404 returning 200 + plain "Not Found" for /.git/logs/HEAD must not confirm:
    # an empty signature no longer means "any 200 body".
    res = await exp.check_exposure(_Client({}, _R(200, "Not Found")), "https://x.test/")
    assert res.git_exposed is False
    assert all(not e.confirmed for e in res.exposed)


@pytest.mark.asyncio
async def test_real_git_confirms():
    # Real content: HEAD 'ref:' and a genuine reflog line (40-hex 40-hex ...) confirm.
    routes = {
        "/.git/HEAD": _R(200, "ref: refs/heads/main\n"),
        "/.git/logs/HEAD": _R(200, "0" * 40 + " " + "a" * 40 + " Dev <d@e> 1700000000 +0000\tcommit\n"),
    }
    res = await exp.check_exposure(_Client(routes, _R(404)), "https://real.test/")
    assert res.git_exposed is True
    confirmed = {e.path for e in res.exposed if e.confirmed}
    assert confirmed == {"/.git/HEAD", "/.git/logs/HEAD"}
    assert res.recent_commits            # parsed from the reflog


@pytest.mark.asyncio
async def test_hg_requires_positive_and_negative():
    # A real /.hg/requires is lowercase tokens; an HTML SPA fallback is not.
    good = _R(200, "revlogv1\nstore\nfncache\ndotencode\ngeneraldelta\n")
    res = await exp.check_exposure(_Client({"/.hg/requires": good}, _R(404)), "https://h.test/")
    assert any(e.path == "/.hg/requires" and e.confirmed for e in res.exposed)
