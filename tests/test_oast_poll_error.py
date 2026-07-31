"""_collect_oast must distinguish a clean 'no callback yet' from a poll FAILURE.

A swallowed poll error rendered as a clean no-hit is a silent miss — the one
failure mode a detection tool cannot have. These tests pin the three outcomes.
"""

import types

import pytest

from moonmcp import server as srv


class _FakeResp:
    def __init__(self, status, text=""):
        self.status = status
        self.error = None if status else "connection refused"
        self._text = text

    def text(self, limit=None):
        return self._text


class _FakeHttp:
    def __init__(self, behavior):
        self._behavior = behavior

    async def fetch(self, *a, **k):
        return self._behavior()


class _FakeOast:
    def __init__(self, poll):
        self._poll = poll

    def poll_target(self, token):
        return self._poll


def _ctx(http, poll="http://poll.example/collect", server=None):
    return types.SimpleNamespace(oast_server=server, oast=_FakeOast(poll), http=http)


@pytest.mark.asyncio
async def test_collect_oast_reports_fetch_exception():
    def boom():
        raise ConnectionError("refused")

    hits, err = await srv._collect_oast(_ctx(_FakeHttp(boom)), "tok")
    assert hits == []
    assert err and "poll request failed" in err


@pytest.mark.asyncio
async def test_collect_oast_reports_unreachable_status_none():
    hits, err = await srv._collect_oast(_ctx(_FakeHttp(lambda: _FakeResp(None))), "tok")
    assert hits == []
    assert err and "poll request failed" in err


@pytest.mark.asyncio
async def test_collect_oast_clean_no_hit_has_no_error():
    hits, err = await srv._collect_oast(_ctx(_FakeHttp(lambda: _FakeResp(200, "[]"))), "tok")
    assert hits == []
    assert err is None


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [401, 403, 404, 500, 502])
async def test_collect_oast_reports_http_error_status(status):
    # A non-2xx poll response is NOT a clean no-hit: the channel could not be read
    # (auth expired, token unknown, server down). Parsing its error body would yield
    # [] and render as "no callback fired" — the exact silent miss to avoid.
    hits, err = await srv._collect_oast(
        _ctx(_FakeHttp(lambda: _FakeResp(status, "<html>error</html>"))), "tok")
    assert hits == []
    assert err and f"HTTP {status}" in err


@pytest.mark.asyncio
async def test_collect_oast_no_poll_target_is_not_an_error():
    hits, err = await srv._collect_oast(
        _ctx(_FakeHttp(lambda: _FakeResp(200)), poll=None), "tok")
    assert hits == []
    assert err is None


@pytest.mark.asyncio
async def test_collect_oast_hit_is_returned():
    body = '[{"protocol": "dns", "unique-id": "abc"}]'
    hits, err = await srv._collect_oast(_ctx(_FakeHttp(lambda: _FakeResp(200, body))), "tok")
    assert len(hits) == 1
    assert err is None
