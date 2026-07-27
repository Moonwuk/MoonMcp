"""Single-packet race via HTTP/1.1 last-byte synchronization."""

import itertools

import pytest

from moonmcp import server as srv
from moonmcp.web import singlepacket as sp


# -- pure helpers -----------------------------------------------------------
def test_split_last_byte():
    assert sp.split_last_byte(b"abc") == (b"ab", b"c")
    assert sp.split_last_byte(b"a") == (b"", b"a")
    assert sp.split_last_byte(b"") == (b"", b"")


def test_build_request_shape_and_reassembly():
    req = sp.build_request("acme.test", "/coupon?x=1", method="POST",
                           headers={"Cookie": "s=1"}, body="code=SAVE")
    text = req.decode()
    assert text.startswith("POST /coupon?x=1 HTTP/1.1\r\n")
    assert "Host: acme.test\r\n" in text and "Cookie: s=1\r\n" in text
    assert "Content-Length: 9\r\n" in text          # len("code=SAVE")
    assert req.endswith(b"code=SAVE")
    # the withheld last byte + head reassemble to the original request
    head, last = sp.split_last_byte(req)
    assert head + last == req and last == b"E"


def test_assess_race_verdict():
    assert sp.assess_race([200, 200, 429])["success_2xx"] == 2
    assert sp.assess_race([200, 200, 429])["verdict"] == "review"
    assert sp.assess_race([429, 429])["verdict"] == "no_race_signal"
    assert sp.assess_race([200])["verdict"] == "no_race_signal"   # single success ≠ race
    assert sp.assess_race([None, None])["success_2xx"] == 0


# -- orchestration via injected fake sockets --------------------------------
class _FakeWriter:
    def __init__(self, log, idx):
        self.log, self.idx, self.closed = log, idx, False

    def write(self, data):
        self.log.append((self.idx, data))

    async def drain(self):
        pass

    def close(self):
        self.closed = True


class _FakeReader:
    def __init__(self, resp):
        self._resp = resp

    async def read(self, n):
        return self._resp


@pytest.mark.asyncio
async def test_single_packet_race_synchronizes_last_byte():
    log: list = []
    counter = itertools.count()

    async def fake_connect(host, port, tls, timeout):
        return (_FakeReader(b"HTTP/1.1 200 OK\r\n\r\n"), _FakeWriter(log, next(counter)))

    res = await sp.single_packet_race("acme.test", 443, True,
                                      sp.build_request("acme.test", "/buy", body="x=1"),
                                      6, settle=0.0, connect=fake_connect)
    assert res["connections"] == 6 and res["success_2xx"] == 6
    assert res["verdict"] == "review" and res["technique"] == "http1-last-byte-sync"

    # every connection got the head first, then the single withheld last byte
    heads = [e for e in log if len(e[1]) > 1]
    lasts = [e for e in log if len(e[1]) == 1]
    assert len(heads) == 6 and len(lasts) == 6
    # BARRIER: all heads are written before any last byte is released
    last_head_pos = max(i for i, e in enumerate(log) if len(e[1]) > 1)
    first_last_pos = min(i for i, e in enumerate(log) if len(e[1]) == 1)
    assert last_head_pos < first_last_pos


@pytest.mark.asyncio
async def test_single_packet_race_needs_two_connections():
    async def failing_connect(host, port, tls, timeout):
        raise OSError("refused")

    res = await sp.single_packet_race("acme.test", 443, True, b"GET / HTTP/1.1\r\n\r\n",
                                      5, settle=0.0, connect=failing_connect)
    assert res["success_2xx"] == 0 and "error" in res


# -- registration -----------------------------------------------------------
@pytest.mark.asyncio
async def test_race_probe_tool_still_registered():
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "race_probe" in tools
