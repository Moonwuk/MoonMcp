"""Built-in OAST callback catcher: canary minting + callback capture."""

import urllib.request

import pytest

from moonmcp import server as srv
from moonmcp.intel.oast_server import CallbackServer, _extract_token


def test_extract_token_from_path_query_host():
    assert _extract_token("/abc123/x", "") == "abc123"
    assert _extract_token("/?token=deadbeef", "") == "deadbeef"
    assert _extract_token("/", "tok9.oast.example:80") == "tok9"


def test_callback_server_records_and_filters():
    s = CallbackServer(host="127.0.0.1")
    s.start()
    try:
        base = s.base()
        urllib.request.urlopen(f"http://{base}/tokenA/probe", timeout=3).read()
        urllib.request.urlopen(f"http://{base}/tokenB", timeout=3).read()
        assert len(s.interactions()) == 2
        a = s.interactions("tokenA")
        assert len(a) == 1 and a[0]["method"] == "GET"
        assert s.interactions("nope") == []
    finally:
        s.stop()


@pytest.mark.asyncio
async def test_oast_selfhost_tool_lifecycle_and_pathmode(fresh_context):
    started = await srv.oast_selfhost(action="start", host="127.0.0.1")
    assert started["running"] is True and ":" in started["base"]
    # Canaries are now path-based against the local catcher.
    cb = await srv.oast_generate()
    assert cb["http_url"].startswith(f"http://{started['base']}/")
    status = await srv.oast_selfhost(action="status")
    assert status["running"] is True
    stopped = await srv.oast_selfhost(action="stop")
    assert stopped["running"] is False
