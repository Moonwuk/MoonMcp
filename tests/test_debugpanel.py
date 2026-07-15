"""Framework debug / console exposure detection."""

import pytest

from moonmcp import server as srv
from moonmcp.web import debugpanel as dp


class _R:
    def __init__(self, status, body=b""):
        self.status = status
        self.body = body

    def text(self, limit=None):
        return self.body.decode() if isinstance(self.body, bytes) else self.body


class _Site:
    """Serves a fixed body per path; 404 for anything unmapped."""

    def __init__(self, pages):
        self._pages = pages

    async def fetch(self, url, **kwargs):
        for path, (status, body) in self._pages.items():
            if url.endswith(path):
                return _R(status, body.encode() if isinstance(body, str) else body)
        return _R(404, b"not found")


@pytest.mark.asyncio
async def test_flags_symfony_profiler_and_ignition():
    site = _Site({
        "/_profiler": (200, "<html><div class='sf-toolbar'>Symfony Profiler</div></html>"),
        "/_ignition/health-check": (200, '{"can_execute_commands":true}'),
    })
    res = await dp.probe_debug_panels(site, "https://x.test")
    labels = {f["label"] for f in res}
    assert "Symfony profiler" in labels and "Laravel Ignition" in labels
    assert all(f["verdict"] == "confirmed" for f in res)


@pytest.mark.asyncio
async def test_flags_actuator_env_and_werkzeug_console():
    site = _Site({
        "/actuator/env": (200, '{"activeProfiles":["prod"],"propertySources":[]}'),
        "/console": (200, "<html>Werkzeug Debugger __debugger__ The console</html>"),
    })
    res = await dp.probe_debug_panels(site, "https://x.test")
    by = {f["label"]: f for f in res}
    assert "Spring Boot Actuator /env" in by
    assert by["Werkzeug/Flask debugger"]["severity"] == "critical"


@pytest.mark.asyncio
async def test_no_false_positive_on_generic_200():
    # a generic app page at every path must not be flagged
    site = _Site({})  # everything → 404
    assert await dp.probe_debug_panels(site, "https://x.test") == []

    site2 = _Site({"/_profiler": (200, "<html><body>Welcome to our shop</body></html>")})
    assert await dp.probe_debug_panels(site2, "https://x.test") == []


@pytest.mark.asyncio
async def test_flags_db_admin_consoles():
    site = _Site({
        "/db/admin": (200, "<html><title>Mongo Express</title><div id='leftPanel'></div></html>"),
        "/play": (200, "<html>ClickHouse Play UI <textarea class='play-textarea'></textarea></html>"),
    })
    res = await dp.probe_debug_panels(site, "https://x.test")
    by = {f["label"]: f for f in res}
    assert by["Mongo-Express"]["severity"] == "high"
    assert "ClickHouse /play" in by


@pytest.mark.asyncio
async def test_debug_exposure_tool_registered():
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "debug_exposure" in tools


@pytest.mark.asyncio
async def test_generic_console_phrase_not_flagged_as_werkzeug():
    # A benign /console page that merely says "The console" must not be reported as
    # a CRITICAL Werkzeug pre-auth RCE (the generic signature was removed).
    site = _Site({"/console": (200, "<html>The console lets you manage your account.</html>")})
    res = await dp.probe_debug_panels(site, "https://x.test")
    assert all(f["label"] != "Werkzeug/Flask debugger" for f in res)
    # a REAL Werkzeug debugger is still flagged critical.
    site2 = _Site({"/console": (200, "<html><div>Werkzeug Debugger</div>"
                                      "<script>__debugger__</script></html>")})
    res2 = await dp.probe_debug_panels(site2, "https://x.test")
    assert any(f["label"] == "Werkzeug/Flask debugger" and f["severity"] == "critical"
               for f in res2)
