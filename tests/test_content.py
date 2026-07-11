"""content_discovery soft-404 auto-calibration."""

import pytest

from moonmcp.recon import content as cd

_INDEX = "<html>welcome to our single-page app</html>" * 20  # stable catch-all body


class _R:
    def __init__(self, status, body=b""):
        self.status = status
        self.body = body.encode() if isinstance(body, str) else body

    def header(self, name, default=None):
        return default


class _SpaApp:
    """Catch-all: every unknown path returns the same 200 index; /admin and /login differ."""

    async def fetch(self, url, **kwargs):
        if url.endswith("/admin"):
            return _R(200, "ADMIN CONTROL PANEL " * 40)   # distinct, much longer
        if url.endswith("/login"):
            return _R(401, "unauthorized")                # hard signal
        return _R(200, _INDEX)                            # soft-404 catch-all


class _NormalApp:
    """Real 404s: /admin exists, everything else is a hard 404."""

    async def fetch(self, url, **kwargs):
        return _R(200, "panel") if url.endswith("/admin") else _R(404, "not found")


class _JitterApp:
    """Every request (incl. the two calibration controls) returns a different-length 200,
    so the two controls diverge and calibration declines."""

    def __init__(self):
        self._n = 0

    async def fetch(self, url, **kwargs):
        self._n += 1
        return _R(200, "x" * (200 + self._n * 500))   # each call differs by 500 bytes


@pytest.mark.asyncio
async def test_soft404_suppresses_catchall_keeps_real_hits():
    res = await cd.probe_paths(_SpaApp(), "x.test", wordlist=["admin", "login", "nothing", "ghost"])
    assert res.calibrated is True and res.baseline_status == 200
    paths = {h.path for h in res.hits}
    assert "admin" in paths and "login" in paths      # distinct size / hard status survive
    assert "nothing" not in paths and "ghost" not in paths  # catch-all echoes suppressed
    assert res.suppressed >= 2


@pytest.mark.asyncio
async def test_hard_404_app_reports_real_hit_and_suppresses_nothing():
    res = await cd.probe_paths(_NormalApp(), "x.test", wordlist=["admin", "missing"])
    assert res.calibrated is True and res.baseline_status == 404
    assert {h.path for h in res.hits} == {"admin"} and res.suppressed == 0


@pytest.mark.asyncio
async def test_jittery_app_declines_calibration():
    # the two random controls diverge → no reliable baseline → nothing suppressed
    res = await cd.probe_paths(_JitterApp(), "x.test", wordlist=["admin", "login"])
    assert res.calibrated is False and res.suppressed == 0
    assert len(res.hits) == 2                          # falls back to old behaviour
