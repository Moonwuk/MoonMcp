"""Behaviour profiler — error-disclosure must be baseline-subtracted (no ambient FP)."""

import pytest

from moonmcp.web import behavior as mm


class _R:
    def __init__(self, status, body="", headers=None):
        self.status = status
        self.body = body.encode() if isinstance(body, str) else body
        self.error = None
        self.elapsed_ms = 1.0
        self._h = {k.lower(): v for k, v in (headers or {}).items()}

    def header(self, name):
        return self._h.get(name.lower())

    def text(self, limit=None):
        return self.body.decode("utf-8", "replace")


class _Client:
    def __init__(self, fn):
        self._fn = fn

    async def fetch(self, url, *, method="GET", headers=None, **kw):
        return self._fn(url, method, headers or {})


_FUZZ = ("%c0%ae", "moonmcp", "'\"><", "><")


@pytest.mark.asyncio
async def test_error_disclosure_ignores_ambient_page_tokens():
    # A docs/tutorial site whose NORMAL page mentions error-ish tokens must NOT read as
    # leaking a stack trace — the tokens are present on the baseline, not introduced.
    docs = ("<html>Django guide: django.contrib.auth. A Warning: line — see the stack "
            "trace section on line 5. Undefined index is a PHP notice.</html>")

    def fn(url, method, headers):
        return _R(200, docs)   # every path (baseline, 404 probe, fuzz) → the same docs page

    prof = await mm.profile_behavior(_Client(fn), "https://docs.test/")
    assert prof.error_disclosure == []
    assert "error/stack-trace signatures leaked in responses" not in prof.notes


@pytest.mark.asyncio
async def test_error_disclosure_flags_a_real_introduced_trace():
    # Baseline is clean; only the fuzz input triggers a genuine traceback → flagged.
    def fn(url, method, headers):
        if "x-does-not-exist" in url:
            return _R(404, "<html>not found</html>" + "x" * 300)
        if any(m in url for m in _FUZZ):
            return _R(500, "Traceback (most recent call last):\n  File \"app.py\", line 10\nNameError")
        return _R(200, "<html>welcome — nothing to see</html>")

    prof = await mm.profile_behavior(_Client(fn), "https://app.test/")
    assert "Traceback (most recent call last)" in prof.error_disclosure
    assert "error/stack-trace signatures leaked in responses" in prof.notes
