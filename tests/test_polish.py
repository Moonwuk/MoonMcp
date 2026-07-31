"""Small hardening polish: port_scan honours the concurrency knob; Obsidian
frontmatter escapes embedded quotes."""

import pytest

from moonmcp import server as srv
from moonmcp.obsidian import frontmatter


@pytest.mark.asyncio
async def test_port_scan_respects_max_concurrency(fresh_context, monkeypatch):
    # The bug: the server passed concurrency = max_concurrency * 10, silently blowing
    # past the operator's MOONMCP_MAX_CONCURRENCY cap. It must pass the cap itself.
    captured = {}

    async def fake_scan(host, ports, **kw):
        captured["concurrency"] = kw.get("concurrency")
        from moonmcp.net.ports import ScanResult
        return ScanResult(host=host)

    from moonmcp.net import ports as portsmod
    monkeypatch.setattr(portsmod, "scan_ports", fake_scan)
    fresh_context.scope.add("scanme.example")
    await srv.port_scan(target="scanme.example", ports="80,443")
    assert captured["concurrency"] == fresh_context.settings.max_concurrency
    assert captured["concurrency"] <= 200


def test_obsidian_frontmatter_escapes_embedded_quote():
    # A value carrying a double-quote (and a colon) must stay inside ONE quoted
    # scalar — it must not break out and inject a stray `evil:` frontmatter key.
    out = frontmatter({"asset": 'host-a" evil: true'})
    assert r'\"' in out                       # the quote is escaped
    # the whole value is one quoted line; no unescaped `evil: true` key leaked out
    body_lines = [ln for ln in out.splitlines() if ln.startswith("asset:")]
    assert len(body_lines) == 1
    assert body_lines[0] == r'asset: "host-a\" evil: true"'


def test_obsidian_frontmatter_plain_values_unquoted():
    out = frontmatter({"severity": "high", "id": "F-1"})
    assert "severity: high" in out
    assert "id: F-1" in out
