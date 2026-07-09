"""Finding deduplication & triage."""

import pytest

from moonmcp import server as srv
from moonmcp.findings import FindingsStore


def _store():
    s = FindingsStore()
    # Two exact dupes (same type+target+title, different evidence) + one unique.
    s.add(target="a.example.com", severity="high", title="Reflected XSS",
          type="xss", evidence="e1", source="crawl")
    s.add(target="a.example.com", severity="high", title="reflected xss  ",
          type="XSS", evidence="e2", source="params")
    s.add(target="a.example.com", severity="low", title="Missing HSTS", type="headers")
    # Same finding on a second host → systemic.
    s.add(target="b.example.com", severity="low", title="Missing HSTS", type="headers")
    return s


def test_dedupe_collapses_exact_duplicates():
    s = _store()
    res = s.dedupe()
    assert res["removed"] == 1
    assert res["remaining"] == 3
    xss = [f for f in s.list() if f.type == "xss"]
    assert len(xss) == 1
    # Evidence + source from the duplicate are merged into the survivor.
    assert "e1" in xss[0].evidence and "e2" in xss[0].evidence
    assert "params" in xss[0].source


def test_unique_is_non_mutating_and_deduped():
    s = _store()
    u = s.unique()
    assert len(s.list()) == 4  # not mutated
    # 3 unique signatures: xss@a, hsts@a, hsts@b.
    assert len(u) == 3
    assert u[0].severity == "high"  # severity-ranked


def test_triage_is_non_mutating_and_ranks():
    s = _store()
    before = len(s.list())
    t = s.triage()
    assert len(s.list()) == before  # triage does not mutate
    assert t["total"] == 4
    assert t["unique"] == 3
    assert t["duplicates"] == 1
    # Highest severity first.
    assert t["prioritized"][0]["finding"]["severity"] == "high"


def test_triage_detects_systemic_cross_target():
    s = _store()
    t = s.triage()
    systemic = t["systemic"]
    assert any(
        u["finding"]["title"].lower().startswith("missing hsts")
        and set(u["affected_targets"]) == {"a.example.com", "b.example.com"}
        for u in systemic
    )


@pytest.mark.asyncio
async def test_triage_findings_tool(fresh_context):
    ctx = fresh_context
    ctx.findings.add(target="x.example", severity="medium", title="Open redirect", type="redirect")
    ctx.findings.add(target="x.example", severity="medium", title="open redirect", type="redirect")
    dry = await srv.triage_findings()
    assert dry["triage"]["duplicates"] == 1
    assert len(ctx.findings.list()) == 2  # dry-run did not mutate

    applied = await srv.triage_findings(apply=True)
    assert applied["deduped"]["removed"] == 1
    assert len(ctx.findings.list()) == 1
    assert applied["triage"]["duplicates"] == 0
