"""Tests for the batch prober and the SARIF/JSON findings export."""

import pytest

from moonmcp import server as srv
from moonmcp.reporting import format_sarif


@pytest.mark.asyncio
async def test_probe_batch_live_and_scope(local_server, fresh_context):
    base, port = local_server
    targets = [
        base,                       # live, in scope
        f"127.0.0.1:{port}",        # same host, in scope
        "http://evil.example.test", # out of scope → skipped
    ]
    res = await srv.probe_batch(targets=targets)
    assert res["requested"] == 3
    assert res["live"] >= 1
    assert res["skipped"] >= 1
    live = [r for r in res["results"] if r.get("status") == 200]
    assert live and any(r.get("title") == "Local" for r in live)


@pytest.mark.asyncio
async def test_probe_batch_dedupes_and_caps(fresh_context):
    res = await srv.probe_batch(targets=["", "  ", "x.example", "x.example"])
    # blank entries dropped, duplicate collapsed → 1 unique target (out of scope → skipped)
    assert res["requested"] == 1


def test_format_sarif_structure():
    findings = [
        {"target": "api.example.com", "severity": "high", "title": "IDOR on /orders",
         "type": "access-control", "detail": "user B reads user A", "evidence": "HTTP 200"},
        {"target": "https://example.com/x", "severity": "low", "title": "verbose header",
         "type": "info-leak"},
    ]
    doc = format_sarif(findings, version="1.2.3")
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "MoonMCP"
    assert run["tool"]["driver"]["version"] == "1.2.3"
    assert len(run["results"]) == 2
    r0 = run["results"][0]
    assert r0["level"] == "error"  # high → error
    assert r0["ruleId"] == "access-control"
    assert r0["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "https://api.example.com"
    assert {rule["id"] for rule in run["tool"]["driver"]["rules"]} == {"access-control", "info-leak"}


@pytest.mark.asyncio
async def test_export_findings_tool(fresh_context):
    await srv.add_finding(target="example.com", severity="critical", title="SQLi in id param",
                          detail="boolean-blind", evidence="' AND 1=1")
    sarif = await srv.export_findings(format="sarif")
    assert sarif["format"] == "sarif"
    assert sarif["sarif"]["runs"][0]["results"][0]["level"] == "error"
    js = await srv.export_findings(format="json")
    assert js["format"] == "json" and js["summary"]["total"] >= 1
    bad = await srv.export_findings(format="pdf")
    assert bad.get("error") == "invalid_input"
    await srv.clear_findings()
