"""The nuclei bridge: coverage map, intent→tags, arg build, finding normalisation."""

import pytest

from moonmcp import server as srv
from moonmcp.external import nuclei as n


# -- coverage map -----------------------------------------------------------
def test_coverage_report_splits_delegate_vs_edge():
    rep = n.coverage_report()
    delegate = {d["tool"] for d in rep["delegate_to_nuclei"]}
    edge = {e["tool"] for e in rep["native_edge"]}
    # commodity detection is delegated to nuclei
    assert {"cve_lookup", "vcs_exposure", "takeover_check"} <= delegate
    # stateful / differential / timing / logic probes are the native edge
    assert {"access_control_check", "logic_probe", "race_probe",
            "desync_modern_probe", "path_bypass_probe"} <= edge
    # a capability is never on both sides of the split
    assert delegate.isdisjoint(edge)
    assert rep["architecture_edge"] and rep["recommendation"]


def test_also_run_native_matches_edge_keys():
    assert set(n.also_run_native()) == set(n.NATIVE_EDGE)


# -- intent → tags ----------------------------------------------------------
def test_intent_to_tags_maps_and_dedupes():
    assert n.intent_to_tags("cve, exposures") == ["cve", "exposure"]
    assert n.intent_to_tags("takeover takeovers") == ["takeover"]   # deduped
    assert n.intent_to_tags("bogus-nonsense") == []


def test_build_args_shape():
    args = n.build_args("https://x.test", tags="cve,exposures", severity="critical,high", dast=True)
    assert args[:2] == ["-u", "https://x.test"]
    assert "-jsonl" in args and "-silent" in args
    joined = " ".join(args)
    assert "-tags cve,exposure" in joined and "-severity critical,high" in joined and "-dast" in args
    # no tags/dast when not requested
    plain = n.build_args("https://x.test")
    assert "-tags" not in plain and "-dast" not in plain


# -- finding normalisation --------------------------------------------------
def test_normalize_finding_flattens_nuclei_row():
    row = {
        "template-id": "CVE-2021-1234",
        "info": {"name": "Some CVE", "severity": "High", "tags": ["cve"], "description": "x" * 500},
        "matched-at": "https://x.test/path", "type": "http",
    }
    f = n.normalize_finding(row)
    assert f["template_id"] == "CVE-2021-1234" and f["name"] == "Some CVE"
    assert f["severity"] == "high"                    # lowercased
    assert f["matched_at"] == "https://x.test/path"
    assert len(f["description"]) <= 400               # capped


def test_normalize_finding_tolerates_sparse_row():
    f = n.normalize_finding({})
    assert f["severity"] == "info" and f["name"]


# -- registration -----------------------------------------------------------
@pytest.mark.asyncio
async def test_scan_coverage_tool_runs_offline():
    res = await srv.scan_coverage()
    assert "delegate_to_nuclei" in res and "native_edge" in res
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "scan_coverage" in tools
