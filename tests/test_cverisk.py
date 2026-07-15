"""CVE risk triage — pure scoring + parse helpers + registration."""

import pytest

from moonmcp import server as srv
from moonmcp.intel import cve as cvemod
from moonmcp.intel import cverisk


# -- compute_risk ------------------------------------------------------------
def test_kev_override_floors_at_critical():
    # A modest-CVSS bug that's actively exploited must land in the CRITICAL band.
    r = cverisk.compute_risk(cvss=4.0, epss=0.05, kev=True, poc=False)
    assert r["risk_score"] >= 76
    assert r["risk_band"] == "critical"
    assert r["kev_override"] is True


def test_actively_exploited_outranks_theoretical_critical():
    exploited = cverisk.compute_risk(cvss=5.0, epss=0.20, kev=True, poc=True)
    theoretical = cverisk.compute_risk(cvss=9.8, epss=0.01, kev=False, poc=False)
    assert exploited["risk_score"] > theoretical["risk_score"]


def test_kev_poc_boost_applied():
    with_boost = cverisk.compute_risk(cvss=6.0, epss=0.5, kev=True, poc=True)
    assert with_boost["kev_poc_boost"] is True


def test_max_signals_cap_at_100():
    r = cverisk.compute_risk(cvss=10.0, epss=1.0, kev=True, poc=True)
    assert r["risk_score"] == 100.0


def test_no_signals_is_zero_low():
    r = cverisk.compute_risk(cvss=None, epss=None, kev=False, poc=False)
    assert r["risk_score"] == 0.0
    assert r["risk_band"] == "low"


def test_bands_track_score():
    assert cverisk.compute_risk(cvss=8.0, epss=0.0, kev=False, poc=False)["risk_band"] == "low"      # 16.0
    assert cverisk.compute_risk(cvss=9.0, epss=0.3, kev=False, poc=True)["risk_band"] == "medium"    # 43.5
    # A cvss-only critical (no exploitation) is deliberately NOT critical-band.
    assert cverisk.compute_risk(cvss=10.0, epss=0.0, kev=False, poc=False)["risk_band"] == "low"     # 20.0


def test_weights_and_components_reported():
    r = cverisk.compute_risk(cvss=10.0, epss=0.5, kev=False, poc=False)
    assert r["weights"] == {"epss": 0.35, "kev": 0.30, "cvss": 0.20, "poc": 0.15}
    assert r["components"]["cvss"] == 100.0
    assert r["components"]["epss"] == 50.0


# -- parse_epss --------------------------------------------------------------
def test_parse_epss_finds_the_cve_case_insensitively():
    body = '{"data":[{"cve":"CVE-2021-44228","epss":"0.9754","percentile":"0.999"}]}'
    assert cverisk.parse_epss(body, "cve-2021-44228") == (0.9754, 0.999)


def test_parse_epss_absent_returns_none():
    assert cverisk.parse_epss('{"data":[]}', "CVE-2021-44228") == (None, None)


def test_parse_epss_bad_json_returns_none():
    assert cverisk.parse_epss("not json", "CVE-1") == (None, None)


# -- parse_kev_ids -----------------------------------------------------------
def test_parse_kev_ids_uppercases():
    ids = cverisk.parse_kev_ids('{"vulnerabilities":[{"cveID":"cve-2021-44228"},{"cveID":"CVE-2017-5638"}]}')
    assert "CVE-2021-44228" in ids
    assert "CVE-2017-5638" in ids


def test_parse_kev_ids_bad_json_is_empty():
    assert cverisk.parse_kev_ids("{{bad") == set()


# -- poc extraction from NVD reference tags ----------------------------------
def test_parse_vuln_sets_poc_from_exploit_tag():
    vuln = {"cve": {"id": "CVE-x", "references": [
        {"url": "https://a", "tags": ["Third Party Advisory"]},
        {"url": "https://b", "tags": ["Exploit", "Patch"]},
    ]}}
    assert cvemod._parse_vuln(vuln).poc is True


def test_parse_vuln_no_exploit_tag_no_poc():
    vuln = {"cve": {"id": "CVE-x", "references": [{"url": "https://a", "tags": ["Patch"]}]}}
    assert cvemod._parse_vuln(vuln).poc is False


# -- registration ------------------------------------------------------------
@pytest.mark.asyncio
async def test_cve_triage_folded_into_cve_lookup(fresh_context):
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "cve_lookup" in tools
    assert "cve_triage" not in tools     # triage folded into cve_lookup(triage=True)
    # the registered cve_lookup tool now accepts the triage flag
    tool = next(t for t in srv.mcp._tool_manager.list_tools() if t.name == "cve_lookup")
    assert "triage" in tool.parameters.get("properties", {})
