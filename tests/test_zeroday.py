"""intel/zeroday.py — version math, root-cause mapping, variant search, and the
NVD-backed orchestrators (network mocked). This module shipped at 0% coverage."""

import pytest

from moonmcp.intel import cve as cvemod
from moonmcp.intel import zeroday as zd


# -- version parsing --------------------------------------------------------
def test_parse_version_strips_trailing_zeros_and_handles_junk():
    assert zd._parse_version("1.2.3") == (1, 2, 3)
    assert zd._parse_version("1.2.0") == (1, 2)        # trailing zero stripped
    assert zd._parse_version("1.0.0") == (1,)
    assert zd._parse_version("v2.29.2") == (2, 29, 2)  # regex finds the digits
    assert zd._parse_version("1.2.3.4") == (1, 2, 3, 4)
    assert zd._parse_version("not-a-version") == (0,)


def test_version_in_range():
    assert zd._version_in_range("32.0.5", "32.0.0", "32.0.9") == "vulnerable"
    assert zd._version_in_range("32.0.9", "32.0.0", "32.0.9") == "patched"    # >= fix
    assert zd._version_in_range("31.9.9", "32.0.0", "32.0.9") == "unknown"    # before range
    assert zd._version_in_range("5.0", "", "6.0") == "vulnerable"             # open lower bound
    assert zd._version_in_range("7.0", "", "6.0") == "patched"


# -- description extraction -------------------------------------------------
def test_extract_version_range_patterns():
    assert zd._extract_version_range("from versions 32.0.0 to before 32.0.9") == ("32.0.0", "32.0.9")
    assert zd._extract_version_range("affected in versions 1.0 to before 1.5") == ("1.0", "1.5")
    assert zd._extract_version_range("prior to 4.5.1") == ("", "4.5.1")
    assert zd._extract_version_range("this is fixed before 2.0") == ("", "2.0")
    assert zd._extract_version_range("from version 1.2 onwards") == ("1.2", "")
    assert zd._extract_version_range("no versions mentioned") == ("", "")


def test_extract_fix_version_patterns():
    assert zd._extract_fix_version("Users should upgrade to 1.2.3") == "1.2.3"
    assert zd._extract_fix_version("This was fixed in 4.5.6") == "4.5.6"
    assert zd._extract_fix_version("patched in version 2.0.0") == "2.0.0"
    assert zd._extract_fix_version("no fix info here") == ""


# -- root cause + reference classification ----------------------------------
def test_identify_root_cause_by_cwe_then_keyword():
    assert zd._identify_root_cause("", ["CWE-918"])[0] == "confused-deputy"
    assert zd._identify_root_cause("", ["CWE-502"])[0] == "insecure-deserialization"
    # no CWE → keyword fallback in the description
    assert zd._identify_root_cause("A reflected xss flaw", [])[0] == "code-data-confusion"
    assert zd._identify_root_cause("nothing recognisable", []) == ("unknown", "Unknown")


def test_classify_references_splits_pr_and_h1():
    refs = ["https://github.com/org/repo/pull/42",
            "https://github.com/org/repo/issues/9",   # not a PR
            "https://hackerone.com/reports/123",
            "https://example.com/blog"]
    prs, h1 = zd._classify_references(refs)
    assert prs == ["https://github.com/org/repo/pull/42"]
    assert h1 == ["https://hackerone.com/reports/123"]


def test_get_probes_for_cwes_dedupes_and_skips_unknown():
    probes = zd._get_probes_for_cwes(["CWE-918", "CWE-918", "CWE-99999"])
    assert len(probes) == 1                     # dedup + unknown CWE skipped
    assert probes[0]["cwe"] == "CWE-918"
    assert probes[0]["moonmcp_tool"] == "ssrf_probe"


# -- variant_search (pure) --------------------------------------------------
def test_variant_search_by_root_cause_id():
    res = zd.variant_search("broken-authorization")
    assert res.root_cause and res.cwes
    assert any(p["moonmcp_tool"] for p in res.moonmcp_probes)
    assert res.triage_memory          # broken-auth has FP-trap memory
    assert res.poc_pipeline           # discover→verify→reproduce chained
    assert len(res.questions_to_ask) == 5


def test_variant_search_by_cwe_and_keyword():
    assert zd.variant_search("CWE-918").root_cause == "Confused Deputy"
    assert zd.variant_search("CWE-918").cwes == ["CWE-918"]
    assert zd.variant_search("ssrf via url param").root_cause == "Confused Deputy"


def test_variant_search_unknown_pattern_still_returns_questions():
    res = zd.variant_search("some novel undocumented thing")
    assert res.root_cause == ""       # nothing matched
    assert len(res.questions_to_ask) == 5
    assert res.payload_sources        # falls back to the generic sources


# -- cve_patch_diff (NVD mocked, no PR fetch) --------------------------------
@pytest.mark.asyncio
async def test_cve_patch_diff_classifies(monkeypatch):
    rec = cvemod.CveRecord(
        id="CVE-2024-0001",
        description="An SSRF in the fetch handler. Fixed in 2.3.4.",
        cvss_score=8.6, cvss_severity="HIGH", cwe=["CWE-918"],
        references=["https://github.com/org/repo/pull/9", "https://hackerone.com/reports/1"])

    async def fake_lookup(client, cve_id, api_key=None):
        return rec

    monkeypatch.setattr(zd.cvemod, "lookup_cve", fake_lookup)
    res = await zd.cve_patch_diff(None, "cve-2024-0001", fetch_pr=False)
    assert res.root_cause_id == "confused-deputy"
    assert any(p["cwe"] == "CWE-918" for p in res.moonmcp_probes)
    assert res.github_prs == ["https://github.com/org/repo/pull/9"]
    assert res.hackerone_reports == ["https://hackerone.com/reports/1"]
    assert res.gap_analysis                       # incomplete-fix indicators populated
    assert "2.3.4" in res.what_patch_fixes


@pytest.mark.asyncio
async def test_cve_patch_diff_not_found(monkeypatch):
    async def fake_lookup(client, cve_id, api_key=None):
        return None

    monkeypatch.setattr(zd.cvemod, "lookup_cve", fake_lookup)
    res = await zd.cve_patch_diff(None, "CVE-0000-0000", fetch_pr=False)
    assert "not found" in res.description.lower()
    assert res.moonmcp_probes == []


# -- version_vuln_check (NVD mocked) ----------------------------------------
def _search_result(records, error=None):
    return cvemod.CveSearchResult(query="x", total=len(records), results=records, error=error)


@pytest.mark.asyncio
async def test_version_vuln_check_classifies_patched_vs_unpatched(monkeypatch):
    recs = [
        cvemod.CveRecord(id="CVE-A", description="Affects from versions 1.0.0 to before "
                         "1.5.0. Fixed in 1.5.0.", cvss_score=9.1, cvss_severity="CRITICAL"),
        cvemod.CveRecord(id="CVE-B", description="from versions 1.0.0 to before 1.1.0. "
                         "Fixed in 1.1.0.", cvss_score=5.0, cvss_severity="MEDIUM"),
    ]

    async def fake_search(client, term, limit=30, api_key=None):
        return _search_result(recs)

    monkeypatch.setattr(zd.cvemod, "search_cves", fake_search)
    res = await zd.version_vuln_check(None, "acme", version="1.2.0")
    unpatched = {e["cve_id"] for e in res.unpatched}
    patched = {e["cve_id"] for e in res.patched}
    assert "CVE-A" in unpatched     # 1.2.0 is within 1.0.0..<1.5.0
    assert "CVE-B" in patched       # 1.2.0 is at/beyond the 1.1.0 fix
    assert "Unpatched: 1" in res.summary


@pytest.mark.asyncio
async def test_version_vuln_check_no_target_version_is_all_unknown(monkeypatch):
    recs = [cvemod.CveRecord(id="CVE-C", description="prior to 3.0.0. Fixed in 3.0.0.")]

    async def fake_search(client, term, limit=30, api_key=None):
        return _search_result(recs)

    monkeypatch.setattr(zd.cvemod, "search_cves", fake_search)
    res = await zd.version_vuln_check(None, "acme", version="")
    assert len(res.unknown) == 1 and not res.unpatched and not res.patched


@pytest.mark.asyncio
async def test_version_vuln_check_surfaces_search_error(monkeypatch):
    async def fake_search(client, term, limit=30, api_key=None):
        return _search_result([], error="rate limited")

    monkeypatch.setattr(zd.cvemod, "search_cves", fake_search)
    res = await zd.version_vuln_check(None, "acme", version="1.0.0")
    assert "rate limited" in res.summary
