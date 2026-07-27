"""CVE lookup via the NVD (National Vulnerability Database) REST API 2.0.

Two entry points:
* :func:`lookup_cve`  — fetch a single CVE by ID.
* :func:`search_cves` — keyword search (e.g. a product + version) returning the
  most relevant recent CVEs.

An optional ``NVD_API_KEY`` raises the rate limit but is never required.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from urllib.parse import quote

from ..net.http import HttpClient

_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@dataclass
class CveRecord:
    id: str
    published: str | None = None
    last_modified: str | None = None
    description: str = ""
    cvss_score: float | None = None
    cvss_severity: str | None = None
    cvss_vector: str | None = None
    cwe: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


@dataclass
class CveSearchResult:
    query: str
    total: int = 0
    results: list[CveRecord] = field(default_factory=list)
    error: str | None = None


def _headers(api_key: str | None) -> dict[str, str]:
    return {"apiKey": api_key} if api_key else {}


def _best_cvss(metrics: dict) -> tuple[float | None, str | None, str | None]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            data = entries[0].get("cvssData", {})
            score = data.get("baseScore")
            severity = data.get("baseSeverity") or entries[0].get("baseSeverity")
            vector = data.get("vectorString")
            return score, severity, vector
    return None, None, None


def _parse_vuln(vuln: dict) -> CveRecord:
    cve = vuln.get("cve", vuln)
    descriptions = cve.get("descriptions", [])
    desc = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
    score, severity, vector = _best_cvss(cve.get("metrics", {}))
    cwes: list[str] = []
    for weakness in cve.get("weaknesses", []):
        for d in weakness.get("description", []):
            val = d.get("value")
            if val and val.startswith("CWE-") and val not in cwes:
                cwes.append(val)
    refs = [r.get("url") for r in cve.get("references", []) if r.get("url")][:15]
    return CveRecord(
        id=cve.get("id", "?"),
        published=cve.get("published"),
        last_modified=cve.get("lastModified"),
        description=desc,
        cvss_score=score,
        cvss_severity=severity,
        cvss_vector=vector,
        cwe=cwes,
        references=refs,
    )


async def lookup_cve(client: HttpClient, cve_id: str, api_key: str | None = None) -> CveRecord | None:
    cve_id = cve_id.strip().upper()
    url = f"{_BASE}?cveId={quote(cve_id)}"
    r = await client.fetch(url, headers=_headers(api_key), timeout=25.0, follow_redirects=True)
    if r.error or r.status != 200:
        return None
    try:
        data = json.loads(r.text())
    except json.JSONDecodeError:
        return None
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return None
    return _parse_vuln(vulns[0])


async def search_cves(
    client: HttpClient,
    keyword: str,
    *,
    limit: int = 15,
    api_key: str | None = None,
) -> CveSearchResult:
    url = f"{_BASE}?keywordSearch={quote(keyword)}&resultsPerPage={min(max(1, limit), 50)}"
    r = await client.fetch(url, headers=_headers(api_key), timeout=25.0, follow_redirects=True)
    out = CveSearchResult(query=keyword)
    if r.error or r.status != 200:
        out.error = r.error or f"HTTP {r.status}"
        return out
    try:
        data = json.loads(r.text())
    except json.JSONDecodeError:
        out.error = "unparseable response"
        return out
    out.total = data.get("totalResults", 0)
    records = [_parse_vuln(v) for v in data.get("vulnerabilities", [])]
    # Surface the most severe first.
    records.sort(key=lambda c: (c.cvss_score or 0.0), reverse=True)
    out.results = records[:limit]
    return out
