"""CVE lookup via the NVD (National Vulnerability Database) REST API 2.0.

Two entry points:
* :func:`lookup_cve`  — fetch a single CVE by ID.
* :func:`search_cves` — keyword search (e.g. a product + version) returning the
  most relevant recent CVEs.

An optional ``NVD_API_KEY`` raises the rate limit but is never required.
"""

from __future__ import annotations

import asyncio
import json
import math
import time
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from urllib.parse import quote

from ..net.http import HttpClient, HttpResult

_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_ATTEMPTS = 4
_MAX_RETRY_DELAY = 30.0


def _retry_delay(response: HttpResult, attempt: int) -> float:
    """Respect bounded Retry-After values; malformed hints use backoff."""
    delay = min(2.0 ** attempt, _MAX_RETRY_DELAY)
    raw = response.header("Retry-After")
    if raw:
        try:
            seconds = float(raw)
        except ValueError:
            try:
                when = parsedate_to_datetime(raw)
                if when.tzinfo is None:
                    return delay
                seconds = when.timestamp() - time.time()
            except (ValueError, TypeError, OverflowError):
                return delay
        if math.isfinite(seconds) and seconds >= 0:
            delay = min(seconds, _MAX_RETRY_DELAY)
    return delay


async def _fetch_nvd(client: HttpClient, url: str, api_key: str | None) -> HttpResult:
    """Retry only transient HTTP failures; every actual attempt stays metered."""
    for attempt in range(_ATTEMPTS):
        try:
            response = await client.fetch(url, headers=_headers(api_key), timeout=25.0,
                                          follow_redirects=True, suppress_auth=True)
        except OSError:
            if attempt == _ATTEMPTS - 1:
                raise
            await asyncio.sleep(min(2.0 ** attempt, _MAX_RETRY_DELAY))
            continue
        if (response.blocked_reason or response.redirect_blocked
                or response.status not in {429, 500, 502, 503, 504}
                or attempt == _ATTEMPTS - 1):
            return response
        await asyncio.sleep(_retry_delay(response, attempt))
    raise AssertionError("unreachable NVD retry state")  # pragma: no cover


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

    try:
        r = await _fetch_nvd(client, url, api_key)
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

    except Exception:
        # Preserve the historical optional-record API. None alone still cannot
        # distinguish absence from provider failure; callers must not interpret
        # it as proof that a product has no vulnerabilities.
        return None


async def search_cves(
    client: HttpClient,
    keyword: str,
    *,
    limit: int = 15,
    api_key: str | None = None,
) -> CveSearchResult:
    url = f"{_BASE}?keywordSearch={quote(keyword)}&resultsPerPage={min(max(1, limit), 50)}"
    r = await _fetch_nvd(client, url, api_key)
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
