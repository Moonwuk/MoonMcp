"""CVE risk triage — turn a raw NVD record into a prioritised, exploit-aware score.

`cve_lookup` gives CVSS, which measures *theoretical* severity. Real triage needs
*exploitation likelihood*: is it being exploited in the wild (CISA KEV), how likely
is it to be (EPSS), and does a public PoC exist? This module enriches a CVE with
those signals and folds them into one composite score, mirroring the weighting the
security-MCP ecosystem has converged on:

    risk = 0.35·EPSS + 0.30·KEV + 0.20·CVSS + 0.15·PoC     (each component 0-100)

with two adjustments: a **KEV hard-override** (anything on CISA's Known Exploited
Vulnerabilities list is clamped to the CRITICAL band, ≥76, because it is *actively*
exploited regardless of its CVSS), and a **KEV+PoC boost** (×1.15, capped at 100)
since a proven, catalogued exploit is the highest-urgency combination.

All enrichment is passive third-party data (NVD, FIRST.org EPSS, CISA KEV) — no
packets to any target. The scoring itself is a pure function, so it's fully
testable offline.
"""

from __future__ import annotations

import json

from ..net.http import HttpClient

EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# The CISA KEV catalogue is ~1MB and updates ~daily; fetch it once per process.
_KEV_CACHE: set[str] | None = None


def compute_risk(*, cvss: float | None, epss: float | None,
                 kev: bool, poc: bool) -> dict:
    """Fold the four signals into a 0-100 composite risk score (pure).

    ``cvss`` is the 0-10 base score, ``epss`` the 0-1 exploitation probability,
    ``kev`` whether it's on CISA's Known-Exploited list, ``poc`` whether a public
    exploit is known. Missing ``cvss``/``epss`` count as 0 for their component."""

    cvss_c = (cvss or 0.0) * 10.0          # 0-10  -> 0-100
    epss_c = (epss or 0.0) * 100.0         # 0-1   -> 0-100 (probability)
    kev_c = 100.0 if kev else 0.0
    poc_c = 100.0 if poc else 0.0

    score = 0.35 * epss_c + 0.30 * kev_c + 0.20 * cvss_c + 0.15 * poc_c
    if kev and poc:
        score = min(100.0, score * 1.15)   # proven, catalogued exploit — highest urgency
    if kev:
        score = max(score, 76.0)           # actively exploited — floor at CRITICAL
    score = round(score, 1)

    band = ("critical" if score >= 76 else
            "high" if score >= 50 else
            "medium" if score >= 25 else
            "low")
    return {
        "risk_score": score,
        "risk_band": band,
        "components": {
            "epss": round(epss_c, 1), "kev": kev_c, "cvss": round(cvss_c, 1), "poc": poc_c,
        },
        "weights": {"epss": 0.35, "kev": 0.30, "cvss": 0.20, "poc": 0.15},
        "kev_override": kev,
        "kev_poc_boost": kev and poc,
    }


def parse_epss(body: str, cve_id: str) -> tuple[float | None, float | None]:
    """Extract ``(epss, percentile)`` for *cve_id* from a FIRST.org EPSS response
    (pure). Returns ``(None, None)`` when the CVE isn't scored."""

    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return None, None
    for row in data.get("data", []):
        if str(row.get("cve", "")).upper() == cve_id.upper():
            try:
                epss = float(row["epss"]) if row.get("epss") is not None else None
            except (ValueError, TypeError):
                epss = None
            try:
                pct = float(row["percentile"]) if row.get("percentile") is not None else None
            except (ValueError, TypeError):
                pct = None
            return epss, pct
    return None, None


def parse_kev_ids(body: str) -> set[str]:
    """Extract the set of KEV CVE IDs from the CISA catalogue JSON (pure)."""

    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return set()
    return {str(v.get("cveID", "")).upper()
            for v in data.get("vulnerabilities", []) if v.get("cveID")}


async def fetch_epss(client: HttpClient, cve_id: str) -> tuple[float | None, float | None]:
    """EPSS score + percentile for one CVE (best-effort; ``(None, None)`` on error)."""

    from urllib.parse import quote
    r = await client.fetch(f"{EPSS_URL}?cve={quote(cve_id.upper())}",
                           timeout=20.0, follow_redirects=True)
    if r.error or r.status != 200:
        return None, None
    return parse_epss(r.text(), cve_id)


async def fetch_kev_ids(client: HttpClient, *, force: bool = False) -> set[str]:
    """The CISA KEV CVE-ID set, cached for the process lifetime.

    Returns an empty set on fetch failure (so a KEV outage degrades to
    "not-listed" rather than crashing the triage)."""

    global _KEV_CACHE
    if _KEV_CACHE is not None and not force:
        return _KEV_CACHE
    r = await client.fetch(KEV_URL, timeout=30.0, follow_redirects=True)
    if r.error or r.status != 200:
        return set()
    ids = parse_kev_ids(r.text())
    if ids:
        _KEV_CACHE = ids
    return ids


async def triage(client: HttpClient, cve_id: str, *, api_key: str | None = None) -> dict:
    """Enrich one CVE with EPSS/KEV/PoC and score it (network; best-effort).

    Returns a dict with the base NVD facts, the three enrichment signals, and the
    composite risk. Any enrichment that can't be fetched degrades gracefully and
    is flagged in ``sources``."""

    from . import cve as cvemod

    cve_id = cve_id.strip().upper()
    record = await cvemod.lookup_cve(client, cve_id, api_key=api_key)
    if record is None:
        return {"error": "not_found", "detail": f"No NVD record for {cve_id}", "cve_id": cve_id}

    epss, percentile = await fetch_epss(client, cve_id)
    kev_ids = await fetch_kev_ids(client)
    kev = cve_id in kev_ids
    poc = record.poc

    risk = compute_risk(cvss=record.cvss_score, epss=epss, kev=kev, poc=poc)
    return {
        "cve_id": cve_id,
        "description": record.description,
        "cvss_score": record.cvss_score,
        "cvss_severity": record.cvss_severity,
        "epss": epss,
        "epss_percentile": percentile,
        "kev": kev,
        "poc": poc,
        "cwe": record.cwe,
        "references": record.references,
        **risk,
        "sources": {
            "nvd": True,
            "epss": epss is not None,
            "kev": bool(kev_ids),  # False = the KEV feed itself couldn't be read
        },
    }
