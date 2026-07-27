"""Query API over the WAF reference knowledge base.

Three kinds of entry — ``how-it-works`` (rule engines & models), ``fingerprint``
(identify the vendor from response headers/cookies/blocking pages) and
``bypass-technique`` (conceptual, defensive: understanding evasion to detect &
defend).  :func:`identify` scans a raw HTTP response (headers + body) against the
fingerprint indicators to name the WAF in front of a target.  Complements the
active ``waf_detect`` / ``waf_efficacy`` tools.  Data lives in
:mod:`moonmcp.knowledge.waf_kb_data`.
"""

from __future__ import annotations

import re
from functools import lru_cache

from .waf_kb_data import WAF_ENTRIES

_STOP = {"header", "headers", "cookie", "cookies", "body", "page", "block", "blocked",
         "response", "status", "server", "the", "and", "with", "http", "error", "waf"}


def list_entries(category: str | None = None) -> list[dict]:
    items = WAF_ENTRIES
    if category:
        c = category.strip().lower()
        items = [w for w in WAF_ENTRIES if str(w.get("category", "")).lower() == c]
    return [{"id": w["id"], "name": w["name"], "category": w.get("category"),
             "summary": w.get("summary", "")} for w in items]


def get_entry(entry_id: str) -> dict | None:
    eid = entry_id.strip().lower()
    for w in WAF_ENTRIES:
        if w["id"] == eid or eid == w.get("name", "").lower():
            return w
    return None


def search(query: str) -> list[dict]:
    q = query.strip().lower()
    out = []
    for w in WAF_ENTRIES:
        hay = " ".join([w["id"], w["name"], w.get("summary", ""), w.get("detail", ""),
                        w.get("category", ""), " ".join(w.get("applies_to", []))]).lower()
        if not q or q in hay:
            out.append({"id": w["id"], "name": w["name"], "category": w.get("category"),
                        "summary": w.get("summary", "")})
    return out


def fingerprints() -> list[dict]:
    return [w for w in WAF_ENTRIES if w.get("category") == "fingerprint"]


def bypasses() -> list[dict]:
    return [w for w in WAF_ENTRIES if w.get("category") == "bypass-technique"]


def _distinctive_tokens(text: str) -> list[str]:
    toks = re.split(r"[^A-Za-z0-9_-]+", text)
    out = []
    for t in toks:
        tl = t.lower()
        if len(t) < 4 or tl in _STOP:
            continue
        # distinctive: has a digit/hyphen/underscore or is a longer vendor-ish token
        if any(c.isdigit() or c in "-_" for c in t) or len(t) >= 6:
            out.append(t)
    return out


@lru_cache(maxsize=1)
def _fingerprint_patterns() -> list[tuple[str, str, re.Pattern]]:
    """(waf_id, waf_name, compiled_regex) from each fingerprint's indicator tokens."""

    pats: list[tuple[str, str, re.Pattern]] = []
    for w in fingerprints():
        toks = set(_distinctive_tokens(w.get("indicator", "")))
        # also key off the vendor name's distinctive words
        toks |= {t for t in _distinctive_tokens(w.get("name", ""))}
        for tok in toks:
            try:
                pats.append((w["id"], w["name"], re.compile(re.escape(tok), re.IGNORECASE)))
            except re.error:
                continue
    return pats


def identify(text: str) -> list[dict]:
    """Scan a raw HTTP response (headers + body) for WAF fingerprint indicators."""

    if not text:
        return []
    hits: dict[str, dict] = {}
    for wid, name, pat in _fingerprint_patterns():
        m = pat.search(text)
        if not m:
            continue
        entry = hits.setdefault(wid, {"waf": wid, "name": name, "matched": []})
        if m.group(0) not in entry["matched"]:
            entry["matched"].append(m.group(0))
    return sorted(hits.values(), key=lambda e: -len(e["matched"]))


def stats() -> dict:
    by_cat: dict[str, int] = {}
    for w in WAF_ENTRIES:
        by_cat[w.get("category", "other")] = by_cat.get(w.get("category", "other"), 0) + 1
    return {"entries": len(WAF_ENTRIES), "by_category": by_cat,
            "fingerprint_signatures": len(_fingerprint_patterns())}
