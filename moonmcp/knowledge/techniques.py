"""Query API over the techniques & notable-PoC catalog.

A *referenced* catalog (like HackTricks / ExploitDB metadata): each entry
describes a technique or notable public vulnerability conceptually and links to
the authoritative public PoC / research — it does **not** ship weaponized
exploit code.  Data lives in :mod:`moonmcp.knowledge.techniques_data`.
"""

from __future__ import annotations

from .techniques_data import TECHNIQUES

_SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _index_entry(t: dict) -> dict:
    return {
        "id": t["id"],
        "name": t["name"],
        "category": t.get("category"),
        "severity": t.get("severity"),
        "languages": t.get("languages", []),
        "cve": t.get("cve", []),
        "summary": t.get("summary", ""),
    }


def list_techniques() -> list[dict]:
    return [_index_entry(t) for t in TECHNIQUES]


def categories() -> list[str]:
    return sorted({t.get("category", "other") for t in TECHNIQUES})


def get_technique(technique_id: str) -> dict | None:
    tid = technique_id.strip().lower()
    for t in TECHNIQUES:
        if t["id"] == tid:
            return t
    # also allow matching by CVE id
    up = technique_id.strip().upper()
    for t in TECHNIQUES:
        if up in [c.upper() for c in t.get("cve", [])]:
            return t
    return None


def search(query: str) -> list[dict]:
    q = query.strip().lower()
    if not q:
        return list_techniques()
    hits = []
    for t in TECHNIQUES:
        hay = " ".join([
            t["id"], t["name"], t.get("summary", ""), t.get("technique", ""),
            t.get("category", ""), " ".join(t.get("languages", [])),
            " ".join(t.get("cve", [])), " ".join(t.get("detection_indicators", [])),
        ]).lower()
        if q in hay:
            hits.append(_index_entry(t))
    return sorted(hits, key=lambda e: _SEV.get(str(e.get("severity")).lower(), 5))


def by_category(category: str) -> list[dict]:
    c = category.strip().lower()
    return [_index_entry(t) for t in TECHNIQUES if str(t.get("category", "")).lower() == c]


def by_language(language: str) -> list[dict]:
    lang = language.strip().lower()
    return [_index_entry(t) for t in TECHNIQUES
            if any(lang in str(lang_).lower() for lang_ in t.get("languages", []))]


def stats() -> dict:
    by_cat: dict[str, int] = {}
    langs: set[str] = set()
    for t in TECHNIQUES:
        by_cat[t.get("category", "other")] = by_cat.get(t.get("category", "other"), 0) + 1
        langs.update(str(lang_).lower() for lang_ in t.get("languages", []))
    return {"techniques": len(TECHNIQUES), "by_category": by_cat, "languages": sorted(langs)}
