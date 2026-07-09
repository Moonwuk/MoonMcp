"""Query API over the privilege-escalation knowledge base.

A *referenced* catalog for authorised security research: privilege-escalation
techniques across Linux / Windows / container / cloud / Active Directory, plus a
catalog of the tooling operators use to find and exploit them.  It ships
conceptual descriptions, benign enumeration commands, detection indicators and
links to public research — **no** weaponized exploit code.

The most useful live feature is :func:`match_enumeration`: paste the output of a
local enumeration command (``sudo -l``, ``id``, a SUID listing, ``whoami /priv``,
``systeminfo`` …) and it tells you which known privilege-escalation vectors that
output *smells* like (e.g. ``NOPASSWD`` → sudo abuse, ``SeImpersonatePrivilege``
→ a potato attack, ``cap_setuid`` → a capabilities escalation).

Data lives in :mod:`moonmcp.knowledge.privesc_data`.
"""

from __future__ import annotations

import re
from functools import lru_cache

from .privesc_data import PRIVESC, PRIVESC_TOOLS

_SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# generic tokens that are too noisy to match on their own
_STOPWORDS = {
    "path", "id", "root", "sudo", "cron", "service", "admin", "user", "group",
    "dll", "tar", "sID", "acl", "com", "run", "job", "key", "log", "the", "and",
}


def _index_entry(t: dict) -> dict:
    return {
        "id": t["id"],
        "name": t["name"],
        "platform": t.get("platform"),
        "category": t.get("category"),
        "severity": t.get("severity"),
        "summary": t.get("summary", ""),
    }


def list_techniques() -> list[dict]:
    return [_index_entry(t) for t in PRIVESC]


def get_technique(technique_id: str) -> dict | None:
    tid = technique_id.strip().lower()
    for t in PRIVESC:
        if t["id"] == tid:
            return t
    up = technique_id.strip().upper()
    for t in PRIVESC:
        if up in [c.upper() for c in t.get("cve", [])]:
            return t
    return None


def _rank(entries: list[dict]) -> list[dict]:
    return sorted(entries, key=lambda e: _SEV.get(str(e.get("severity")).lower(), 5))


def search(query: str) -> list[dict]:
    q = query.strip().lower()
    if not q:
        return list_techniques()
    hits = []
    for t in PRIVESC:
        hay = " ".join([
            t["id"], t["name"], t.get("summary", ""), t.get("technique", ""),
            t.get("platform", ""), t.get("category", ""),
            " ".join(t.get("cve", [])), " ".join(t.get("tools", [])),
            " ".join(t.get("detection_indicators", [])),
        ]).lower()
        if q in hay:
            hits.append(_index_entry(t))
    return _rank(hits)


def by_platform(platform: str) -> list[dict]:
    p = platform.strip().lower()
    return _rank([_index_entry(t) for t in PRIVESC if str(t.get("platform", "")).lower() == p])


def by_category(category: str) -> list[dict]:
    c = category.strip().lower()
    return _rank([_index_entry(t) for t in PRIVESC if str(t.get("category", "")).lower() == c])


def platforms() -> list[str]:
    return sorted({str(t.get("platform", "other")) for t in PRIVESC})


def categories() -> list[str]:
    return sorted({str(t.get("category", "other")) for t in PRIVESC})


# --- tools catalog ----------------------------------------------------------
def list_tools() -> list[dict]:
    return [
        {"id": t["id"], "name": t["name"], "platform": t.get("platform"),
         "category": t.get("category"), "summary": t.get("summary", ""), "url": t.get("url", "")}
        for t in PRIVESC_TOOLS
    ]


def get_tool(tool_id: str) -> dict | None:
    tid = tool_id.strip().lower()
    for t in PRIVESC_TOOLS:
        if t["id"] == tid or tid == t.get("name", "").lower():
            return t
    return None


def search_tools(query: str) -> list[dict]:
    q = query.strip().lower()
    out = []
    for t in PRIVESC_TOOLS:
        hay = " ".join([t["id"], t["name"], t.get("summary", ""), t.get("category", ""),
                        t.get("platform", ""), t.get("usage_note", "")]).lower()
        if not q or q in hay:
            out.append({"id": t["id"], "name": t["name"], "platform": t.get("platform"),
                        "category": t.get("category"), "summary": t.get("summary", ""),
                        "url": t.get("url", "")})
    return out


# --- enumeration-output matching -------------------------------------------
def _is_signalish(indicator: str) -> bool:
    """True if an indicator is specific enough to match against pasted output.

    Requires some specificity marker (a capital, digit, or one of ``_./:=-``) so
    bare generic words — ``docker``, ``enabled``, ``unquoted`` — can't fire a
    CRITICAL match on unrelated prose, while keeping precise tokens like
    ``SeImpersonatePrivilege``, ``cap_setuid``, ``docker.sock``, ``NOPASSWD`` and
    ``/etc/passwd``.
    """

    ind = indicator.strip()
    if not (4 <= len(ind) <= 48):
        return False
    if ind.count(" ") > 4:  # a full sentence, not a token/pattern
        return False
    if ind.lower() in _STOPWORDS:
        return False
    if not any(c.isupper() or c.isdigit() or c in "_./:=-" for c in ind):
        return False
    return True


@lru_cache(maxsize=1)
def _compiled_indicators() -> list[tuple[str, str, str, str, re.Pattern]]:
    """(technique_id, platform, severity, indicator, compiled_regex) per usable indicator."""

    compiled: list[tuple[str, str, str, str, re.Pattern]] = []
    for t in PRIVESC:
        for ind in t.get("detection_indicators", []):
            if not _is_signalish(ind):
                continue
            try:
                pat = re.compile(re.escape(ind), re.IGNORECASE)
            except re.error:
                continue
            compiled.append((t["id"], t.get("platform", ""), str(t.get("severity", "")), ind, pat))
    return compiled


def match_enumeration(text: str, platform: str | None = None) -> list[dict]:
    """Scan pasted enumeration output for known privilege-escalation vectors.

    Returns one entry per matched technique: the technique it indicates, the
    matched indicator, platform and severity — severity-ranked.
    """

    if not text:
        return []
    want = platform.strip().lower() if platform else None
    out: list[dict] = []
    seen: set[str] = set()
    for tid, plat, sev, ind, pat in _compiled_indicators():
        if want and str(plat).lower() != want:
            continue
        if tid in seen:
            continue
        if pat.search(text):
            seen.add(tid)
            t = get_technique(tid) or {}
            out.append({
                "technique": tid,
                "name": t.get("name", tid),
                "platform": plat,
                "category": t.get("category"),
                "severity": sev,
                "matched": ind,
                "summary": t.get("summary", ""),
            })
    return _rank(out) if out else out


def stats() -> dict:
    by_platform_: dict[str, int] = {}
    by_category_: dict[str, int] = {}
    for t in PRIVESC:
        p = str(t.get("platform", "other"))
        c = str(t.get("category", "other"))
        by_platform_[p] = by_platform_.get(p, 0) + 1
        by_category_[c] = by_category_.get(c, 0) + 1
    return {
        "techniques": len(PRIVESC),
        "tools": len(PRIVESC_TOOLS),
        "by_platform": by_platform_,
        "by_category": by_category_,
        "matchable_indicators": len(_compiled_indicators()),
    }
