"""Query API over the injection knowledge base.

The data lives in :mod:`moonmcp.knowledge.injections_data` (one dict per injection
class).  This module provides lookup, search and — most usefully for a live
recon — :func:`match_signatures`, which scans an HTTP response body against every
class's error/regex signatures to tell you which injection a response *smells*
like (e.g. a raw ``ORA-01756`` error → Oracle SQL injection).
"""

from __future__ import annotations

import re
from functools import lru_cache

from .injections_data import INJECTIONS


def list_classes() -> list[dict]:
    """A compact index: id, name, cwe, severity, one-line summary."""

    return [
        {
            "id": c["id"],
            "name": c["name"],
            "cwe": c.get("cwe", []),
            "severity": c.get("severity"),
            "summary": c.get("summary", ""),
        }
        for c in INJECTIONS
    ]


def get_class(class_id: str) -> dict | None:
    cid = class_id.strip().lower()
    for c in INJECTIONS:
        if c["id"] == cid or cid in [a.lower() for a in c.get("aliases", [])]:
            return c
    return None


def search(query: str) -> list[dict]:
    q = query.strip().lower()
    if not q:
        return list_classes()
    hits = []
    for c in INJECTIONS:
        hay = " ".join([
            c["id"], c["name"], c.get("summary", ""),
            " ".join(c.get("aliases", [])), " ".join(c.get("cwe", [])),
        ]).lower()
        if q in hay:
            hits.append({"id": c["id"], "name": c["name"], "severity": c.get("severity"),
                         "summary": c.get("summary", "")})
    return hits


@lru_cache(maxsize=1)
def _compiled_signatures() -> list[tuple[str, str, str, re.Pattern]]:
    """(class_id, technology, meaning, compiled_regex) for every regex/error signature."""

    compiled: list[tuple[str, str, str, re.Pattern]] = []
    for c in INJECTIONS:
        for sig in c.get("signatures", []):
            stype = str(sig.get("type", "")).lower()
            if stype not in ("error", "regex"):
                continue  # behavioral signatures aren't text-matchable
            value = sig.get("value", "")
            if not value:
                continue
            try:
                # 'error' signatures are literal strings; 'regex' are patterns.
                pattern = re.compile(value if stype == "regex" else re.escape(value), re.IGNORECASE)
            except re.error:
                try:
                    pattern = re.compile(re.escape(value), re.IGNORECASE)
                except re.error:
                    continue
            compiled.append((c["id"], sig.get("technology", "generic"), sig.get("meaning", ""), pattern))
    return compiled


def match_signatures(text: str, class_id: str | None = None) -> list[dict]:
    """Scan *text* (e.g. an HTTP response body) for injection error signatures.

    Returns one entry per matched signature: the injection class it indicates,
    the technology (DBMS/engine), the matched snippet and its meaning.
    """

    if not text:
        return []
    want = class_id.strip().lower() if class_id else None
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for cid, tech, meaning, pattern in _compiled_signatures():
        if want and cid != want:
            continue
        m = pattern.search(text)
        if not m:
            continue
        key = (cid, m.group(0)[:60])
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "class": cid,
            "technology": tech,
            "matched": m.group(0)[:120],
            "meaning": meaning,
        })
    return out


def stats() -> dict:
    return {
        "classes": len(INJECTIONS),
        "total_payloads": sum(len(c.get("detection_payloads", [])) for c in INJECTIONS),
        "total_signatures": sum(len(c.get("signatures", [])) for c in INJECTIONS),
    }
