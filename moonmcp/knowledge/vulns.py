"""Query API over the server-side vulnerability catalog + root-cause taxonomy.

A *referenced* catalog for authorised security research: popular and obscure
server-side vulnerability classes, each mapped to the ROOT CAUSE it springs from
and the concrete point where real apps get it wrong.  The root-cause taxonomy
answers "where is the core of all these problems?" — the handful of fundamental
causes underneath nearly every web/server bug.  Data lives in
:mod:`moonmcp.knowledge.vulns_data`.
"""

from __future__ import annotations

from .vulns_data import ROOT_CAUSES, SERVER_SIDE_VULNS, VULN_TOOLS

_SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _index(v: dict) -> dict:
    return {
        "id": v["id"],
        "name": v["name"],
        "category": v.get("category"),
        "severity": v.get("severity"),
        "popularity": v.get("popularity"),
        "root_cause": v.get("root_cause"),
        "summary": v.get("summary", ""),
    }


def _rank(items: list[dict]) -> list[dict]:
    return sorted(items, key=lambda e: _SEV.get(str(e.get("severity")).lower(), 5))


def list_vulns() -> list[dict]:
    return [_index(v) for v in SERVER_SIDE_VULNS]


def get_vuln(vuln_id: str) -> dict | None:
    vid = vuln_id.strip().lower()
    for v in SERVER_SIDE_VULNS:
        if v["id"] == vid:
            return v
    for v in SERVER_SIDE_VULNS:  # forgiving: match on category too
        if str(v.get("category", "")).lower() == vid:
            return v
    return None


def search(query: str) -> list[dict]:
    q = query.strip().lower()
    if not q:
        return list_vulns()
    hits = []
    for v in SERVER_SIDE_VULNS:
        hay = " ".join([
            v["id"], v["name"], v.get("summary", ""), v.get("category", ""),
            v.get("root_cause", ""), v.get("where_it_breaks", ""),
            " ".join(v.get("real_world", [])), " ".join(v.get("tools", [])),
        ]).lower()
        if q in hay:
            hits.append(_index(v))
    return _rank(hits)


def by_category(category: str) -> list[dict]:
    c = category.strip().lower()
    return _rank([_index(v) for v in SERVER_SIDE_VULNS if str(v.get("category", "")).lower() == c])


def by_popularity(popularity: str) -> list[dict]:
    p = popularity.strip().lower()
    return _rank([_index(v) for v in SERVER_SIDE_VULNS if str(v.get("popularity", "")).lower() == p])


def by_root_cause(root_cause: str) -> list[dict]:
    rc = root_cause.strip().lower()
    return _rank([_index(v) for v in SERVER_SIDE_VULNS if str(v.get("root_cause", "")).lower() == rc])


def categories() -> list[str]:
    return sorted({str(v.get("category", "other")) for v in SERVER_SIDE_VULNS})


# --- root-cause taxonomy ----------------------------------------------------
def list_root_causes() -> list[dict]:
    return [{"id": r["id"], "name": r["name"], "summary": r.get("summary", ""),
             "derived_vuln_classes": r.get("derived_vuln_classes", [])} for r in ROOT_CAUSES]


def get_root_cause(root_id: str) -> dict | None:
    rid = root_id.strip().lower()
    for r in ROOT_CAUSES:
        if r["id"] == rid:
            # attach the concrete vulns that derive from this cause
            derived = [{"id": v["id"], "name": v["name"], "category": v.get("category")}
                       for v in SERVER_SIDE_VULNS if v.get("root_cause") == rid]
            return {**r, "vulns_in_catalog": derived}
    return None


# --- tooling ----------------------------------------------------------------
def list_tools() -> list[dict]:
    return [{"id": t["id"], "name": t["name"], "category": t.get("category"),
             "target": t.get("target", ""), "summary": t.get("summary", ""),
             "url": t.get("url", "")} for t in VULN_TOOLS]


def get_tool(tool_id: str) -> dict | None:
    tid = tool_id.strip().lower()
    for t in VULN_TOOLS:
        if t["id"] == tid or tid == t.get("name", "").lower():
            return t
    return None


def search_tools(query: str) -> list[dict]:
    q = query.strip().lower()
    out = []
    for t in VULN_TOOLS:
        hay = " ".join([t["id"], t["name"], t.get("summary", ""), t.get("category", ""),
                        t.get("target", "")]).lower()
        if not q or q in hay:
            out.append({"id": t["id"], "name": t["name"], "category": t.get("category"),
                        "target": t.get("target", ""), "summary": t.get("summary", ""),
                        "url": t.get("url", "")})
    return out


def stats() -> dict:
    by_cat: dict[str, int] = {}
    by_pop: dict[str, int] = {}
    for v in SERVER_SIDE_VULNS:
        by_cat[v.get("category", "other")] = by_cat.get(v.get("category", "other"), 0) + 1
        by_pop[v.get("popularity", "common")] = by_pop.get(v.get("popularity", "common"), 0) + 1
    return {
        "vulns": len(SERVER_SIDE_VULNS),
        "root_causes": len(ROOT_CAUSES),
        "tools": len(VULN_TOOLS),
        "by_category": by_cat,
        "by_popularity": by_pop,
    }
