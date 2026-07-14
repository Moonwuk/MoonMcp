"""Progressive tool discovery — rank the tool surface by relevance to a query.

A server with 160+ tools is past the point where handing an agent every schema at
once helps: tool-selection accuracy drops as the visible set grows. `search_tools`
lets the agent ask for the handful of tools relevant to what it's doing ("graphql",
"jwt", "cache poisoning") and get back a short ranked list instead of the whole
catalogue — the same "retrieve the few, not the all" pattern the MCP ecosystem has
converged on.

This module is the pure ranker; the server tool supplies the live entries (name,
family, one-line gist per registered tool).
"""

from __future__ import annotations

import re

# name hit dominates (you searched for a tool), family next, gist last.
_W_NAME = 5
_W_FAMILY = 2
_W_GIST = 1

_TOKEN = re.compile(r"[a-z0-9]+")


def _tokens(query: str) -> list[str]:
    """Lowercase alphanumeric tokens of length >= 2 (drops noise like 'a'/'to')."""

    return [t for t in _TOKEN.findall(query.lower()) if len(t) >= 2]


def rank(query: str, entries: list[dict], limit: int = 6) -> list[dict]:
    """Rank *entries* ({name, family, gist}) by relevance to *query* (pure).

    Each query token scores ``_W_NAME`` when it's a substring of the tool name,
    ``_W_FAMILY`` in the family, ``_W_GIST`` in the gist; the scores sum. Entries
    with a zero score are dropped; ties break by name for stability. Returns the
    top *limit* as ``{name, family, gist, score}``."""

    toks = _tokens(query)
    if not toks:
        return []

    scored: list[dict] = []
    for e in entries:
        name = str(e.get("name", "")).lower()
        family = str(e.get("family", "")).lower()
        gist = str(e.get("gist", "")).lower()
        score = 0
        for t in toks:
            if t in name:
                score += _W_NAME
            if t in family:
                score += _W_FAMILY
            if t in gist:
                score += _W_GIST
        if score > 0:
            scored.append({"name": e.get("name", ""), "family": e.get("family", ""),
                           "gist": e.get("gist", ""), "score": score})

    scored.sort(key=lambda s: (-s["score"], str(s["name"])))
    return scored[:max(1, limit)]
