"""Response shaping — a concise view of a big result, on demand.

Recon tools can emit large payloads (hundreds of subdomains, a full crawl tree, a
long request history). Streaming all of it into the agent's context on every call
burns the token budget it needs for the actual hunt. `concise` trims the long
lists to a preview and marks how much was withheld; the tool exposes a
`response_format` param so the agent asks for `"detailed"` only when it needs the
full set.

Deliberately conservative: only lists *longer than* ``max_list`` are trimmed, and
only their length changes — every key, scalar, and short list is passed through
untouched, so a concise result is a strict subset of the detailed one.
"""

from __future__ import annotations

from typing import Any

_HINT = "call again with response_format='detailed' for the full list"


def concise(obj: Any, *, max_list: int = 20) -> Any:
    """Recursively trim lists longer than *max_list* to a preview (pure).

    A trimmed list keeps its first *max_list* items and appends a sentinel dict
    ``{"_truncated": <total>, "_shown": max_list, "_hint": ...}`` so the caller
    knows the result was clipped and how to get the rest. Dicts recurse into their
    values; lists recurse into their (kept) items; everything else is returned
    as-is."""

    if isinstance(obj, dict):
        return {k: concise(v, max_list=max_list) for k, v in obj.items()}
    if isinstance(obj, list):
        if len(obj) > max_list:
            head = [concise(v, max_list=max_list) for v in obj[:max_list]]
            head.append({"_truncated": len(obj), "_shown": max_list, "_hint": _HINT})
            return head
        return [concise(v, max_list=max_list) for v in obj]
    return obj


def apply(result: dict, response_format: str, *, max_list: int = 20) -> dict:
    """Return *result* unchanged for ``detailed``; a `concise` view otherwise.

    Any value other than the exact string ``"detailed"`` (case-insensitive) means
    concise — the safe default, since a stray value shouldn't dump the full
    payload."""

    if str(response_format).strip().lower() == "detailed":
        return result
    return concise(result, max_list=max_list)
