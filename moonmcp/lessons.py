"""Lesson hygiene — keep the learning loop from rotting into stale, unvetted, or
contradictory noise.

``memory_lesson`` stores free-text tradecraft ("technique X didn't work behind WAF
Y"). Left ungoverned it accumulates three failure modes the store can't catch on
its own: (1) **unvetted** one-off claims that were a fluke or a misconfigured
probe; (2) **stale** lessons — a WAF/target changes and last year's bypass no
longer holds; (3) outright **contradictions** — one lesson says a technique works,
another says it doesn't. This module scores lessons by corroboration, ages them
against a TTL, and flags contradictory pairs so the agent reconciles instead of
trusting a coin-flip. Purely offline and deterministic — no LLM, no network.

Confidence is corroboration count: re-asserting the same lesson bumps it, so a
claim three independent runs agree on outranks a one-off. Staleness needs a
timestamp (``created_at``); a lesson with no timestamp is treated as *unknown age*,
never silently pruned.
"""

from __future__ import annotations

import re
from datetime import datetime


# -- confidence --------------------------------------------------------------
def confidence_label(count: int) -> str:
    """Map a corroboration count to a label (pure)."""

    if count >= 3:
        return "corroborated"
    if count == 2:
        return "supported"
    return "unverified"


# -- polarity / contradictions ----------------------------------------------
# A lesson claim is negative if it says a thing does NOT work / is blocked.
_NEG = re.compile(
    r"\b(?:no|not|never|none|doesn'?t|does not|didn'?t|did not|isn'?t|is not|"
    r"wasn'?t|won'?t|will not|can'?t|cannot|couldn'?t|fail(?:s|ed)?|block(?:s|ed)?|"
    r"useless|ineffective|unaffected|immune|without|bypass(?:es|ed)? nothing)\b",
    re.IGNORECASE,
)

_WORD = re.compile(r"[a-z0-9][a-z0-9_-]{2,}")
# Common words + the polarity words themselves — excluded from the *subject* so
# two lessons about the same subject with opposite polarity still overlap.
_STOP = {
    "the", "and", "for", "with", "that", "this", "was", "were", "are", "has", "have",
    "use", "used", "using", "via", "but", "still", "when", "from", "into", "over",
    "http", "https", "does", "did", "not", "never", "none", "isnt", "wasnt",
    "cant", "cannot", "couldnt", "wont", "doesnt", "didnt", "fail", "fails", "failed",
    "block", "blocks", "blocked", "useless", "ineffective", "without", "work", "works",
    "worked", "working", "against", "target", "probe", "technique",
}


def polarity(text: str) -> int:
    """+1 (the claim is affirmative) or -1 (negative) — crude, offline."""

    return -1 if _NEG.search(text or "") else 1


def _subject_tokens(row: dict) -> set[str]:
    text = f"{row.get('title', '')} {row.get('body', '')}".lower()
    return {w for w in _WORD.findall(text) if w not in _STOP}


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def find_contradictions(rows: list[dict], *, overlap: float = 0.5) -> list[dict]:
    """Pairs of lessons about the same subject (token overlap ≥ *overlap*) whose
    claims have opposite polarity — a contradiction to reconcile (pure)."""

    out: list[dict] = []
    prepared = [
        (r, _subject_tokens(r), polarity(f"{r.get('title', '')} {r.get('body', '')}"))
        for r in rows
    ]
    for i in range(len(prepared)):
        ri, si, pi = prepared[i]
        for j in range(i + 1, len(prepared)):
            rj, sj, pj = prepared[j]
            if pi != pj and _jaccard(si, sj) >= overlap:
                out.append({
                    "a": {"id": ri.get("id"), "title": ri.get("title")},
                    "b": {"id": rj.get("id"), "title": rj.get("title")},
                    "overlap": round(_jaccard(si, sj), 2),
                })
    return out


# -- staleness ---------------------------------------------------------------
def _parse(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(str(ts))
    except (ValueError, TypeError):
        return None


def age_days(created_at: str | None, now_iso: str) -> int | None:
    """Whole days between *created_at* and *now_iso*, or None if unparseable (pure)."""

    c, n = _parse(created_at), _parse(now_iso)
    if c is None or n is None:
        return None
    # Tolerate a naive/aware mix (both are UTC in practice) — subtracting one of
    # each would raise TypeError, so compare on a common naive basis.
    if (c.tzinfo is None) != (n.tzinfo is None):
        c, n = c.replace(tzinfo=None), n.replace(tzinfo=None)
    return max(0, (n - c).days)


def is_stale(created_at: str | None, now_iso: str, ttl_days: int) -> bool:
    """True if the lesson is older than *ttl_days*. Unknown age is NEVER stale
    (never prune a lesson we can't date) (pure)."""

    age = age_days(created_at, now_iso)
    return age is not None and age > ttl_days


def annotate(rows: list[dict], *, now_iso: str, ttl_days: int) -> list[dict]:
    """Return each lesson row with confidence label, age, and a stale flag (pure)."""

    out: list[dict] = []
    for r in rows:
        conf = int(r.get("confidence") or 1)
        out.append({
            "id": r.get("id"),
            "title": r.get("title"),
            "body": r.get("body"),
            "tags": r.get("tags"),
            "confidence": conf,
            "confidence_label": confidence_label(conf),
            "created_at": r.get("created_at") or "",
            "age_days": age_days(r.get("created_at"), now_iso),
            "stale": is_stale(r.get("created_at"), now_iso, ttl_days),
        })
    return out
