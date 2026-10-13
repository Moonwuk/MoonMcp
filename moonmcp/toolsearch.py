"""Task-driven tool discovery (AGENT_NAVIGATION_PLAN.md stage 1).

``tool_search`` hands the agent a SHORT candidate list for the job in
front of it, with the reason each candidate matched — instead of a
172KB tools/list. The searchable index is generated from the live
registry (family, purpose, gate flags) plus a small hand-curated
keyword map, so it can never silently drift from what is registered
(a contract test enforces that).

The search deliberately does NOT promise dynamic schema loading: the
plan is explicit that a short catalog does not shrink what the client
loads. What it does fix is the *choice* problem — «which 3 tools do I
need for THIS observation» — at a fraction of the full map's context
cost.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from . import catalog as cat

# Observation/phase → tool name keywords. Curated from the navigation
# plan's table and the families' blurbs; intentionally small — the
# purpose text of every tool is searched too, this only biases it.
_BIAS: dict[str, list[str]] = {
    "recon": ["subdomain", "dns", "wayback", "probe", "fingerprint", "recon",
              "well_known", "tls", "crawl"],
    "injection": ["sqli", "xss", "ssti", "cmdi", "xxe", "nosqli", "interp",
                  "injection", "lfi", "traversal"],
    "auth": ["auth", "jwt", "oauth", "saml", "session", "idor", "access_control",
             "authz", "bola", "mfa", "password", "login"],
    "logic": ["logic", "race", "workflow", "value", "mass", "parameter", "ratelimit"],
    "infra": ["waf", "cache", "cors", "vhost", "desync", "smuggling", "edge",
              "backend", "ratelimit", "timing"],
    "ssrf": ["ssrf", "gopher", "metadata", "smuggling", "protocol"],
    "report": ["finding", "report", "export", "cvss", "remediation", "triage",
                "obsidian", "sarif"],
    "knowledge": ["knowledge", "payload", "cheat", "writeup", "dataset",
                  "nuclei", "cve", "playbook", "injection_info"],
    "oast": ["oast", "blind", "callback", "canary", "interactsh"],
    "run": ["run_", "task", "coverage", "budget", "artifact"],
}


@dataclass
class Candidate:
    name: str
    family: str
    purpose: str
    reason: str
    scope_gated: bool
    intrusive: bool


def _tokens(text: str) -> set[str]:
    return {w for w in re.split(r"[^a-z0-9_]+", text.lower()) if len(w) > 1}


def _phase_terms(phase: str) -> list[str]:
    key = (phase or "").strip().lower()
    for known, terms in _BIAS.items():
        if key == known or key.startswith(known):
            return terms
    # unknown phase: treat the phase string itself as part of the query
    return sorted(_tokens(phase))[:6] if key else []


def search(query: str, phase: str = "", available_only: bool = True,
           limit: int = 5) -> dict:
    """Rank tools for the task at hand. Returns short cards with reasons."""
    meta = _live_meta()
    q = _tokens(query or "")
    phase_terms = set(_phase_terms(phase))

    scored: list[tuple[float, str, dict]] = []
    for name, info in meta.items():
        purpose_t = _tokens(info.get("purpose", ""))
        name_t = _tokens(name)
        # score: query tokens in the name weigh most, then purpose, then phase bias
        score = 0.0
        reason_bits: list[str] = []
        hits_name = q & name_t
        hits_purpose = q & purpose_t - name_t
        hits_phase = phase_terms & (name_t | purpose_t)
        if hits_name:
            score += 3.0 * len(hits_name)
            reason_bits.append("name match: " + ", ".join(sorted(hits_name)[:4]))
        if hits_purpose:
            score += 1.0 * len(hits_purpose)
            reason_bits.append("purpose: " + ", ".join(sorted(hits_purpose)[:4]))
        if hits_phase:
            score += 0.5 * len(hits_phase)
            reason_bits.append(f"phase bias ({phase})")
        if not score:
            continue
        if available_only and info.get("hidden"):
            continue
        scored.append((score, name, {**info, "reason": "; ".join(reason_bits)}))

    scored.sort(key=lambda x: (-x[0], x[1]))
    top = scored[: max(1, min(limit, 10))]

    candidates = [
        Candidate(
            name=name,
            family=cat.TOOL_FAMILY.get(name, "uncategorized"),
            purpose=info["purpose"],
            reason=info["reason"],
            scope_gated=bool(info.get("gated")),
            intrusive=bool(info.get("intrusive")),
        ).__dict__
        for _score, name, info in top
    ]
    return {
        "query": query,
        "phase": phase or None,
        "candidates": candidates,
        "count": len(candidates),
        "hint": (
            "Cards only — load the tool's full schema from the client when you "
            "call it. scope_gated/intrusive still apply per tool: family or "
            "search rank is never permission."
        ) if candidates else (
            "No candidates — try a different keyword or drop the phase filter."
        ),
    }


def _live_meta() -> dict[str, dict]:
    """name -> {purpose, gated, intrusive, hidden} from the live registry."""
    from .server import mcp
    out: dict[str, dict] = {}
    for t in mcp._tool_manager.list_tools():
        desc = " ".join((t.description or "").split())
        purpose = cat._first_sentence(desc)
        fn = getattr(t.fn, "__moonmcp_gated__", False)
        intr = getattr(t.fn, "__moonmcp_intrusive__", False)
        out[t.name] = {
            "purpose": purpose,
            "gated": fn,
            "intrusive": intr,
            "hidden": False,  # profile filtering already ran at import
        }
    return out