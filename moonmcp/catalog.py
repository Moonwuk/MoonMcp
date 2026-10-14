"""A self-describing map of MoonMCP's own tools.

An agent lands on MoonMCP with 120+ tools and no idea where to start. This module
groups every tool into a family, records how much each one touches the target
(scope-gated? intrusive?), and lays out the recommended recon → report order —
so `tool_catalog` (and the packaged skill) can hand the model a compact,
machine-readable map instead of making it read 90 docstrings.

Pure data + one pure function (``build_catalog``); the server tool supplies the
live descriptions and gate markers so this never drifts from what is registered
(a test asserts every registered tool appears here exactly once).
"""

from __future__ import annotations

from .registry import FAMILIES, ORIENTATION_TOOLS, TOOL_FAMILY

# The recommended order of operations for a fresh engagement.
# Run-aware (AGENT_NAVIGATION_PLAN.md): the run_* coordinator frames the work;
# steps 1-4 stay the same for ad-hoc sessions without a run.
WORKFLOW: list[str] = [
    "server_status — see config, the active program and which external CLIs are present.",
    "RECALL — memory_brief(target) / memory_search(target=…) first: build on prior/other-agents' "
    "work, skip recon already done (recon_target/report also surface a prior_memory block); "
    "memory_lesson(action=recall) to apply past tradecraft.",
    "Run or ad-hoc — for a structured assessment: run_start(target, budget=…) seeds the "
    "coordinator→mapper→hypothesis→validator→reporter task graph; run_next hands out one "
    "dependency-ordered task at a time; run_usage records actual spend; run_finish refuses "
    "unfinished work (force=true to override). Without a run, continue ad-hoc.",
    "program_add / scope_add — authorise the target and set the program's bug-bounty header. "
    "The profile/family is NOT permission: scope, auth and intrusive gates apply to every tool.",
    "Passive OSINT — web_search (multi-engine) then web_read a promising result, "
    "enumerate_subdomains, wayback_urls, cve_search, host_intel.",
    "Light active — recon_target for a one-shot sweep, then http_probe / fingerprint / "
    "analyze_headers / well_known / tls_inspect.",
    "Web-app — crawl, analyze_js, discover_parameters, cors_audit, graphql_check, "
    "extract_secrets; access_control_check / authz_probe after auth_set for IDOR/BOLA.",
    "Intrusive (only with explicit consent + MOONMCP_ALLOW_INTRUSIVE) — port_scan, "
    "content_discovery, vuln_scan (then also_run_native), logic_probe / workflow_probe / value_probe.",
    "Confirm — turn a probe's review lead into a proof: promote_lead(kind=…) routes it to "
    "confirm_finding / side-effect re-observation / a Strix PoC brief. Verify each lead "
    "independently before believing it (validator session or oracle), not by re-reading the finder.",
    "Record & report — add_finding / promote_lead as you go (both mirror to shared memory), "
    "triage_findings to dedupe, then report / export_findings / export_obsidian. For run-based "
    "sessions: run_coverage_update, export saved via run_artifact_add, then run_finish.",
]

# Observation → minimal next step (AGENT_NAVIGATION_PLAN.md navigation table).
# The map from what you SEE to the smallest useful action — not a linear checklist.
NAVIGATION: dict[str, str] = {
    "unknown surface": "http_probe / fingerprint first; then only the recon slices you still miss",
    "openapi or JS endpoints": "parse_openapi / analyze_js; then refine parameters",
    "auth and roles": "auth_set, then access_control_check / authz_probe when context allows",
    "graphql signs": "graphql_check; deepen by the specific observation",
    "JS app, data not in HTML": "browser_open; then act on DOM/network observations",
    "ambiguous param behaviour": "class reference (injection_info) → the matching detector; confirm separately",
    "a lead": "specialised probe, baseline + control → confirm_finding / promote_lead as applicable",
    "results ready": "triage_findings → export → artifact (run_artifact_add) → run_finish",
    "budget refused": "stop; do not start new work — record the blocked task with the reason",
}

# Named exposure profiles → the set of families to expose. Used to hand a *curated
# slice* of MoonMCP to another agent (e.g. embed the knowledge + memory + recon
# slice inside Strix, which already has its own scanners/proxy/browser). ``full``
# (None) exposes everything and is the default.
PROFILES: dict[str, set[str] | None] = {
    "full": None,
    # For strengthening an external autonomous tool (Strix): give it MoonMCP's
    # reference brain + shared memory + cheap scope-gated recon, NOT the heavy
    # scanners/proxy it already has (intrusive / external / intercept / orchestration).
    "strix": {"setup", "passive_osint", "light_active", "knowledge", "memory", "reporting"},
    # No active probing of the target — safe to expose broadly.
    "passive": {"setup", "passive_osint", "knowledge", "memory", "reporting"},
    # Pure offline reference + shared memory.
    "knowledge": {"knowledge", "memory"},
    # Recon-only (no knowledge bases, no memory).
    "recon": {"setup", "passive_osint", "light_active", "orchestration", "reporting"},
}

# Always reachable so an agent can orient itself and check scope, whatever the profile.
_ALWAYS_ON = ORIENTATION_TOOLS


def profile_names() -> list[str]:
    return list(PROFILES)


def select_profile(all_names, *, profile: str | None = None,
                   expose=(), hide=()) -> set[str]:
    """Return the subset of ``all_names`` to expose for the given profile /
    expose-list / hide-list. Names in ``expose``/``hide`` may be tool names or
    family names. Empty inputs → expose everything (the default)."""

    names = set(all_names)
    prof = (profile or "").strip().lower()
    expose = {str(e).strip() for e in expose if str(e).strip()}
    hide = {str(h).strip() for h in hide if str(h).strip()}
    if not prof and not expose and not hide:
        return names

    fam_set = PROFILES.get(prof)
    if prof in PROFILES and fam_set is not None:
        allowed = {n for n in names if TOOL_FAMILY.get(n) in fam_set}
    elif prof == "full":
        allowed = set(names)
    elif prof:
        # Fail closed (AGENT_NAVIGATION_PLAN.md stage 1): an unknown profile is a
        # configuration error, not license to expose everything. Only the
        # orientation tools stay reachable so a client can diagnose and fix.
        allowed = set()
    elif expose:  # an explicit expose-list with no profile → whitelist
        allowed = set()
    else:  # hide-only → start from everything
        allowed = set(names)

    if expose:
        allowed |= {n for n in names if n in expose or TOOL_FAMILY.get(n) in expose}
    if hide:
        allowed -= {n for n in names if n in hide or TOOL_FAMILY.get(n) in hide}
    allowed |= (names & _ALWAYS_ON)
    return allowed


def _first_sentence(text: str, limit: int = 160) -> str:
    """The first sentence of a tool description (what the tool is *for*)."""

    s = " ".join((text or "").split())
    for end in (". ", ".\n", ".\t"):
        idx = s.find(end)
        if 0 < idx <= limit:
            return s[: idx + 1]
    return s[:limit].rstrip() + ("…" if len(s) > limit else "")


def build_catalog(meta: dict[str, dict], *, family: str | None = None) -> dict:
    """Assemble the catalog from live tool ``meta`` (name -> {description, gated,
    intrusive}).

    Returns families in the suggested order, each tool tagged with its purpose and
    gate flags, plus the workflow. Any registered tool missing from FAMILIES is
    surfaced under ``uncategorized`` so the map can never silently drift.
    """

    known = set(TOOL_FAMILY)
    uncategorized = sorted(set(meta) - known)

    families_out: list[dict] = []
    for fam, (title, blurb, names) in FAMILIES.items():
        if family and fam != family:
            continue
        tools = []
        for name in names:
            info = meta.get(name)
            if info is None:
                continue  # a family lists a tool that isn't registered (caught by tests)
            tools.append({
                "name": name,
                "purpose": _first_sentence(info.get("description", "")),
                "scope_gated": bool(info.get("gated")),
                "intrusive": bool(info.get("intrusive")),
            })
        families_out.append({"family": fam, "title": title, "blurb": blurb,
                             "count": len(tools), "tools": tools})

    out: dict = {
        "total_tools": len(meta),
        "families": families_out,
        "workflow": WORKFLOW,
        "navigation": NAVIGATION,
        "safety": (
            "Authorised testing only. Every 'scope_gated' tool refuses out-of-scope "
            "targets and blocked private IPs; 'intrusive' tools also need "
            "MOONMCP_ALLOW_INTRUSIVE and explicit consent."
        ),
    }
    if uncategorized:
        out["uncategorized"] = uncategorized
    return out
