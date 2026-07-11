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

from collections import OrderedDict

# family key -> (title, one-line blurb, [tool names in suggested order])
FAMILIES: OrderedDict[str, tuple[str, str, list[str]]] = OrderedDict([
    ("setup", (
        "Setup & safety",
        "Authorise and identify before touching anything: scope, per-program "
        "header, engagement auth, out-of-band callbacks, audit trail.",
        [
            "server_status", "tool_catalog",
            "scope_list", "scope_add", "scope_exclude", "scope_remove",
            "program_add", "program_use", "program_list", "program_remove",
            "auth_set", "auth_clear",
            "oast_configure", "oast_selfhost", "oast_generate", "oast_poll", "oast_list",
            "audit_log",
        ],
    )),
    ("passive_osint", (
        "Passive OSINT",
        "Queries third-party datasets / search engines about the target — no "
        "packets to the target itself.",
        [
            "web_search", "search_dorks",
            "enumerate_subdomains", "wayback_urls",
            "cve_lookup", "cve_search",
            "host_intel", "ip_intel", "reverse_ip",
            "cloud_buckets", "email_security", "dependency_confusion",
        ],
    )),
    ("light_active", (
        "Light active",
        "Benign, low-noise in-scope requests: probe, fingerprint, crawl, and "
        "analyse the web-app surface (incl. a headless browser).",
        [
            "dns_lookup", "http_probe", "tls_inspect", "analyze_headers",
            "fingerprint", "well_known", "favicon_hash", "tls_fingerprint",
            "jarm_fingerprint", "origin_discovery", "behavior_probe",
            "crawl", "analyze_js", "recover_sourcemaps", "parse_openapi", "extract_secrets",
            "cors_audit", "access_control_check", "authz_probe", "graphql_check",
            "discover_parameters", "waf_detect", "takeover_check",
            "open_redirect", "trace_redirects", "crlf_probe", "vcs_exposure",
            "response_leak_probe", "reset_poison_probe", "path_bypass_probe",
            "debug_exposure",
            "screenshot", "browser_open", "browser_eval", "browser_interact",
            "analyze_binary", "analyze_config", "jwt_analyze", "jwt_crack",
            "oauth_probe", "oauth_redirect_probe",
        ],
    )),
    ("intrusive", (
        "Intrusive (gated)",
        "Noisier scanning that must be explicitly enabled with "
        "MOONMCP_ALLOW_INTRUSIVE — get consent first.",
        [
            "port_scan", "content_discovery", "http_methods",
            "waf_efficacy", "desync_probe", "desync_modern_probe", "vuln_scan",
            "cache_deception_probe", "stack_probe", "ssrf_metadata_probe",
            "logic_probe", "race_probe", "workflow_probe", "value_probe", "jwt_jku_probe",
            "nosqli_probe", "db_exposure", "second_order_sqli_probe", "orm_leak_probe",
        ],
    )),
    ("orchestration", (
        "Orchestration",
        "Chain the safe tools: batch liveness, a one-shot recon sweep, a report.",
        ["probe_batch", "recon_target", "report"],
    )),
    ("infra", (
        "Behavioural infrastructure",
        "Infer the infra's shape from response variance: backend fleet / patch "
        "drift, DNS/zone behaviour (wildcard, LB, dangling CNAME), Host-header "
        "routing, and rate-limit behaviour.",
        ["backend_probe", "dns_behavior", "vhost_probe", "ratelimit_probe",
         "tls_behavior", "edge_map", "http_behavior"],
    )),
    ("intercept", (
        "Interception & active probes",
        "Drive the Burp workflow from tools (repeater, intruder, passive scan, "
        "history), plus differential detectors for top-payout classes (SSTI, SQLi, "
        "blind SSRF, cache poisoning) and the confirm_finding gate.",
        ["http_repeater", "intruder", "passive_scan", "confirm_finding",
         "ssti_probe", "sqli_probe", "ssrf_probe", "cache_probe", "http_history"],
    )),
    ("knowledge", (
        "Knowledge bases",
        "Offline reference: injections, techniques/PoCs, privilege escalation, "
        "server-side vulns + root causes, WAF fingerprints. No traffic.",
        [
            "injection_info", "injection_search", "match_injection_signatures",
            "technique_info", "technique_search",
            "privesc_info", "privesc_search", "privesc_tools", "match_privesc",
            "vuln_info", "vuln_search", "vuln_tools", "rootcause_info",
            "waf_info", "identify_waf",
        ],
    )),
    ("reporting", (
        "Findings & reporting",
        "Record findings, export (SARIF/JSON/Obsidian), and diff the attack "
        "surface across runs.",
        [
            "add_finding", "promote_lead", "label_finding", "metrics",
            "list_findings", "clear_findings", "triage_findings",
            "cvss_score", "export_findings", "export_obsidian",
            "surface_diff", "surface_snapshots",
        ],
    )),
    ("memory", (
        "Shared memory hub",
        "Persistent, cross-agent, provenance/trust-tagged memory (SQLite + FTS) "
        "so agents build on each other's work instead of re-deriving context.",
        ["memory_add", "memory_search", "memory_get", "memory_stats"],
    )),
    ("external", (
        "External CLIs",
        "Detect and safely drive installed security CLIs (scope-checked, "
        "file-I/O flags refused). Gated by MOONMCP_ALLOW_EXTERNAL_TOOLS.",
        ["external_tools", "run_scanner", "scan_coverage"],
    )),
])

# The recommended order of operations for a fresh engagement.
WORKFLOW: list[str] = [
    "server_status — see config, the active program and which external CLIs are present.",
    "RECALL — memory_search(target=…) first: build on prior/other-agents' work, skip recon "
    "already done (recon_target/report also surface a prior_memory block).",
    "program_add / scope_add — authorise the target and set the program's bug-bounty header.",
    "Passive OSINT — web_search, enumerate_subdomains, wayback_urls, cve_search, host_intel.",
    "Light active — recon_target for a one-shot sweep, then http_probe / fingerprint / "
    "analyze_headers / well_known / tls_inspect.",
    "Web-app — crawl, analyze_js, discover_parameters, cors_audit, graphql_check, "
    "extract_secrets; access_control_check / authz_probe after auth_set for IDOR/BOLA.",
    "Intrusive (only with explicit consent + MOONMCP_ALLOW_INTRUSIVE) — port_scan, "
    "content_discovery, vuln_scan (then also_run_native), logic_probe / workflow_probe / value_probe.",
    "Confirm — turn a probe's review lead into a proof: promote_lead(kind=…) routes it to "
    "confirm_finding / side-effect re-observation / a Strix PoC brief.",
    "Record & report — add_finding / promote_lead as you go (both mirror to shared memory), "
    "triage_findings to dedupe, then report / export_findings / export_obsidian.",
]

# Which family a tool name belongs to (inverted from FAMILIES).
TOOL_FAMILY: dict[str, str] = {
    name: fam for fam, (_t, _b, names) in FAMILIES.items() for name in names
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
_ALWAYS_ON = {"server_status", "tool_catalog", "scope_list"}


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
    elif expose:  # an explicit expose-list with no (or 'full') profile → whitelist
        allowed = set()
    else:  # 'full', unknown profile, or hide-only → start from everything
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
        "safety": (
            "Authorised testing only. Every 'scope_gated' tool refuses out-of-scope "
            "targets and blocked private IPs; 'intrusive' tools also need "
            "MOONMCP_ALLOW_INTRUSIVE and explicit consent."
        ),
    }
    if uncategorized:
        out["uncategorized"] = uncategorized
    return out
