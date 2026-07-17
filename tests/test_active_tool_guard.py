"""Scope-coverage guard.

Every packet-sending tool must pass MoonMCP's single scope choke point — the
``@active_tool`` decorator. This test enumerates every registered tool and fails
loudly if one sends traffic without the gate (or if the passive allowlist drifts
out of date), so an un-gated capability can never ship by accident.
"""

from moonmcp import server as srv

# Tools that legitimately need NO scope gate: server meta, scope/program/auth/
# oast management, keyless OSINT that never touches the *target*, the offline
# knowledge bases, and the reporting/findings helpers. Everything else must be
# an @active_tool. Adding a new tool here is a deliberate, reviewed decision.
PASSIVE = {
    # meta / management
    "server_status", "tool_catalog", "search_tools",
    "scope_list", "scope_add", "scope_exclude", "scope_remove",
    "program_add", "program_use", "program_list", "program_remove",
    "auth_set", "auth_clear",
    "oast_configure", "oast_selfhost", "oast_generate", "oast_poll", "oast_list",
    # keyless OSINT (queries a third party, never the target)
    "web_search", "web_read", "document_metadata_osint", "search_dorks", "cve_lookup", "cve_search",
    "dependency_confusion",
    "host_intel", "ip_intel", "reverse_ip", "cloud_buckets", "jwt_analyze", "jwt_crack",
    "jwt_alg_confusion", "deserialize_fingerprint", "js_library_scan",
    # interception history (reads the in-memory log; no traffic)
    "http_history",
    # shared memory hub (local store; no traffic)
    "memory_add", "memory_search", "memory_get", "memory_stats",
    "memory_link", "memory_graph", "memory_brief", "memory_lesson", "plan_target",
    # findings / reporting / monitoring
    "add_finding", "promote_lead", "label_finding", "metrics",
    "list_findings", "clear_findings", "triage_findings", "cvss_score",
    "audit_log",
    "export_obsidian", "surface_diff", "export_findings",
    # offline knowledge bases
    "injection_info", "match_injection_signatures",
    "technique_info",
    "privesc_info", "privesc_tools", "match_privesc",
    "vuln_info", "rootcause_info", "vuln_tools",
    "waf_info", "identify_waf",
    # external-tool inventory + nuclei coverage map (no traffic; run_scanner/vuln_scan do the work)
    "external_tools", "scan_coverage",
}


def _tools():
    # The internal tool manager exposes the wrapped callable as `.fn`, which
    # carries the @active_tool markers (the async mcp.list_tools() returns only
    # the wire schema).
    return {t.name: t.fn for t in srv.mcp._tool_manager.list_tools()}


def test_every_packet_tool_is_scope_gated():
    ungated = [
        name for name, fn in _tools().items()
        if not getattr(fn, "__moonmcp_gated__", False) and name not in PASSIVE
    ]
    assert not ungated, f"tools that send traffic without @active_tool: {sorted(ungated)}"


def test_passive_allowlist_is_current():
    tools = _tools()
    stale = sorted(PASSIVE - set(tools))
    assert not stale, f"PASSIVE lists tools that no longer exist: {stale}"
    # A passive tool must not also carry the gate marker (that would be a lie).
    contradictory = [n for n in PASSIVE if getattr(tools[n], "__moonmcp_gated__", False)]
    assert not contradictory, f"passive tools wrongly marked gated: {contradictory}"


def test_known_packet_tools_are_gated():
    tools = _tools()
    for name in ("http_probe", "tls_inspect", "dns_lookup", "port_scan",
                 "content_discovery", "vuln_scan", "probe_batch", "run_scanner",
                 "recon_target", "email_security"):
        assert getattr(tools[name], "__moonmcp_gated__", False), f"{name} is not gated"


def test_intrusive_tools_carry_intrusive_marker():
    tools = _tools()
    for name in ("port_scan", "content_discovery", "http_methods", "waf_efficacy",
                 "desync_probe", "vuln_scan"):
        assert getattr(tools[name], "__moonmcp_intrusive__", False), f"{name} not intrusive"
