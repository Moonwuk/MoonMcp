"""Scope-coverage guard.

Every packet-sending tool must pass MoonMCP's single scope choke point — the
``@active_tool`` decorator. This test enumerates every registered tool and fails
loudly if one sends traffic without the gate (or if the passive allowlist drifts
out of date), so an un-gated capability can never ship by accident.
"""

import ast
import inspect
import textwrap

import pytest

from moonmcp import server as srv

# Tools that legitimately need NO scope gate: server meta, scope/program/auth/
# oast management, keyless OSINT that never touches the *target*, the offline
# knowledge bases, and the reporting/findings helpers. Everything else must be
# an @active_tool. Adding a new tool here is a deliberate, reviewed decision.
PASSIVE = {
    # meta / management
    "server_status", "tool_catalog",
    "scope_list", "scope_add", "scope_exclude", "scope_remove",
    "program_add", "program_use", "program_list", "program_remove",
    "auth_set", "auth_clear",
    "oast_configure", "oast_selfhost", "oast_generate", "oast_poll", "oast_list",
    # keyless OSINT (queries a third party, never the target)
    "web_search", "web_read", "search_dorks", "cve_lookup", "cve_search",
    "dependency_confusion",
    "host_intel", "ip_intel", "reverse_ip", "cloud_buckets", "jwt_analyze", "jwt_crack",
    "jwt_alg_confusion", "deserialize_fingerprint", "js_library_scan",
    # interception history (reads the in-memory log; no traffic)
    "http_history",
    # shared memory hub (local store; no traffic)
    "memory_add", "memory_search", "memory_get", "memory_stats",
    "memory_link", "memory_graph", "memory_brief", "memory_lesson",
    # findings / reporting / monitoring
    "add_finding", "promote_lead", "label_finding", "metrics",
    "list_findings", "clear_findings", "triage_findings", "cvss_score",
    "audit_log",
    "export_obsidian", "surface_diff", "surface_snapshots", "export_findings",
    # offline knowledge bases
    "injection_info", "injection_search", "match_injection_signatures",
    "technique_info", "technique_search",
    "privesc_info", "privesc_search", "privesc_tools", "match_privesc",
    "vuln_info", "vuln_search", "rootcause_info", "vuln_tools",
    "waf_info", "identify_waf",
    # external-tool inventory + nuclei coverage map (no traffic; run_scanner/vuln_scan do the work)
    "external_tools", "scan_coverage",
    # AI zero-day hunting — query NVD / pure reference mapping, never touch the target
    "cve_patch_diff", "variant_search", "version_vuln_check",
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


# --- self_scoped tools: the decorator does NOT gate them, so the marker proves
#     nothing — the BODY must call _require_scope. The declarative test above cannot
#     catch a self_scoped body that drops the call, so guard it two ways: statically
#     (every body references _require_scope) and behaviourally (a real out-of-scope
#     call is refused). -------------------------------------------------------------

def _self_scoped():
    return {n: fn for n, fn in _tools().items()
            if getattr(fn, "__moonmcp_self_scoped__", False)}


def _calls_require_scope(fn) -> bool:
    """True if the tool's own body contains a call to _require_scope (AST, so a bare
    mention in a comment/string doesn't count)."""

    src = textwrap.dedent(inspect.getsource(inspect.unwrap(fn)))
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                and node.func.id == "_require_scope":
            return True
    return False


def test_self_scoped_bodies_actually_call_require_scope():
    # A future refactor that removes the hand-rolled _require_scope from a
    # self_scoped body would keep the __moonmcp_gated__ marker (it's set
    # unconditionally) and pass every marker-based test — but ship un-gated traffic.
    # This static check fails instead.
    ss = _self_scoped()
    assert ss, "expected some self_scoped tools to exist"
    missing = sorted(n for n, fn in ss.items() if not _calls_require_scope(fn))
    assert not missing, f"self_scoped tools whose body never calls _require_scope: {missing}"


@pytest.mark.asyncio
@pytest.mark.parametrize("tool,kwargs", [
    ("parse_openapi", {"target": "http://evil.example.test/openapi.json"}),
    ("analyze_config", {"target": "http://evil.example.test/.env"}),
    ("firebase_exposure", {"target": "http://evil.example.test/"}),
    ("supabase_exposure", {"target": "http://evil.example.test/"}),
    ("confirm_finding", {"target": "http://evil.example.test/", "payload": "x", "param": "q"}),
    ("http_repeater", {"url": "http://evil.example.test/"}),
])
async def test_self_scoped_tool_refuses_out_of_scope(tool, kwargs, fresh_context):
    # fresh_context authorises only 127.0.0.1, so evil.example.test is out of scope.
    res = await getattr(srv, tool)(**kwargs)
    assert res.get("error") == "out_of_scope", (tool, res)


@pytest.mark.asyncio
async def test_second_order_probe_refuses_out_of_scope(fresh_context):
    res = await srv.second_order_sqli_probe(
        write={"url": "http://evil.example.test/w"},
        read="http://evil.example.test/r", param="q")
    assert res.get("error") == "out_of_scope", res
