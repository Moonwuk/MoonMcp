"""Canonical tool policies, independent of the MCP SDK and live server.

Declare navigation and execution metadata once per tool. Schemas and scope /
intrusive markers are always obtained from the actual registered callable.
Unknown tools default to unmetered; family membership never grants execution.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal


@dataclass(frozen=True)
class ToolPolicy:
    name: str
    family: str
    aliases: str = ""
    read_only: bool = False
    accounting: Literal["local", "http_client", "unmetered"] = "unmetered"
    static_reference: bool = False
    public_research: bool = False
    compact: bool = False
    orientation: bool = False
    browser: bool = False
    knowledge_paths: tuple[str, ...] = ()
    selected_resource: bool = False
    external_cli: str = ""
    execution_control: bool = False


FAMILY_INFO = {
    "setup": (
        "Setup & safety",
        "Authorise and identify before touching anything: scope, per-program header, engagement auth, out-of-band callbacks, audit trail.",
    ),
    "passive_osint": (
        "Passive OSINT",
        "Queries third-party datasets / search engines about the target — no packets to the target itself.",
    ),
    "light_active": (
        "Light active",
        "Benign, low-noise in-scope requests: probe, fingerprint, crawl, and analyse the web-app surface (incl. a headless browser).",
    ),
    "intrusive": (
        "Intrusive (gated)",
        "Noisier scanning that must be explicitly enabled with MOONMCP_ALLOW_INTRUSIVE — get consent first.",
    ),
    "orchestration": (
        "Orchestration",
        "Create resumable assessment runs, coordinate role-based tasks, enforce budgets and coverage gates, then chain the safe recon/report tools.",
    ),
    "infra": (
        "Behavioural infrastructure",
        "Infer the infra's shape from response variance: backend fleet / patch drift, DNS/zone behaviour (wildcard, LB, dangling CNAME), Host-header routing, and rate-limit behaviour.",
    ),
    "intercept": (
        "Interception & active probes",
        "Drive the Burp workflow from tools (repeater, intruder, passive scan, history), plus differential detectors for top-payout classes (SSTI, SQLi, blind SSRF, cache poisoning) and the confirm_finding gate.",
    ),
    "knowledge": (
        "Knowledge bases",
        "Offline reference: injections, techniques/PoCs, privilege escalation, server-side vulns + root causes, WAF fingerprints. No traffic.",
    ),
    "reporting": (
        "Findings & reporting",
        "Record findings, export (SARIF/JSON/Obsidian), and diff the attack surface across runs.",
    ),
    "memory": (
        "Shared memory hub",
        "Persistent, cross-agent, provenance/trust-tagged memory (SQLite + FTS) so agents build on each other's work instead of re-deriving context. A typed knowledge graph (entities + relations) structures findings, and cross-target lessons carry tradecraft forward between sessions.",
    ),
    "external": (
        "External CLIs",
        "Detect and safely drive installed security CLIs (scope-checked, file-I/O flags refused). Gated by MOONMCP_ALLOW_EXTERNAL_TOOLS.",
    ),
    "pipeline": (
        "Hermes pipeline (absorbed)",
        "The retired Node server's local data tools, now served natively: engagement queue, targets.yaml scope/config, HackerOne report calibration, knowledge-base grep, airecon FTS5 datasets, nuclei CVE index, web-security catalog, takeover fingerprints.",
    ),
}

_DECLARATIONS = (
    # setup
    ToolPolicy(
        "server_status",
        "setup",
        aliases="capabilities dependencies configuration status",
        read_only=True,
        accounting="local",
        compact=True,
        orientation=True,
    ),
    ToolPolicy("tool_catalog", "setup", read_only=True, accounting="local", orientation=True),
    ToolPolicy(
        "tool_search",
        "setup",
        aliases="discover search tools task capabilities",
        read_only=True,
        accounting="local",
        compact=True,
        orientation=True,
    ),
    ToolPolicy(
        "tool_describe",
        "setup",
        aliases="tool schema arguments prerequisites describe",
        read_only=True,
        accounting="local",
        compact=True,
        orientation=True,
    ),
    ToolPolicy(
        "scope_list",
        "setup",
        aliases="scope check view list authorized targets boundaries",
        read_only=True,
        accounting="local",
        compact=True,
        orientation=True,
    ),
    ToolPolicy(
        "scope_add",
        "setup",
        aliases="scope add authorize target",
        compact=True,
        execution_control=True,
    ),
    ToolPolicy("scope_exclude", "setup", aliases="scope exclude deny target", compact=True),
    ToolPolicy(
        "scope_remove",
        "setup",
        aliases="scope remove revoke target",
        compact=True,
        execution_control=True,
    ),
    ToolPolicy("program_add", "setup", execution_control=True),
    ToolPolicy("program_use", "setup", compact=True, execution_control=True),
    ToolPolicy("program_list", "setup", read_only=True, accounting="local"),
    ToolPolicy("program_remove", "setup", execution_control=True),
    ToolPolicy("auth_set", "setup", compact=True, execution_control=True),
    ToolPolicy("auth_clear", "setup", compact=True, execution_control=True),
    ToolPolicy("oast_configure", "setup"),
    ToolPolicy("oast_selfhost", "setup"),
    ToolPolicy("oast_generate", "setup"),
    ToolPolicy("oast_poll", "setup"),
    ToolPolicy("oast_list", "setup", accounting="local"),
    ToolPolicy("oast_payload_gen", "setup", accounting="local"),
    ToolPolicy("oast_techniques", "setup", accounting="local"),
    ToolPolicy("proxy_rules", "setup", execution_control=True),
    ToolPolicy("telemetry", "setup", read_only=True, accounting="local"),
    ToolPolicy("view_dashboard", "setup"),
    ToolPolicy("sast_scan", "setup"),
    ToolPolicy("generate_remediation", "setup"),
    ToolPolicy("opsec_config", "setup"),
    ToolPolicy("extract_api_schemas", "setup"),
    ToolPolicy("audit_log", "setup", read_only=True, accounting="local"),
    # passive_osint
    ToolPolicy("web_search", "passive_osint", accounting="http_client", public_research=True),
    ToolPolicy("web_read", "passive_osint", accounting="http_client", public_research=True),
    ToolPolicy("search_dorks", "passive_osint", accounting="local"),
    ToolPolicy(
        "enumerate_subdomains", "passive_osint", accounting="http_client", public_research=True
    ),
    ToolPolicy("wayback_urls", "passive_osint", accounting="http_client", public_research=True),
    ToolPolicy("cve_lookup", "passive_osint", accounting="http_client", public_research=True),
    ToolPolicy("cve_search", "passive_osint", accounting="http_client", public_research=True),
    ToolPolicy("cve_patch_diff", "passive_osint"),
    ToolPolicy("variant_search", "passive_osint"),
    ToolPolicy("version_vuln_check", "passive_osint"),
    ToolPolicy("host_intel", "passive_osint"),
    ToolPolicy("ip_intel", "passive_osint"),
    ToolPolicy("reverse_ip", "passive_osint"),
    ToolPolicy("cloud_audit", "passive_osint"),
    ToolPolicy("cloud_buckets", "passive_osint"),
    ToolPolicy("email_security", "passive_osint"),
    ToolPolicy("dependency_confusion", "passive_osint"),
    # light_active
    ToolPolicy("dns_lookup", "light_active"),
    ToolPolicy("http_probe", "light_active", accounting="http_client"),
    ToolPolicy("tls_inspect", "light_active"),
    ToolPolicy("analyze_headers", "light_active", accounting="http_client"),
    ToolPolicy("fingerprint", "light_active"),
    ToolPolicy("well_known", "light_active", accounting="http_client"),
    ToolPolicy("favicon_hash", "light_active"),
    ToolPolicy("tls_fingerprint", "light_active"),
    ToolPolicy("jarm_fingerprint", "light_active"),
    ToolPolicy("origin_discovery", "light_active"),
    ToolPolicy("behavior_probe", "light_active"),
    ToolPolicy("crawl", "light_active", accounting="http_client"),
    ToolPolicy("analyze_js", "light_active", accounting="http_client"),
    ToolPolicy("js_library_scan", "light_active"),
    ToolPolicy("recover_sourcemaps", "light_active"),
    ToolPolicy("parse_openapi", "light_active", accounting="http_client"),
    ToolPolicy("extract_secrets", "light_active"),
    ToolPolicy("firebase_exposure", "light_active"),
    ToolPolicy("supabase_exposure", "light_active"),
    ToolPolicy("cors_audit", "light_active", accounting="http_client"),
    ToolPolicy(
        "access_control_check",
        "light_active",
        aliases="authentication authorization access control idor role comparison",
        accounting="http_client",
    ),
    ToolPolicy(
        "authz_probe",
        "light_active",
        aliases="authentication authorization access control idor bola role comparison",
        accounting="http_client",
    ),
    ToolPolicy("graphql_check", "light_active", accounting="http_client"),
    ToolPolicy("graphql_probe", "light_active", accounting="http_client"),
    ToolPolicy("ws_probe", "light_active"),
    ToolPolicy("discover_parameters", "light_active", accounting="http_client"),
    ToolPolicy("waf_detect", "light_active", accounting="http_client"),
    ToolPolicy("takeover_check", "light_active"),
    ToolPolicy("open_redirect", "light_active"),
    ToolPolicy("trace_redirects", "light_active", accounting="http_client"),
    ToolPolicy("crlf_probe", "light_active"),
    ToolPolicy("vcs_exposure", "light_active"),
    ToolPolicy("git_forensics", "light_active"),
    ToolPolicy("response_leak_probe", "light_active"),
    ToolPolicy("reset_poison_probe", "light_active"),
    ToolPolicy("path_bypass_probe", "light_active"),
    ToolPolicy("debug_exposure", "light_active"),
    ToolPolicy(
        "screenshot",
        "light_active",
        aliases="browser screenshot image playwright chromium",
        browser=True,
    ),
    ToolPolicy(
        "browser_open",
        "light_active",
        aliases="browser rendered page playwright chromium",
        browser=True,
    ),
    ToolPolicy("browser_eval", "light_active", browser=True),
    ToolPolicy("browser_interact", "light_active", browser=True),
    ToolPolicy("cspp_probe", "light_active", browser=True),
    ToolPolicy("analyze_binary", "light_active"),
    ToolPolicy("analyze_config", "light_active"),
    ToolPolicy("jwt_analyze", "light_active"),
    ToolPolicy("jwt_crack", "light_active"),
    ToolPolicy("jwt_alg_confusion", "light_active"),
    ToolPolicy("deserialize_fingerprint", "light_active"),
    ToolPolicy("oauth_probe", "light_active"),
    ToolPolicy("oauth_redirect_probe", "light_active"),
    # intrusive
    ToolPolicy("port_scan", "intrusive"),
    ToolPolicy("content_discovery", "intrusive", accounting="http_client"),
    ToolPolicy("http_methods", "intrusive", accounting="http_client"),
    ToolPolicy("waf_efficacy", "intrusive", accounting="http_client"),
    ToolPolicy("desync_probe", "intrusive"),
    ToolPolicy("desync_modern_probe", "intrusive"),
    ToolPolicy("vuln_scan", "intrusive", external_cli="nuclei"),
    ToolPolicy("cache_deception_probe", "intrusive"),
    ToolPolicy("stack_probe", "intrusive"),
    ToolPolicy("ssrf_metadata_probe", "intrusive"),
    ToolPolicy("logic_probe", "intrusive"),
    ToolPolicy("race_probe", "intrusive"),
    ToolPolicy("workflow_probe", "intrusive"),
    ToolPolicy("value_probe", "intrusive"),
    ToolPolicy("jwt_jku_probe", "intrusive"),
    ToolPolicy("nosqli_probe", "intrusive"),
    ToolPolicy("db_exposure", "intrusive"),
    ToolPolicy("second_order_sqli_probe", "intrusive"),
    ToolPolicy("orm_leak_probe", "intrusive"),
    ToolPolicy("fastjson_oast_probe", "intrusive"),
    ToolPolicy("ssrf_protocol_probe", "intrusive"),
    ToolPolicy("parser_diff_probe", "intrusive"),
    ToolPolicy("graphql_nosqli", "intrusive"),
    # orchestration
    ToolPolicy(
        "run_start",
        "orchestration",
        aliases="run create start budget limits assessment",
        compact=True,
        execution_control=True,
    ),
    ToolPolicy(
        "run_status",
        "orchestration",
        aliases="run budget remaining usage status progress",
        read_only=True,
        execution_control=True,
    ),
    ToolPolicy("run_list", "orchestration", read_only=True, compact=True, execution_control=True),
    ToolPolicy(
        "run_control",
        "orchestration",
        aliases="run pause resume cancel",
        compact=True,
        execution_control=True,
    ),
    ToolPolicy("run_task_add", "orchestration", compact=True, execution_control=True),
    ToolPolicy("run_task_update", "orchestration", compact=True, execution_control=True),
    ToolPolicy(
        "run_next",
        "orchestration",
        aliases="run next pending task",
        read_only=True,
        execution_control=True,
    ),
    ToolPolicy("run_coverage_update", "orchestration", compact=True, execution_control=True),
    ToolPolicy(
        "run_usage",
        "orchestration",
        aliases="run budget record spend usage accounting",
        execution_control=True,
    ),
    ToolPolicy("run_artifact_add", "orchestration", compact=True, execution_control=True),
    ToolPolicy("run_artifacts", "orchestration", read_only=True, execution_control=True),
    ToolPolicy("run_finish", "orchestration", compact=True, execution_control=True),
    ToolPolicy(
        "run_brief",
        "orchestration",
        aliases="run summary continuation resume context",
        read_only=True,
        compact=True,
        execution_control=True,
    ),
    ToolPolicy(
        "run_execute",
        "orchestration",
        aliases="run execute tool task budget",
        compact=True,
        execution_control=True,
    ),
    ToolPolicy("run_claim", "orchestration", compact=True, execution_control=True),
    ToolPolicy("run_heartbeat", "orchestration", compact=True, execution_control=True),
    ToolPolicy("run_task_retry", "orchestration", compact=True, execution_control=True),
    ToolPolicy("run_artifact_read", "orchestration", compact=True, execution_control=True),
    ToolPolicy("run_recover", "orchestration", compact=True, execution_control=True),
    ToolPolicy("run_reconcile", "orchestration", compact=True, execution_control=True),
    ToolPolicy("probe_batch", "orchestration", accounting="http_client"),
    ToolPolicy("recon_target", "orchestration"),
    ToolPolicy("report", "orchestration"),
    # infra
    ToolPolicy("backend_probe", "infra"),
    ToolPolicy("dns_behavior", "infra"),
    ToolPolicy("vhost_probe", "infra"),
    ToolPolicy("ratelimit_probe", "infra"),
    ToolPolicy("tls_behavior", "infra"),
    ToolPolicy("edge_map", "infra"),
    ToolPolicy("http_behavior", "infra"),
    ToolPolicy("timing_diff", "infra", accounting="http_client"),
    # intercept
    ToolPolicy("http_repeater", "intercept", accounting="http_client"),
    ToolPolicy("intruder", "intercept"),
    ToolPolicy("passive_scan", "intercept", accounting="http_client"),
    ToolPolicy("confirm_finding", "intercept"),
    ToolPolicy("ssti_probe", "intercept"),
    ToolPolicy("sqli_probe", "intercept", aliases="sql injection sqli differential test"),
    ToolPolicy("cmdi_probe", "intercept"),
    ToolPolicy("lfi_probe", "intercept"),
    ToolPolicy(
        "ssrf_probe", "intercept", aliases="blind ssrf callback server side request forgery"
    ),
    ToolPolicy("xxe_probe", "intercept"),
    ToolPolicy("interp_probe", "intercept"),
    ToolPolicy("saml_xsw_probe", "intercept"),
    ToolPolicy("cache_probe", "intercept"),
    ToolPolicy("http_history", "intercept", read_only=True, accounting="local"),
    # knowledge
    ToolPolicy(
        "injection_info", "knowledge", read_only=True, accounting="local", static_reference=True
    ),
    ToolPolicy(
        "injection_search", "knowledge", read_only=True, accounting="local", static_reference=True
    ),
    ToolPolicy("match_injection_signatures", "knowledge", accounting="local"),
    ToolPolicy(
        "technique_info", "knowledge", read_only=True, accounting="local", static_reference=True
    ),
    ToolPolicy(
        "technique_search", "knowledge", read_only=True, accounting="local", static_reference=True
    ),
    ToolPolicy(
        "privesc_info", "knowledge", read_only=True, accounting="local", static_reference=True
    ),
    ToolPolicy(
        "privesc_search", "knowledge", read_only=True, accounting="local", static_reference=True
    ),
    ToolPolicy(
        "privesc_tools", "knowledge", read_only=True, accounting="local", static_reference=True
    ),
    ToolPolicy("match_privesc", "knowledge", accounting="local"),
    ToolPolicy("vuln_info", "knowledge", read_only=True, accounting="local", static_reference=True),
    ToolPolicy(
        "vuln_search", "knowledge", read_only=True, accounting="local", static_reference=True
    ),
    ToolPolicy(
        "vuln_tools", "knowledge", read_only=True, accounting="local", static_reference=True
    ),
    ToolPolicy(
        "rootcause_info", "knowledge", read_only=True, accounting="local", static_reference=True
    ),
    ToolPolicy(
        "playbook_info", "knowledge", read_only=True, accounting="local", static_reference=True
    ),
    ToolPolicy("deduplicate_findings", "knowledge", read_only=True, accounting="local"),
    ToolPolicy("render_finding_md", "knowledge", read_only=True, accounting="local"),
    ToolPolicy("proxy_manage", "knowledge", execution_control=True),
    ToolPolicy("sandbox_exec", "knowledge", execution_control=True),
    ToolPolicy("research_environment", "orchestration", aliases="replay capsule sqlite docker research fixture cleanup",
               execution_control=True),
    ToolPolicy("agent_tree", "knowledge", execution_control=True),
    ToolPolicy("export_csv", "knowledge"),
    ToolPolicy("waf_info", "knowledge", read_only=True, accounting="local", static_reference=True),
    ToolPolicy("identify_waf", "knowledge", accounting="local"),
    # reporting
    ToolPolicy("add_finding", "reporting", accounting="local"),
    ToolPolicy("promote_lead", "reporting", accounting="local"),
    ToolPolicy("label_finding", "reporting", accounting="local"),
    ToolPolicy("metrics", "reporting", read_only=True, accounting="local"),
    ToolPolicy("list_findings", "reporting", read_only=True, accounting="local"),
    ToolPolicy("clear_findings", "reporting", accounting="local", execution_control=True),
    ToolPolicy("triage_findings", "reporting", accounting="local"),
    ToolPolicy("cvss_score", "reporting", read_only=True, accounting="local"),
    ToolPolicy("export_findings", "reporting", accounting="local"),
    ToolPolicy("export_obsidian", "reporting"),
    ToolPolicy("surface_diff", "reporting"),
    ToolPolicy("surface_snapshots", "reporting"),
    # memory
    ToolPolicy("memory_add", "memory", accounting="local"),
    ToolPolicy("memory_search", "memory", read_only=True, accounting="local"),
    ToolPolicy("memory_get", "memory", read_only=True, accounting="local"),
    ToolPolicy("memory_stats", "memory", read_only=True, accounting="local"),
    ToolPolicy("memory_link", "memory", accounting="local"),
    ToolPolicy("memory_graph", "memory", read_only=True, accounting="local"),
    ToolPolicy(
        "memory_brief",
        "memory",
        aliases="memory recall target summary prior observations",
        read_only=True,
        accounting="local",
    ),
    ToolPolicy("memory_lesson", "memory", accounting="local"),
    ToolPolicy("flag_record", "memory", accounting="local"),
    ToolPolicy("flag_get", "memory", read_only=True, accounting="local"),
    ToolPolicy("flag_search", "memory", read_only=True, accounting="local"),
    ToolPolicy("flag_update", "memory", accounting="local"),
    ToolPolicy("flag_link", "memory", accounting="local"),
    ToolPolicy("hypothesis_record", "memory", accounting="local"),
    ToolPolicy("hypothesis_get", "memory", read_only=True, accounting="local"),
    ToolPolicy("hypothesis_update", "memory", accounting="local"),
    ToolPolicy("analysis_brief", "memory", accounting="local"),
    # external
    ToolPolicy("external_tools", "external", read_only=True, accounting="local"),
    ToolPolicy("run_scanner", "external", external_cli="selected", execution_control=True),
    ToolPolicy("scan_coverage", "external", read_only=True),
    # pipeline
    ToolPolicy("queue_task", "pipeline"),
    ToolPolicy("list_queue", "pipeline", read_only=True),
    ToolPolicy(
        "get_target",
        "pipeline",
        read_only=True,
        knowledge_paths=("targets.yaml",),
        selected_resource=True,
    ),
    ToolPolicy("list_targets", "pipeline", read_only=True, knowledge_paths=("targets.yaml",)),
    ToolPolicy(
        "search_bugbounty_reports",
        "pipeline",
        read_only=True,
        knowledge_paths=("knowledge_base", "hackerone_reports", "tops_by_bug_type"),
        selected_resource=True,
    ),
    ToolPolicy("list_report_categories", "pipeline", read_only=True),
    ToolPolicy(
        "search_knowledge_base",
        "pipeline",
        read_only=True,
        knowledge_paths=("knowledge_base",),
        selected_resource=True,
    ),
    ToolPolicy(
        "search_datasets",
        "pipeline",
        read_only=True,
        knowledge_paths=("knowledge_base", "airecon_datasets"),
        selected_resource=True,
    ),
    ToolPolicy(
        "match_signature_to_cve",
        "pipeline",
        read_only=True,
        knowledge_paths=("knowledge_base", "nuclei_index.sqlite3"),
    ),
    ToolPolicy(
        "get_nuclei_template",
        "pipeline",
        read_only=True,
        knowledge_paths=("knowledge_base", "nuclei_index.sqlite3"),
    ),
    ToolPolicy(
        "search_web_security_resources",
        "pipeline",
        read_only=True,
        knowledge_paths=("knowledge_base", "web_security_index", "index.json"),
    ),
    ToolPolicy(
        "list_web_security_categories",
        "pipeline",
        read_only=True,
        knowledge_paths=("knowledge_base", "web_security_index", "index.json"),
    ),
    ToolPolicy(
        "check_subdomain_takeover",
        "pipeline",
        read_only=True,
        knowledge_paths=("knowledge_base", "subdomain_takeover", "fingerprints.json"),
    ),
)


def _build() -> dict[str, ToolPolicy]:
    policies: dict[str, ToolPolicy] = {}
    for item in _DECLARATIONS:
        if item.name in policies:
            raise ValueError(f"duplicate tool policy: {item.name}")
        if item.family not in FAMILY_INFO:
            raise ValueError(f"unknown tool family: {item.family}")
        if item.static_reference and (item.accounting != "local" or not item.read_only):
            raise ValueError(f"static reference must be a local read: {item.name}")
        if item.public_research and item.accounting != "http_client":
            raise ValueError(f"public research requires reviewed HTTP accounting: {item.name}")
        policies[item.name] = item
    return policies


POLICIES = MappingProxyType(_build())
FAMILIES = OrderedDict(
    (family, (title, blurb, [p.name for p in POLICIES.values() if p.family == family]))
    for family, (title, blurb) in FAMILY_INFO.items()
)
TOOL_FAMILY = MappingProxyType({p.name: p.family for p in POLICIES.values()})
COMPACT_TOOLS = frozenset(p.name for p in POLICIES.values() if p.compact)
ORIENTATION_TOOLS = frozenset(p.name for p in POLICIES.values() if p.orientation)


def policy(name: str) -> ToolPolicy:
    """An unreviewed tool cannot acquire budget/accounting privileges by its name."""
    return POLICIES.get(name, ToolPolicy(name, "uncategorized"))


def request_accounting(name: str) -> str:
    return policy(name).accounting
