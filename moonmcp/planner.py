"""Rank the next probes worth running against a target from what's already known.

`plan_target` codifies the idea-gen skill's attack-vector brainstorming as a tool
any agent can call *without* the skill loaded. It reads the knowledge graph (what
tech / endpoints / params have been discovered) and the findings store (what's
already confirmed or tried), cross-references against a signal→probe map, and
returns a ranked, non-redundant list of next actions — each naming the concrete
MoonMCP tool to run and the recon signal that motivated it.

This is the inverse of `leadpipe.py`: leadpipe routes an *already-found* lead to
its confirmation path; this points at which probe to run *next* given the recon
signal. Pure/offline — the server tool gathers entities + findings and passes
them in.
"""

from __future__ import annotations

# (needle, tools, why): when a technology/service/asset/cve entity's name contains
# <needle> (case-insensitive), suggest <tools> with rationale <why>.
_TECH_SIGNALS: list[tuple[str, tuple[str, ...], str]] = [
    ("graphql", ("graphql_check", "graphql_probe", "graphql_nosqli"), "GraphQL surface present"),
    ("graphiql", ("graphql_check", "graphql_probe"), "GraphiQL — introspection likely open"),
    ("jwt", ("jwt_analyze", "jwt_alg_confusion", "jwt_jku_probe"), "JWT / signed-token auth seen"),
    ("saml", ("saml_xsw_probe",), "SAML SSO — test signature wrapping"),
    ("websocket", ("ws_probe",), "WebSocket endpoint — CSWSH / foreign-Origin check"),
    ("aws", ("ssrf_metadata_probe", "cloud_buckets"), "AWS-hosted — IMDS + S3 exposure"),
    ("amazon", ("ssrf_metadata_probe", "cloud_buckets"), "AWS-hosted — IMDS + S3 exposure"),
    ("s3", ("cloud_buckets",), "S3 storage referenced"),
    ("gcp", ("ssrf_metadata_probe",), "GCP-hosted — metadata SSRF"),
    ("google cloud", ("ssrf_metadata_probe",), "GCP-hosted — metadata SSRF"),
    ("azure", ("ssrf_metadata_probe",), "Azure-hosted — metadata SSRF"),
    ("firebase", ("firebase_exposure",), "Firebase backend — rules exposure"),
    ("supabase", ("supabase_exposure",), "Supabase backend — RLS exposure"),
    ("mongo", ("nosqli_probe", "db_exposure"), "MongoDB — operator injection"),
    ("redis", ("db_exposure",), "Redis — unauth datastore sweep"),
    ("elastic", ("db_exposure",), "Elasticsearch — unauth datastore sweep"),
    ("wordpress", ("cve_search", "lfi_probe"), "WordPress — version CVEs + LFI"),
    ("php", ("lfi_probe", "cmdi_probe"), "PHP stack — file/exec sinks"),
    ("java", ("deserialize_fingerprint", "fastjson_oast_probe"), "Java stack — deserialization"),
    (".net", ("deserialize_fingerprint",), ".NET stack — ViewState/deserialization"),
    ("express", ("nosqli_probe",), "Express — Mongo operator injection"),
    ("nginx", ("desync_probe", "cache_deception_probe"), "nginx front — desync / cache deception"),
    ("cloudflare", ("cache_deception_probe",), "CDN in front — cache deception"),
    ("soap", ("xxe_probe",), "SOAP/XML — XXE"),
    ("swagger", ("parse_openapi", "discover_parameters"), "OpenAPI spec — enumerate endpoints/params"),
    ("openapi", ("parse_openapi", "discover_parameters"), "OpenAPI spec — enumerate endpoints/params"),
]

# When a param/endpoint surface exists, the differential injection battery applies.
_INJECTION_BATTERY: tuple[tuple[str, str], ...] = (
    ("interp_probe", "unclear param behaviour — meta-probe first to pick the class"),
    ("sqli_probe", "param may reach a query sink"),
    ("ssti_probe", "param may reach a template engine"),
    ("cmdi_probe", "param may reach a shell/exec sink"),
    ("lfi_probe", "param may reach a file path"),
    ("xxe_probe", "endpoint may parse an XML/JSON body"),
    ("authz_probe", "object referenced by id — IDOR/BOLA"),
)

# First-contact recon when little is known yet.
_BASELINE: tuple[tuple[str, str], ...] = (
    ("recon_target", "one-shot passive + light sweep to populate the graph"),
    ("fingerprint", "identify the tech stack — drives everything downstream"),
    ("analyze_headers", "security-header + CSP posture (cheap wins)"),
    ("crawl", "map endpoints and surface params / JS"),
    ("analyze_js", "extract endpoints/secrets from JS + source maps"),
)

# class keywords used to detect a finding already covers a probe's territory.
_TOOL_CLASS: dict[str, tuple[str, ...]] = {
    "sqli_probe": ("sqli", "sql inject"),
    "ssti_probe": ("ssti", "template inject"),
    "cmdi_probe": ("cmdi", "command inject"),
    "lfi_probe": ("lfi", "traversal"),
    "xxe_probe": ("xxe",),
    "graphql_probe": ("graphql",),
    "jwt_alg_confusion": ("jwt", "alg confusion"),
    "ssrf_metadata_probe": ("ssrf", "metadata"),
    "cache_deception_probe": ("cache decept",),
    "authz_probe": ("idor", "bola", "access control", "authz"),
    "nosqli_probe": ("nosql",),
    "ws_probe": ("cswsh", "websocket hijack"),
    "saml_xsw_probe": ("saml", "signature wrapping"),
}

_HIGH = {"jwt_alg_confusion", "saml_xsw_probe", "ssrf_metadata_probe", "sqli_probe",
         "cmdi_probe", "graphql_probe", "nosqli_probe", "xxe_probe"}
_MED = {"lfi_probe", "ssti_probe", "authz_probe", "cache_deception_probe",
        "fastjson_oast_probe", "deserialize_fingerprint", "ws_probe", "cloud_buckets",
        "firebase_exposure", "supabase_exposure", "db_exposure", "graphql_probe",
        "graphql_nosqli", "jwt_jku_probe"}


def _priority(tool: str) -> int:
    if tool in _HIGH:
        return 3
    if tool in _MED:
        return 2
    return 1


def plan(entities: list[dict], findings: list[dict], *, target: str) -> dict:
    """Rank next probes from known *entities* + recorded *findings* (pure).

    Each suggestion carries the tool to run, the recon signal that motivated it,
    a priority, and an ``already_evidence`` flag when a finding already covers that
    class (so it sorts down rather than being re-run blindly)."""

    kinds = [str(e.get("kind", "")).lower() for e in entities]
    kind_counts: dict[str, int] = {}
    for k in kinds:
        kind_counts[k] = kind_counts.get(k, 0) + 1

    seen_text = " ".join(
        f"{f.get('type', '')} {f.get('title', '')} {f.get('detail', '')}" for f in findings
    ).lower()

    # tool -> {tool, priority, signals:set, whys:list}
    picks: dict[str, dict] = {}

    def add(tool: str, why: str, signal: str) -> None:
        p = picks.setdefault(tool, {"tool": tool, "priority": _priority(tool),
                                    "signals": set(), "whys": []})
        p["signals"].add(signal)
        if why not in p["whys"]:
            p["whys"].append(why)

    # 1) technology/service/asset/cve name signals
    for e in entities:
        kind = str(e.get("kind", "")).lower()
        if kind not in ("technology", "service", "asset", "cve"):
            continue
        name = str(e.get("name", "")).lower()
        for needle, tools, why in _TECH_SIGNALS:
            if needle in name:
                for t in tools:
                    add(t, why, f"{kind}:{name[:40]}")

    # 2) injection battery when there's an input surface to hit
    if any(k in ("param", "endpoint") for k in kinds):
        for t, why in _INJECTION_BATTERY:
            add(t, why, "param/endpoint surface in the graph")

    # 3) baseline first-contact recon when the graph is thin or has no tech yet
    if len([e for e in entities if str(e.get("kind", "")).lower() == "technology"]) == 0 \
            or len(entities) < 3:
        for t, why in _BASELINE:
            add(t, why, "little known yet — establish the surface")

    suggestions = []
    for p in picks.values():
        keywords = _TOOL_CLASS.get(p["tool"], ())
        already = bool(keywords) and any(kw in seen_text for kw in keywords)
        suggestions.append({
            "tool": p["tool"],
            "why": "; ".join(p["whys"]),
            "signals": sorted(p["signals"]),
            "priority": p["priority"],
            "already_evidence": already,
        })

    # not-already-covered first, then by impact, then alphabetically for stability
    suggestions.sort(key=lambda s: (s["already_evidence"], -s["priority"], s["tool"]))

    note = ("plan derived from the knowledge graph + findings; run the tools top-down. "
            "Items flagged already_evidence have a related finding on file — confirm or "
            "move on rather than re-running blind.")
    if not entities:
        note = ("nothing in memory for this target yet — start with the baseline recon tools "
                "below (recon_target/fingerprint), then re-run plan_target.")

    return {
        "target": target,
        "known_entity_counts": kind_counts,
        "finding_count": len(findings),
        "suggestions": suggestions,
        "note": note,
    }
