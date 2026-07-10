"""The nuclei bridge — use nuclei for what it is best at, and *steer to what it cannot do*.

nuclei is a stateless, per-template request→matcher engine. On a real bug-bounty
target it is table stakes: everyone mass-scans with it, so the bugs it *can* find are
already reported and duped. The leverage is therefore twofold:

1. **Delegate** the commodity detection nuclei owns (version→CVE, static exposures,
   takeovers, tech fingerprints, DAST fuzzing of reflected params) instead of
   re-implementing it in Python — nuclei's community template library will always win.
2. **Steer to MoonMCP's native edge** — the *stateful / differential / timing /
   business-logic* probes nuclei structurally can't express in a template. Those fire
   on targets already scanned to death by nuclei, so their marginal hit-rate is higher.

This module is the single source of truth for that split (``coverage_report``), the
intent→template-tag selector (``intent_to_tags`` / ``build_args``), and the nuclei
JSONL normaliser (``normalize_finding``). It is pure/offline; the server tools drive it.
"""

from __future__ import annotations

# ── The coverage map (the honest nuclei-vs-us verdict, made executable) ─────────

# MoonMCP capabilities nuclei covers as well or better — prefer nuclei, don't invest
# native effort here. native_tool -> where nuclei covers it.
NUCLEI_DELEGATE: dict[str, str] = {
    "cve_lookup": "nuclei cves/ — thousands of community version→CVE templates",
    "cve_search": "nuclei cves/ + tags",
    "vcs_exposure": "nuclei http/exposures/ (.git/.svn/.env/.hg)",
    "debug_exposure": "nuclei http/exposures/ + misconfiguration/ (ignition/actuator/profiler/adminer…)",
    "extract_secrets": "nuclei exposures/tokens/ (also trufflehog/gitleaks)",
    "takeover_check": "nuclei http/takeovers/ (large fingerprint set; also subzy/subjack)",
    "fingerprint": "nuclei http/technologies/ (also wappalyzer/whatweb)",
    "favicon_hash": "nuclei favicon/ + shodan/fofa",
    "waf_detect": "wafw00f + nuclei technologies/waf",
    "well_known": "nuclei misconfiguration/",
    "content_discovery": "ffuf/feroxbuster + nuclei fuzzing/",
    "port_scan": "naabu/nmap",
    "open_redirect": "nuclei -dast fuzzing (reflected-param redirect)",
    "crlf_probe": "nuclei -dast fuzzing (crlf) — but our differential twin-set is a useful cross-check",
    "ssti_probe": "nuclei -dast fuzzing (ssti, OAST-backed)",
    "sqli_probe": "nuclei -dast fuzzing (sqli) — deep SQLi still needs sqlmap",
}

# MoonMCP capabilities nuclei STRUCTURALLY cannot (or only clumsily) express — these
# are the higher-hit-rate probes to keep and sharpen. native_tool -> why nuclei can't.
NATIVE_EDGE: dict[str, str] = {
    "access_control_check": "compares TWO authenticated identities against the same object "
                            "(IDOR/BOLA) — nuclei is single-template, no cross-identity diff",
    "logic_probe": "business-logic param tampering + mass-assignment; depends on app intent, "
                   "not a static signature",
    "race_probe": "single-packet / N-parallel race; not expressible as a per-request template",
    "desync_probe": "CL.TE / obfuscated-TE framing indicators on RAW sockets",
    "desync_modern_probe": "0.CL/TE.0/Expect/chunk-ext via response-timeout deltas on raw sockets — "
                           "nuclei's HTTP client normalises framing, so it cannot send these",
    "path_bypass_probe": "401/403→2xx path-normalization flip; needs a confirmed-protected baseline "
                         "then a per-twin differential",
    "cache_deception_probe": "authed-vs-anon body + cache-HIT differential; needs a session and a "
                             "two-state comparison",
    "response_leak_probe": "drives the OTP/reset/verify flow and detects the out-of-band secret "
                           "returned in-band — flow-stateful",
    "reset_poison_probe": "Host/X-Forwarded-Host reset poisoning; reflected-host differential across "
                          "the reset flow",
    "ssrf_metadata_probe": "multi-cloud metadata response-diff for credential signatures (nuclei has "
                           "ssrf+interactsh, but not this targeted response correlation)",
    "confirm_finding": "differential confirmation engine (baseline vs payload similarity)",
    "surface_diff": "cross-run attack-surface diff over time — stateful across snapshots",
    "origin_discovery": "behavioural: infer origin behind a CDN from response variance",
    "edge_map": "behavioural: map the CDN/edge from response variance across a request series",
    "backend_probe": "behavioural: infer backend fleet / patch-drift from response variance",
    "tls_behavior": "behavioural TLS variance analysis",
    "http_behavior": "behavioural HTTP variance analysis",
    "vhost_probe": "Host-header routing inference",
    "ratelimit_probe": "rate-limit behaviour inference over a request series",
    "oauth_probe": "OIDC metadata policy logic (implicit grant / weak-PKCE / none+HS256 / "
                   "issuer↔jwks mix) — partially templatable but reasoned better natively",
    "config_audit": "classifies a leaked signing secret → framework → forge-to-RCE primitive "
                    "(nuclei can detect the leak, not classify the chain)",
    "business_logic_hunt": "an LLM methodology prompt, not a scanner",
}


def coverage_report() -> dict:
    """The delegate-to-nuclei vs native-edge split — the executable form of the
    'what's in nuclei / what's only in us' answer."""

    return {
        "premise": ("nuclei is a stateless per-template matcher; because everyone mass-scans with "
                    "it, nuclei-detectable bugs are largely already reported. MoonMCP's leverage is "
                    "to DELEGATE the commodity detection to nuclei and spend its effort on the "
                    "stateful/differential/timing/logic probes nuclei structurally cannot express — "
                    "those have a higher marginal hit-rate on already-scanned targets."),
        "delegate_to_nuclei": [{"tool": k, "covered_by": v} for k, v in NUCLEI_DELEGATE.items()],
        "native_edge": [{"tool": k, "why_nuclei_cannot": v} for k, v in NATIVE_EDGE.items()],
        "architecture_edge": [
            "single scope-gating choke-point (allow/deny + resolve-then-check SSRF guard + "
            "intrusive gate + audit) for an AUTONOMOUS agent — nuclei has no scope model",
            "shared cross-agent memory hub (SQLite + FTS + provenance)",
            "offline knowledge bases (injection/technique/privesc/root-cause/WAF)",
            "orchestration of the Strix autonomous pentest agent under human confirmation",
        ],
        "recommendation": ("Run nuclei (via vuln_scan) for the commodity pass, then ALWAYS run the "
                           "native-edge probes — that is where bugs survive the nuclei crowd."),
    }


def also_run_native() -> list[str]:
    """The native-edge probes an agent should run *in addition to* a nuclei scan."""

    return list(NATIVE_EDGE)


# ── Template-tag selection (intent → nuclei flags) ──────────────────────────────

# Plain intent → nuclei -tags value(s). Keeps agents from guessing template paths.
_INTENT_TAGS: dict[str, str] = {
    "cve": "cve", "cves": "cve",
    "exposure": "exposure", "exposures": "exposure", "disclosure": "exposure",
    "misconfig": "misconfig", "misconfiguration": "misconfig",
    "takeover": "takeover", "takeovers": "takeover",
    "default-login": "default-login", "default-logins": "default-login", "login": "default-login",
    "panel": "panel", "panels": "panel",
    "tech": "tech", "fingerprint": "tech", "technology": "tech",
    "lfi": "lfi", "rce": "rce", "sqli": "sqli", "xss": "xss", "ssrf": "ssrf",
    "redirect": "redirect", "traversal": "lfi", "injection": "injection",
    "auth-bypass": "auth-bypass", "misconfigured": "misconfig",
}


def intent_to_tags(intent: str) -> list[str]:
    """Map a comma/space-separated plain intent string to nuclei tag values."""

    out: list[str] = []
    for token in str(intent or "").replace(",", " ").split():
        tag = _INTENT_TAGS.get(token.strip().lower())
        if tag and tag not in out:
            out.append(tag)
    return out


def build_args(url: str, *, tags: str | None = None, templates: str | None = None,
               severity: str | None = None, dast: bool = False) -> list[str]:
    """Assemble the nuclei argv (JSONL, silent, update-check off)."""

    args = ["-u", url, "-jsonl", "-silent", "-duc"]
    tag_values = intent_to_tags(tags) if tags else []
    if tag_values:
        args += ["-tags", ",".join(tag_values)]
    if templates:
        args += ["-t", templates]
    if severity:
        args += ["-severity", severity]
    if dast:
        args += ["-dast"]
    return args


# ── Finding normalisation (nuclei JSONL row → MoonMCP shape) ────────────────────

def normalize_finding(row: dict) -> dict:
    """Flatten one nuclei JSONL result into a stable, compact finding shape."""

    info = row.get("info") or {}
    return {
        "template_id": row.get("template-id") or row.get("templateID") or "",
        "name": info.get("name") or row.get("template-id") or "nuclei finding",
        "severity": str(info.get("severity") or "info").lower(),
        "type": row.get("type") or "http",
        "matched_at": row.get("matched-at") or row.get("matched_at") or row.get("host") or "",
        "tags": info.get("tags") or [],
        "description": (info.get("description") or "").strip()[:400],
        "reference": info.get("reference") or [],
    }
