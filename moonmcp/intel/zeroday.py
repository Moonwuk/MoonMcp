"""AI-powered zero-day hunting tools — patch-diff analysis, variant search,
and version vulnerability checking.

Inspired by the cognitive pattern demonstrated by Kimi K3, Google Big Sleep,
Anthropic Mythos, and depthfirst:

1. **cve_patch_diff** — Given a CVE, fetch the advisory + references, extract
   what the patch fixes, identify the root cause, and flag potential gaps
   (incomplete-fix detection).

2. **variant_search** — Given a vulnerability pattern (root cause or CWE),
   return matching MoonMCP probes, payload classes, and knowledge-base
   entries — the "where else does this pattern exist?" question.

3. **version_vuln_check** — Given a product name + version, search NVD for
   all CVEs affecting that product, then classify each as patched/unpatched
   relative to the target version.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..net.http import HttpClient
from . import cve as cvemod

# ---------------------------------------------------------------------------
# Root-cause → CWE → MoonMCP probe mapping
# ---------------------------------------------------------------------------

_ROOT_CAUSE_CWE_MAP: dict[str, list[str]] = {
    "code-data-confusion": ["CWE-79", "CWE-94", "CWE-1336"],
    "confused-deputy": ["CWE-352", "CWE-918", "CWE-601"],
    "parser-differential": ["CWE-20", "CWE-444", "CWE-93"],
    "broken-authorization": ["CWE-284", "CWE-285", "CWE-639", "CWE-862", "CWE-863"],
    "insecure-deserialization": ["CWE-502", "CWE-915"],
    "state-desync-race": ["CWE-362", "CWE-367", "CWE-416", "CWE-415"],
    "insecure-defaults": ["CWE-1188", "CWE-276", "CWE-732"],
    "memory-safety": ["CWE-119", "CWE-120", "CWE-125", "CWE-787", "CWE-476"],
    "crypto-misuse": ["CWE-327", "CWE-326", "CWE-347", "CWE-345"],
    "network-position-abuse": ["CWE-444", "CWE-525", "CWE-1021"],
    "supply-chain-trust": ["CWE-426", "CWE-494", "CWE-829"],
    "implicit-client-trust": ["CWE-290", "CWE-441", "CWE-601"],
    "ambient-authority": ["CWE-384", "CWE-619", "CWE-522"],
}

# CWE → MoonMCP probe mapping
_CWE_PROBE_MAP: dict[str, dict] = {
    "CWE-79": {"probe": "xss (reflection in response)", "moonmcp_tool": "confirm_finding", "injection_class": "xss"},
    "CWE-89": {"probe": "sqli_probe", "moonmcp_tool": "sqli_probe", "injection_class": "sqli"},
    "CWE-918": {"probe": "ssrf_probe", "moonmcp_tool": "ssrf_probe", "injection_class": "ssrf"},
    "CWE-22": {"probe": "lfi_probe / path traversal", "moonmcp_tool": "lfi_probe", "injection_class": "path-traversal"},
    "CWE-78": {"probe": "cmdi_probe", "moonmcp_tool": "cmdi_probe", "injection_class": "cmdi"},
    "CWE-94": {"probe": "ssti_probe / code injection", "moonmcp_tool": "ssti_probe", "injection_class": "ssti"},
    "CWE-502": {"probe": "deserialize_fingerprint + fastjson_oast_probe", "moonmcp_tool": "deserialize_fingerprint", "injection_class": "deserialization"},
    "CWE-352": {"probe": "csrf check (token validation)", "moonmcp_tool": "confirm_finding", "injection_class": "csrf"},
    "CWE-639": {"probe": "authz_probe / access_control_check", "moonmcp_tool": "authz_probe", "injection_class": "idor"},
    "CWE-862": {"probe": "authz_probe / access_control_check", "moonmcp_tool": "access_control_check", "injection_class": "authz"},
    "CWE-287": {"probe": "oauth_probe / auth check", "moonmcp_tool": "oauth_probe", "injection_class": "auth"},
    "CWE-601": {"probe": "open_redirect", "moonmcp_tool": "open_redirect", "injection_class": "redirect"},
    "CWE-444": {"probe": "desync_probe / parser_diff_probe", "moonmcp_tool": "desync_probe", "injection_class": "smuggling"},
    "CWE-362": {"probe": "race_probe", "moonmcp_tool": "race_probe", "injection_class": "race"},
    "CWE-416": {"probe": "(memory safety — not web)", "moonmcp_tool": None, "injection_class": None},
    "CWE-415": {"probe": "(memory safety — not web)", "moonmcp_tool": None, "injection_class": None},
    "CWE-119": {"probe": "(memory safety — not web)", "moonmcp_tool": None, "injection_class": None},
    "CWE-787": {"probe": "(memory safety — not web)", "moonmcp_tool": None, "injection_class": None},
    "CWE-476": {"probe": "(memory safety — not web)", "moonmcp_tool": None, "injection_class": None},
    "CWE-327": {"probe": "jwt_analyze / jwt_crack", "moonmcp_tool": "jwt_analyze", "injection_class": "crypto"},
    "CWE-347": {"probe": "jwt_alg_confusion", "moonmcp_tool": "jwt_alg_confusion", "injection_class": "crypto"},
    "CWE-522": {"probe": "reset_poison_probe / auth check", "moonmcp_tool": "reset_poison_probe", "injection_class": "auth"},
    "CWE-1336": {"probe": "ssti_probe / injection_info", "moonmcp_tool": "ssti_probe", "injection_class": "ssti"},
    "CWE-619": {"probe": "reset_poison_probe / session check", "moonmcp_tool": "reset_poison_probe", "injection_class": "auth"},
    "CWE-384": {"probe": "oauth_probe / session fixation", "moonmcp_tool": "oauth_probe", "injection_class": "auth"},
    "CWE-285": {"probe": "access_control_check", "moonmcp_tool": "access_control_check", "injection_class": "authz"},
    "CWE-284": {"probe": "authz_probe / access_control_check", "moonmcp_tool": "authz_probe", "injection_class": "authz"},
    "CWE-863": {"probe": "path_bypass_probe", "moonmcp_tool": "path_bypass_probe", "injection_class": "authz"},
    "CWE-20": {"probe": "parser_diff_probe / interp_probe", "moonmcp_tool": "parser_diff_probe", "injection_class": "parser"},
    "CWE-93": {"probe": "crlf_probe", "moonmcp_tool": "crlf_probe", "injection_class": "crlf"},
    "CWE-915": {"probe": "logic_probe (mass assignment)", "moonmcp_tool": "logic_probe", "injection_class": "mass-assignment"},
    "CWE-525": {"probe": "cache_probe / cache_deception_probe", "moonmcp_tool": "cache_probe", "injection_class": "cache"},
    "CWE-1021": {"probe": "cache_probe / vhost_probe", "moonmcp_tool": "vhost_probe", "injection_class": "cache"},
    "CWE-290": {"probe": "vhost_probe / host header injection", "moonmcp_tool": "vhost_probe", "injection_class": "host-header"},
    "CWE-441": {"probe": "interp_probe / parser_diff_probe", "moonmcp_tool": "interp_probe", "injection_class": "parser"},
    "CWE-426": {"probe": "dependency_confusion", "moonmcp_tool": "dependency_confusion", "injection_class": "supply-chain"},
    "CWE-494": {"probe": "dependency_confusion", "moonmcp_tool": "dependency_confusion", "injection_class": "supply-chain"},
    "CWE-829": {"probe": "dependency_confusion", "moonmcp_tool": "dependency_confusion", "injection_class": "supply-chain"},
    "CWE-276": {"probe": "debug_exposure / content_discovery", "moonmcp_tool": "debug_exposure", "injection_class": "info"},
    "CWE-732": {"probe": "content_discovery / vcs_exposure", "moonmcp_tool": "content_discovery", "injection_class": "info"},
    "CWE-1188": {"probe": "debug_exposure / content_discovery", "moonmcp_tool": "debug_exposure", "injection_class": "info"},
    "CWE-326": {"probe": "tls_fingerprint / tls_behavior", "moonmcp_tool": "tls_fingerprint", "injection_class": "crypto"},
    "CWE-345": {"probe": "jwt_analyze / oauth_probe", "moonmcp_tool": "jwt_analyze", "injection_class": "crypto"},
    "CWE-367": {"probe": "race_probe (TOCTOU)", "moonmcp_tool": "race_probe", "injection_class": "race"},
}

# Incomplete-fix indicators — patterns that suggest a patch is incomplete
_INCOMPLETE_FIX_INDICATORS = [
    {
        "pattern": "single check added",
        "description": "Patch adds if/return check in ONE function — are there OTHER paths to the same code?",
        "questions": [
            "Does the patch cover ALL entry points to the vulnerable code?",
            "Can corrupted/malcrafted input bypass the new check?",
            "Are there other functions calling the same vulnerable logic?",
        ],
    },
    {
        "pattern": "single field validated",
        "description": "Patch validates field A — are there OTHER fields with the same pattern?",
        "questions": [
            "Are there sibling fields that skip the same validation?",
            "Does the deserialization loader trust other attacker-controlled fields?",
            "Is the same pattern present in other modules/components?",
        ],
    },
    {
        "pattern": "core fix only",
        "description": "Patch in core product — are bundled modules/extensions also affected?",
        "questions": [
            "Do bundled modules have the same pattern?",
            "Are third-party extensions affected?",
            "Is the fix ported to all supported version branches?",
        ],
    },
    {
        "pattern": "exploit-specific fix",
        "description": "Patch blocks the specific exploit path, not the root cause",
        "questions": [
            "Does the patch address the fundamental logic flaw or just the reported exploit?",
            "Can a different input trigger the same memory corruption/logic error?",
            "Is the root cause (e.g. shared ownership, deserialization mismatch) structurally prevented?",
        ],
    },
    {
        "pattern": "version gap",
        "description": "Patch in version X.Y.Z — target on older version",
        "questions": [
            "Is the patch ported to the target's version branch?",
            "Are there LTS versions that might not receive the fix?",
            "Was the fix included in the next minor/major release?",
        ],
    },
]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class PatchDiffResult:
    cve_id: str
    description: str = ""
    cvss_score: float | None = None
    cvss_severity: str | None = None
    cwe: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    root_cause: str = ""
    root_cause_id: str = ""
    what_patch_fixes: str = ""
    gap_analysis: list[dict] = field(default_factory=list)
    variant_questions: list[str] = field(default_factory=list)
    moonmcp_probes: list[dict] = field(default_factory=list)
    github_prs: list[str] = field(default_factory=list)
    hackerone_reports: list[str] = field(default_factory=list)


@dataclass
class VariantSearchResult:
    pattern: str
    root_cause: str = ""
    cwes: list[str] = field(default_factory=list)
    moonmcp_probes: list[dict] = field(default_factory=list)
    payload_sources: list[str] = field(default_factory=list)
    knowledge_base_entries: list[str] = field(default_factory=list)
    bugbounty_calibration: list[str] = field(default_factory=list)
    questions_to_ask: list[str] = field(default_factory=list)
    poc_pipeline: list[dict] = field(default_factory=list)
    triage_memory: list[str] = field(default_factory=list)


@dataclass
class VersionVulnResult:
    product: str
    version: str = ""
    total_cves: int = 0
    unpatched: list[dict] = field(default_factory=list)
    patched: list[dict] = field(default_factory=list)
    unknown: list[dict] = field(default_factory=list)
    summary: str = ""


# ---------------------------------------------------------------------------
# Version parsing helpers
# ---------------------------------------------------------------------------

_VERSION_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?(?:\.(\d+))?")

def _parse_version(v: str) -> tuple[int, ...]:
    m = _VERSION_RE.search(v)
    if not m:
        return (0,)
    parts = [int(g or 0) for g in m.groups()]
    # Strip trailing zeros for comparison
    while parts and parts[-1] == 0:
        parts.pop()
    return tuple(parts) if parts else (0,)

def _version_in_range(target: str, affected_min: str, affected_max: str) -> str:
    """Returns 'vulnerable', 'patched', or 'unknown'."""
    t = _parse_version(target)
    lo = _parse_version(affected_min) if affected_min else (0,)
    hi = _parse_version(affected_max) if affected_max else (999,)
    if t < lo:
        return "unknown"  # before affected range
    if t >= hi:
        return "patched"  # at or beyond fix version
    return "vulnerable"


def _extract_version_range(description: str) -> tuple[str, str]:
    """Extract affected version range from CVE description."""
    # Patterns: "from versions X to before Y", "prior to X", "before X"
    lo = ""
    hi = ""

    # "from versions 32.0.0 to before 32.0.9"
    m = re.search(r"from versions?\s+([\d.]+)\s+to\s+before\s+([\d.]+)", description, re.I)
    if m:
        lo = m.group(1)
        hi = m.group(2)
        return lo, hi

    # "versions 32.0.0 to before 32.0.9"
    m = re.search(r"versions?\s+([\d.]+)\s+to\s+before\s+([\d.]+)", description, re.I)
    if m:
        lo = m.group(1)
        hi = m.group(2)
        return lo, hi

    # "prior to X" or "before X"
    m = re.search(r"(?:prior to|before)\s+([\d.]+)", description, re.I)
    if m:
        hi = m.group(1)
        return lo, hi

    # "from X" (lower bound only)
    m = re.search(r"from\s+(?:version\s+)?([\d.]+)", description, re.I)
    if m:
        lo = m.group(1)
        return lo, hi

    return lo, hi


def _extract_fix_version(description: str) -> str:
    """Extract the fix version from CVE description."""
    # "upgraded to X" / "fixed in X" / "patched in X"
    for pattern in [
        r"(?:upgraded|fixed|patched|updated)\s+to\s+([\d.]+)",
        r"fix(?:ed)?\s+(?:in\s+)?(?:version\s+)?([\d.]+)",
        # "patched/resolved/addressed in [version] X" (the "in" phrasing pattern 1's
        # "to" requirement misses)
        r"(?:patched|resolved|addressed|corrected)\s+(?:in\s+)?(?:version\s+)?([\d.]+)",
        r"release[sd]?\s+([\d.]+)",
        r"upgrade[d]?\s+to\s+([\d.]+)",
    ]:
        m = re.search(pattern, description, re.I)
        if m:
            return m.group(1)
    return ""


def _identify_root_cause(description: str, cwes: list[str]) -> tuple[str, str]:
    """Identify root cause from description + CWE. Returns (root_cause_id, root_cause_name)."""
    desc_lower = description.lower()

    # Map CWE to root cause
    for rc_id, rc_cwes in _ROOT_CAUSE_CWE_MAP.items():
        for cwe in cwes:
            if cwe in rc_cwes:
                rc_names = {
                    "code-data-confusion": "Code/Data Confusion",
                    "confused-deputy": "Confused Deputy / Trust-Boundary Violation",
                    "parser-differential": "Parser Differential",
                    "broken-authorization": "Broken Authorization",
                    "insecure-deserialization": "Insecure Deserialization",
                    "state-desync-race": "State Desync / Race",
                    "insecure-defaults": "Insecure Defaults",
                    "memory-safety": "Memory Safety",
                    "crypto-misuse": "Crypto Misuse",
                    "network-position-abuse": "Network-Position Abuse",
                    "supply-chain-trust": "Supply-Chain Trust",
                    "implicit-client-trust": "Implicit Trust of Client Metadata",
                    "ambient-authority": "Ambient Authority",
                }
                return rc_id, rc_names.get(rc_id, rc_id)

    # Fallback: keyword matching in description
    keyword_map = {
        "broken-authorization": ["authorization", "access control", "ownership", "permission", "acl", "bypass"],
        "insecure-deserialization": ["deserializ", "rdb", "unserial", "pickle", "marshal"],
        "memory-safety": ["buffer overflow", "heap", "use-after-free", "double-free", "out-of-bounds", "oob"],
        "code-data-confusion": ["xss", "template injection", "ssti", "eval", "code injection"],
        "confused-deputy": ["ssrf", "csrf", "redirect", "forgery"],
        "parser-differential": ["smuggling", "parsing", "desync", "chunked"],
        "state-desync-race": ["race condition", "toctou", "time-of-check", "double"],
        "crypto-misuse": ["crypto", "jwt", "signature", "key", "algorithm"],
        "insecure-defaults": ["default", "debug", "enabled by default", "missing protection"],
        "implicit-client-trust": ["x-forwarded", "host header", "client", "ip spoof"],
    }
    for rc_id, keywords in keyword_map.items():
        for kw in keywords:
            if kw in desc_lower:
                return rc_id, rc_id.replace("-", " ").title()

    return "unknown", "Unknown"


def _classify_references(refs: list[str]) -> tuple[list[str], list[str]]:
    """Split references into GitHub PRs and HackerOne reports."""
    github_prs = [r for r in refs if "github.com" in r and "/pull/" in r]
    hackerone = [r for r in refs if "hackerone.com" in r]
    return github_prs, hackerone


def _get_probes_for_cwes(cwes: list[str]) -> list[dict]:
    """Get MoonMCP probe recommendations for given CWEs."""
    probes = []
    seen = set()
    for cwe in cwes:
        if cwe in _CWE_PROBE_MAP and cwe not in seen:
            entry = _CWE_PROBE_MAP[cwe]
            probes.append({
                "cwe": cwe,
                "probe": entry["probe"],
                "moonmcp_tool": entry["moonmcp_tool"],
                "injection_class": entry["injection_class"],
            })
            seen.add(cwe)
    return probes


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def cve_patch_diff(client: HttpClient, cve_id: str, api_key: str | None = None,
                         *, fetch_pr: bool = True) -> PatchDiffResult:
    """Analyze a CVE for patch-diff gap analysis (Kimi K3 cognitive pattern).

    Fetches the CVE from NVD, extracts:
    - What the patch fixes (from description + references)
    - Root cause identification
    - Gap analysis (incomplete-fix indicators)
    - Variant analysis questions
    - MoonMCP probe recommendations
    - GitHub PRs and HackerOne reports for further study
    - When fetch_pr=True (default), auto-reads the first GitHub PR diff
      and extracts what the patch actually changes in the code.
    """
    cve_id = cve_id.strip().upper()
    record = await cvemod.lookup_cve(client, cve_id, api_key=api_key)
    if record is None:
        return PatchDiffResult(cve_id=cve_id, description="CVE not found in NVD")

    root_cause_id, root_cause_name = _identify_root_cause(record.description, record.cwe)
    github_prs, hackerone = _classify_references(record.references)
    probes = _get_probes_for_cwes(record.cwe)
    fix_version = _extract_fix_version(record.description)

    # Auto-read the first GitHub PR to extract what the patch changes
    patch_summary = ""
    if fetch_pr and github_prs:
        try:
            from .reader import web_read
            pr_url = github_prs[0]
            # GitHub PR pages are JS-heavy; try the .diff or .patch suffix
            diff_url = pr_url.rstrip("/") + ".diff"
            page = await web_read(client, diff_url, max_chars=8000)
            if page.get("text"):
                patch_summary = page["text"][:2000]
            elif page.get("error"):
                # Fallback: read the PR page itself
                page = await web_read(client, pr_url, max_chars=8000)
                if page.get("text"):
                    patch_summary = page["text"][:2000]
        except Exception:
            pass  # network errors are non-fatal — the NVD data is still useful

    # Build what_patch_fixes from description + patch summary
    what_fixes = ""
    if fix_version:
        what_fixes = f"Fix version: {fix_version}. "
    what_fixes += record.description[:500]
    if patch_summary:
        what_fixes += f"\n\n--- Patch diff (auto-extracted from {github_prs[0]}) ---\n{patch_summary}"

    # Build gap analysis
    gaps = []
    for indicator in _INCOMPLETE_FIX_INDICATORS:
        gaps.append({
            "indicator": indicator["pattern"],
            "description": indicator["description"],
            "questions": indicator["questions"],
        })

    # Build variant questions specific to this CVE
    variant_questions = []
    if root_cause_id == "broken-authorization":
        variant_questions = [
            "Where else in this product is there an object access WITHOUT ownership check?",
            "Are there PUBLIC endpoints (no auth required) with the same authorization pattern?",
            "Can the same object be accessed via a different API/DAV/OCS path?",
            "Does the patch check ownership in ALL code paths or just the reported one?",
        ]
    elif root_cause_id == "insecure-deserialization":
        variant_questions = [
            "Where else in this product is untrusted data deserialized?",
            "Are there OTHER deserialization loaders with the same alloc-vs-trusted-length pattern?",
            "Can the same object be deserialized via a different format/protocol?",
            "Does the patch validate ALL attacker-controlled fields or just the reported one?",
        ]
    elif root_cause_id == "memory-safety":
        variant_questions = [
            "Where else in this codebase is there the same memory management pattern?",
            "Are there OTHER paths to the same double-free/OOB/UAF?",
            "Can the same memory corruption be triggered via a different input vector?",
            "Is the fix structural (prevents the class) or point (blocks one exploit)?",
        ]
    elif root_cause_id == "state-desync-race":
        variant_questions = [
            "Where else is there shared state accessed without proper locking?",
            "Are there OTHER TOCTOU windows in the same component?",
            "Can the same race be triggered via a different sequence of operations?",
        ]
    elif root_cause_id == "code-data-confusion":
        variant_questions = [
            "Where else is user input treated as code (eval, template, include)?",
            "Are there OTHER template engines or eval paths with the same pattern?",
            "Can the same injection be reached via a different parameter/endpoint?",
        ]
    elif root_cause_id == "confused-deputy":
        variant_questions = [
            "Where else does the server make requests on behalf of the user?",
            "Are there OTHER SSRF/CSRF vectors via different endpoints?",
            "Can the same confused-deputy pattern be exploited via a different protocol?",
        ]
    else:
        variant_questions = [
            f"Where else in this product is there the same {root_cause_name} pattern?",
            "Are there OTHER components/modules with the same root cause?",
            "Can the same vulnerability class be triggered via a different entry point?",
            "Is the fix structural or point-specific?",
        ]

    return PatchDiffResult(
        cve_id=cve_id,
        description=record.description,
        cvss_score=record.cvss_score,
        cvss_severity=record.cvss_severity,
        cwe=record.cwe,
        references=record.references,
        root_cause=root_cause_name,
        root_cause_id=root_cause_id,
        what_patch_fixes=what_fixes,
        gap_analysis=gaps,
        variant_questions=variant_questions,
        moonmcp_probes=probes,
        github_prs=github_prs,
        hackerone_reports=hackerone,
    )


def variant_search(pattern: str, *, target: str = "") -> VariantSearchResult:
    """Search for variant vulnerabilities matching a pattern (Kimi K3 variant analysis).

    Given a vulnerability pattern (root cause or CWE), returns:
    - Matching MoonMCP probes to run
    - Payload sources from knowledge base
    - Bug bounty report calibration sources
    - Questions to ask when hunting for variants
    - PoC validation pipeline (discovery → verification → reproduction)
    - Triage memory recall (false positive patterns from past runs)

    When `target` is provided, the result includes a `poc_pipeline` field that
    chains variant_search → probe → confirm_finding → add_finding, following
    the FuzzingBrain V2 discovery-verification-reproduction pattern.
    """
    pattern_lower = pattern.strip().lower()

    # Identify root cause
    root_cause_id = ""
    root_cause_name = ""
    cwes = []

    # Check if pattern is a root cause ID
    if pattern_lower in _ROOT_CAUSE_CWE_MAP:
        root_cause_id = pattern_lower
        root_cause_name = pattern_lower.replace("-", " ").title()
        cwes = _ROOT_CAUSE_CWE_MAP[root_cause_id]
    else:
        # Check if pattern is a CWE
        cwe_upper = pattern_lower.upper()
        if cwe_upper.startswith("CWE-"):
            cwes = [cwe_upper]
            for rc_id, rc_cwes in _ROOT_CAUSE_CWE_MAP.items():
                if cwe_upper in rc_cwes:
                    root_cause_id = rc_id
                    root_cause_name = rc_id.replace("-", " ").title()
                    break
        else:
            # Keyword search
            keyword_map = {
                "broken-authorization": ["authorization", "access control", "ownership", "idor", "bola", "auth bypass", "permission"],
                "insecure-deserialization": ["deserialization", "deserializ", "rdb", "unserial", "pickle", "marshal"],
                "memory-safety": ["buffer overflow", "heap", "use-after-free", "double-free", "out-of-bounds", "oob", "uaf"],
                "code-data-confusion": ["xss", "template injection", "ssti", "eval", "code injection", "rce"],
                "confused-deputy": ["ssrf", "csrf", "redirect", "forgery", "open redirect"],
                "parser-differential": ["smuggling", "parsing", "desync", "chunked", "parser diff"],
                "state-desync-race": ["race condition", "toctou", "time-of-check", "race"],
                "crypto-misuse": ["crypto", "jwt", "signature", "key", "algorithm", "crypto"],
                "insecure-defaults": ["default", "debug", "enabled by default", "missing protection"],
                "implicit-client-trust": ["x-forwarded", "host header", "client", "ip spoof"],
            }
            for rc_id, keywords in keyword_map.items():
                for kw in keywords:
                    if kw in pattern_lower:
                        root_cause_id = rc_id
                        root_cause_name = rc_id.replace("-", " ").title()
                        cwes = _ROOT_CAUSE_CWE_MAP.get(rc_id, [])
                        break
                if root_cause_id:
                    break

    # Get probes
    probes = _get_probes_for_cwes(cwes)

    # Knowledge base sources
    kb_sources = []
    if root_cause_id == "broken-authorization":
        kb_sources = ["payloads (idor)", "writeups (IDOR)", "owasp_cheatsheets (authorization)"]
    elif root_cause_id == "insecure-deserialization":
        kb_sources = ["payloads (deserialization)", "writeups (RCE)", "owasp_cheatsheets (deserialization)"]
    elif root_cause_id == "code-data-confusion":
        kb_sources = ["payloads (xss)", "payloads (ssti)", "writeups (XSS)", "owasp_cheatsheets (xss)"]
    elif root_cause_id == "confused-deputy":
        kb_sources = ["payloads (ssrf)", "writeups (SSRF)", "owasp_cheatsheets (ssrf)"]
    elif root_cause_id == "parser-differential":
        kb_sources = ["waf_bypass (techniques)", "payloads (smuggling)"]
    elif root_cause_id == "state-desync-race":
        kb_sources = ["business_logic (race)", "payloads (race)"]
    elif root_cause_id == "crypto-misuse":
        kb_sources = ["payloads (jwt)", "owasp_cheatsheets (jwt)"]
    else:
        kb_sources = ["payloads", "writeups", "owasp_cheatsheets"]

    # Bug bounty calibration
    bb_types = {
        "broken-authorization": "idor",
        "insecure-deserialization": "rce",
        "code-data-confusion": "xss",
        "confused-deputy": "ssrf",
        "state-desync-race": "race-condition",
        "crypto-misuse": "auth",
        "memory-safety": "rce",
        "insecure-defaults": "info-disclosure",
    }
    bb_type = bb_types.get(root_cause_id, "")

    # Questions
    questions = [
        f"Where else in the target is there the same {root_cause_name or pattern} pattern?",
        "Are there OTHER endpoints/modules with the same vulnerability class?",
        "Can the same bug be triggered via a different input vector?",
        "Is there a PUBLIC (no-auth) path to the same vulnerable code?",
        "What does the patch NOT cover? Which paths remain open?",
    ]

    # PoC validation pipeline (FuzzingBrain V2: discovery → verification → reproduction)
    poc_pipeline = []
    for probe in probes:
        tool = probe.get("moonmcp_tool")
        if not tool:
            continue
        poc_pipeline.append({
            "step": "1_discover",
            "tool": tool,
            "action": f"Run {tool} on target endpoints matching {root_cause_name or pattern}",
        })
        poc_pipeline.append({
            "step": "2_verify",
            "tool": "confirm_finding",
            "action": "Confirm with confirm_finding: baseline vs payload differential",
        })
        poc_pipeline.append({
            "step": "3_reproduce",
            "tool": "add_finding",
            "action": "Record with add_finding if confirmed, label_finding if false positive",
        })

    # Triage memory — false positive patterns to watch for
    # Based on Odd Sequence research: triage memories offer fast ROI
    triage_memory = []
    if root_cause_id == "broken-authorization":
        triage_memory = [
            "FP: 200 for all usernames = SPA stub, not user enumeration (check 429 rate limit)",
            "FP: public-calendars endpoint returns 200 but empty = no public shares, not auth bypass",
            "FP: same response for existing/non-existing user = no differential, not IDOR",
            "FP: 401 for all DAV endpoints = auth required, not broken authorization",
        ]
    elif root_cause_id == "insecure-deserialization":
        triage_memory = [
            "FP: Jackson @type rejected = type check active, not exploitable",
            "FP: WAF blocks XML = cannot reach deserializer",
            "FP: JSON endpoint rejects @type = strict typing, not polymorphic deserialization",
        ]
    elif root_cause_id == "code-data-confusion":
        triage_memory = [
            "FP: reflected input in HTML but < > escaped = not XSS",
            "FP: template expression in response but not evaluated (reflected not SSTI)",
            "FP: WAF blocks on* event handlers = cannot execute JS",
        ]
    elif root_cause_id == "confused-deputy":
        triage_memory = [
            "FP: server fetches URL but only returns HTTP status (no body) = limited SSRF",
            "FP: redirect to attacker domain but no token in URL = not token theft",
            "FP: CORS reflects origin but no Allow-Credentials = not exploitable",
        ]

    return VariantSearchResult(
        pattern=pattern,
        root_cause=root_cause_name,
        cwes=cwes,
        moonmcp_probes=probes,
        payload_sources=kb_sources,
        knowledge_base_entries=kb_sources,
        bugbounty_calibration=[f"search_bugbounty_reports(vuln_type={bb_type})"] if bb_type else [],
        questions_to_ask=questions,
        poc_pipeline=poc_pipeline,
        triage_memory=triage_memory,
    )


async def version_vuln_check(
    client: HttpClient,
    product: str,
    version: str = "",
    api_key: str | None = None,
    limit: int = 30,
) -> VersionVulnResult:
    """Check which CVEs are unpatched for a given product version (Kimi K3 version gap analysis).

    Searches NVD for CVEs affecting the product, then classifies each as:
    - unpatched: target version is within the affected range
    - patched: target version is at or beyond the fix version
    - unknown: version range could not be determined
    """
    # Search NVD — use product name only (version in description is used for filtering)
    search_term = product
    search_result = await cvemod.search_cves(client, search_term, limit=limit, api_key=api_key)

    result = VersionVulnResult(
        product=product,
        version=version,
        total_cves=search_result.total,
    )

    if search_result.error:
        result.summary = f"NVD search error: {search_result.error}"
        return result

    target_v = _parse_version(version) if version else None

    for cve_rec in search_result.results:
        lo, hi = _extract_version_range(cve_rec.description)
        fix_ver = _extract_fix_version(cve_rec.description)

        entry = {
            "cve_id": cve_rec.id,
            "cvss": cve_rec.cvss_score,
            "severity": cve_rec.cvss_severity,
            "description": cve_rec.description[:200],
            "cwe": cve_rec.cwe,
            "affected_range": f"{lo} - {hi}" if lo or hi else "unknown",
            "fix_version": fix_ver,
            "references": cve_rec.references[:5],
        }

        if not target_v:
            entry["status"] = "unknown"
            result.unknown.append(entry)
        elif fix_ver:
            status = _version_in_range(version, lo, fix_ver)
            entry["status"] = status
            if status == "vulnerable":
                result.unpatched.append(entry)
            elif status == "patched":
                result.patched.append(entry)
            else:
                result.unknown.append(entry)
        elif hi:
            status = _version_in_range(version, lo, hi)
            entry["status"] = status
            if status == "vulnerable":
                result.unpatched.append(entry)
            elif status == "patched":
                result.patched.append(entry)
            else:
                result.unknown.append(entry)
        else:
            entry["status"] = "unknown"
            result.unknown.append(entry)

    # Sort unpatched by CVSS (highest first)
    result.unpatched.sort(key=lambda e: e.get("cvss") or 0, reverse=True)
    result.patched.sort(key=lambda e: e.get("cvss") or 0, reverse=True)

    result.summary = (
        f"Product: {product} v{version}. "
        f"Total CVEs found: {len(search_result.results)}. "
        f"Unpatched: {len(result.unpatched)}. "
        f"Patched: {len(result.patched)}. "
        f"Unknown: {len(result.unknown)}."
    )

    return result