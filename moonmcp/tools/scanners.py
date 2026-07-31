"""External scanner integration (nuclei / nmap / httpx / … ) & coverage.

Extracted from server.py. Lists the external security CLIs MoonMCP knows about
(`external_tools`), runs an allow-listed scanner with every host/URL/IP argument
scope-checked and filesystem-I/O flags refused (`run_scanner`), reports scan
coverage, and drives templated `vuln_scan`. The scanner-arg guards
(`_reject_dangerous_scanner_args`, `_host_like_tokens`) and their host/flag
tables move with them. Importing this module registers the tools on `mcp`.
"""

from __future__ import annotations

import re

from ..context import to_dict
from ..external import cli
from ..external import nuclei as nucleimod
from ..mcp_core import _require_scope, active_tool, get_context, mcp, safe_tool
from ..scope import canonical_ip, normalize_target

_HOSTISH_RE = re.compile(r"^[a-z0-9.-]+\.[a-z]{2,63}(?::\d+)?$", re.IGNORECASE)
# Final-label extensions that mean "this is a file/list arg", not a hostname,
# so we don't false-positive a wordlist/config path as a scan target.
_NON_TLD = {
    "txt", "json", "yaml", "yml", "xml", "csv", "html", "htm", "conf", "cfg",
    "ini", "log", "list", "md", "js", "py", "sh", "pdf", "png", "jpg", "toml",
}


# Flags that make a scanner read or write a filesystem path — refused via
# run_scanner so it can't be turned into an arbitrary file read/write that sails
# past the host scope check (which only vets host/URL/IP tokens).
_SCANNER_PATH_FLAGS = {
    "-o", "-oa", "-on", "-ox", "-og", "-os", "-oj", "--output", "-output", "-output-file",
    "-w", "--write", "-config", "--config", "-input-file", "-l", "-list", "-resume",
    "-store-resp", "-srd", "-sr", "-or", "-data-dir", "--stats-file", "-je", "-jle",
    "-sf", "-store-response-dir",
}


def _reject_dangerous_scanner_args(args: list[str]) -> str | None:
    """Return a reason if *args* try to read/write a filesystem path, else None."""

    for tok in args:
        t = tok.strip()
        base = t.split("=", 1)[0].lower()
        if base in _SCANNER_PATH_FLAGS:
            return f"flag '{t}' performs file I/O and is not allowed via run_scanner"
        if "://" in t:
            continue  # a URL, not a path
        if t.startswith(("/", "~", "\\\\")) or ".." in t or (len(t) > 2 and t[1] == ":"):
            return f"path-like argument '{t}' is not allowed via run_scanner"
    return None


def _host_like_tokens(args: list[str]) -> list[str]:
    """Extract host/URL/IP-looking tokens from a CLI arg list (for scope checks).

    Skips flags and non-target tokens (template paths, severities, wordlists) so
    that every actual scan target in ``args`` gets scope-checked.
    """

    import ipaddress

    def _loopback_alias(h: str) -> bool:
        # Well-known loopback hostnames carry no dot+TLD, so `_HOSTISH_RE` misses them,
        # yet they are prime SSRF-to-loopback scan targets (`nmap … localhost`). Extract
        # them explicitly. (Arbitrary single-label names are NOT extracted — that would
        # scope-block benign scanner values like `-tags redis,cve`.)
        hl = h.strip().lower().rstrip(".")
        return (hl in ("localhost", "ip6-localhost", "localhost.localdomain")
                or hl.endswith(".localhost"))

    # Expand comma/whitespace-delimited values so an embedded target (e.g.
    # `-u in-scope.example.com,169.254.169.254`) is scope-checked, not skipped whole.
    # `_HOSTISH_RE` requires a dot+TLD and IPs are matched separately, so tag/status
    # lists (`-tags redis,mongodb`, `-mc 200,301`) never look host-like. A value glued
    # to a flag with '=' (goflags-style `-u=value`, `--target=value`) is the real
    # scope-relevant token — pull it out, else the URL/IP rides to the scanner
    # completely unchecked (an SSRF hole past the scope gate).
    expanded: list[str] = []
    for tok in args:
        t = tok.strip()
        if t.startswith("-"):
            if "=" not in t:
                continue  # a bare flag carries no target
            t = t.split("=", 1)[1].strip()
            if not t or t.startswith("-"):
                continue
        if "," in t or " " in t:
            expanded.extend(p for p in re.split(r"[,\s]+", t) if p)
        elif t:
            expanded.append(t)

    found: list[str] = []
    for tok in expanded:
        t = tok.strip()
        if not t or t.startswith("-"):
            continue
        if "://" in t:
            found.append(t)
            continue
        if "/" in t:
            # A CIDR block is itself a scan target; a host/path (example.com/api)
            # must still have its host scope-checked — don't skip either.
            try:
                ipaddress.ip_network(t, strict=False)
                found.append(t)
                continue
            except ValueError:
                t = t.split("/", 1)[0]
        # Normalise (strip scheme/brackets/port) then test for ANY IP literal —
        # including the obfuscated IPv4 encodings (decimal 2852039166 = 169.254.169.254,
        # hex 0x7f000001, short 127.1) and IPv6 (::1, [::1]) that the old
        # ipaddress.ip_address(t.split(':')[0]) missed and would smuggle to the scanner
        # past the scope check.
        try:
            host_only = normalize_target(t)
        except ValueError:
            continue
        if canonical_ip(host_only) is not None:
            # A dotted/hex/short/IPv6 literal is always a target. A BARE decimal
            # integer also matches benign scanner values (status codes 200/301, ports,
            # counts, rates), so only treat one as a target when it maps to >= 1.0.0.0
            # (0x01000000) — every real obfuscated IP does; small values do not.
            if not host_only.isdigit() or int(host_only) > 0x00FFFFFF:
                found.append(t)
                continue
        if _loopback_alias(host_only):
            found.append(t)
            continue
        if _HOSTISH_RE.match(t) and host_only.rsplit(".", 1)[-1].lower() not in _NON_TLD:
            found.append(t)
    return found


@mcp.tool()
@safe_tool
async def external_tools(category: str | None = None) -> dict:
    """List the external security CLIs MoonMCP knows about — **grouped by
    category** (subdomain, dns, http, crawl, content, port, vuln, cms, tls, url,
    decompile) — with, for each: whether it is installed on PATH, its native
    MoonMCP fallback, whether it is `intrusive` (gated), and an install hint.

    On Kali most of these are already present. Call this before `run_scanner` /
    `vuln_scan` to see what is available and what to install. Pass a `category` to
    filter. `by_category` groups the same data for quick scanning.
    """

    s = get_context().settings
    grouped = cli.tools_by_category()
    if category:
        grouped = {category: grouped.get(category, [])}
    installed = sorted(n for n, m in cli.detect_tools().items() if m["available"])
    return {
        "runner_enabled": s.allow_external_tools,
        "intrusive_enabled": s.allow_intrusive,
        "installed": installed,
        "installed_count": len(installed),
        "known_count": len(cli.KNOWN_TOOLS),
        "by_category": grouped,
    }


@mcp.tool()
@active_tool(self_scoped=True)
async def run_scanner(tool: str, args: list[str], target: str | None = None) -> dict:
    """Run an installed external security CLI and return its output.

    ``tool`` must be one of the known tools — see `external_tools` for the full,
    categorised list (subfinder, amass, httpx, whatweb, wafw00f, katana,
    gau/waybackurls, ffuf/feroxbuster/gobuster, naabu/nmap/masscan,
    nuclei/nikto/wpscan/sqlmap/dalfox, sslscan/tlsx, …). ``args`` are passed
    through verbatim. If ``target`` is given it is scope-checked first; every
    host/URL in ``args`` is scope-checked too. **Intrusive** scanners (fuzzers,
    port scanners, active vuln scanners) also require MOONMCP_ALLOW_INTRUSIVE. If
    the tool is missing, returns the native MoonMCP fallback to use instead. JSONL
    output is auto-parsed. Gated by MOONMCP_ALLOW_EXTERNAL_TOOLS.
    """

    ctx = get_context()
    if tool not in cli.KNOWN_TOOLS:
        return {"error": "unknown_tool", "detail": f"{tool} is not a known scanner",
                "known": list(cli.KNOWN_TOOLS)}
    # Intrusive external scanners are gated exactly like the native intrusive
    # tools — scope alone is not enough for a fuzzer/port-scanner/active scanner.
    if cli.is_intrusive(tool) and not ctx.settings.allow_intrusive:
        ctx.audit.record("intrusive_blocked", tool="run_scanner", target=(target or tool),
                         decision="deny")
        return {"error": "disabled",
                "detail": f"{tool} is an intrusive scanner; enable with MOONMCP_ALLOW_INTRUSIVE=1."}
    # Refuse file-I/O flags/paths: run_scanner is a network-recon passthrough, not
    # a way to read/write arbitrary files past the host scope check.
    bad = _reject_dangerous_scanner_args(args)
    if bad is not None:
        return {"error": "unsafe_args", "detail": bad,
                "hint": "run_scanner is for network recon only; file input/output flags are blocked."}
    # Scope-check the declared target AND every host/URL/IP in args — the real
    # scan target usually lives inside args (e.g. `-u https://host`).
    to_check = ([target] if target else []) + _host_like_tokens(args)
    if ctx.settings.enforce_scope and not to_check:
        return {"error": "no_target",
                "detail": "Refusing to run a scanner with no scope-checked target while "
                          "enforcement is on. Pass a 'target' that is in scope, or include the "
                          "host/URL in args."}
    for t in to_check:
        await _require_scope(t, tool="run_scanner")
    ctx.audit.record("external_tool", tool=tool, target=(target or ",".join(to_check)),
                     decision="run", args=args[:20])
    result = await cli.run_tool(
        tool, args, timeout=ctx.settings.external_timeout, allow=ctx.settings.allow_external_tools
    )
    data = to_dict(result)
    if result.available and result.stdout:
        parsed = cli.parse_jsonl(result.stdout)
        if parsed:
            data["parsed"] = parsed[:500]
    return data


@mcp.tool()
@safe_tool
async def scan_coverage() -> dict:
    """**What nuclei covers vs. what only MoonMCP does** — the honest, executable map.

    nuclei is a stateless per-template matcher: because everyone mass-scans with it,
    the bugs it can find are largely already reported. This returns the split so you
    scan efficiently: `delegate_to_nuclei` (commodity — run `vuln_scan`, don't hand-
    hunt it), `native_edge` (the stateful/differential/timing/logic probes nuclei
    STRUCTURALLY can't express — higher hit-rate on already-scanned targets, always
    run these), plus MoonMCP's architecture edge. Offline; no traffic.
    """

    return nucleimod.coverage_report()


@mcp.tool()
@active_tool(intrusive=True)
async def vuln_scan(target: str, templates: str | None = None, severity: str | None = None,
                    tags: str | None = None, dast: bool = False, record: bool = False) -> dict:
    """Run a nuclei template-based vulnerability scan against an in-scope target — the
    commodity pass (delegate what nuclei owns; see `scan_coverage`).

    `tags` takes plain intents (cve, exposure, misconfig, takeover, panel, tech, sqli,
    xss, ssrf, redirect, lfi, …) mapped to nuclei `-tags`; `templates` maps to `-t`;
    `severity` to `-severity` (e.g. 'critical,high'); `dast=True` enables nuclei
    fuzzing of discovered params; `record=True` files findings into the findings store.
    The result includes `also_run_native` — the probes nuclei can't do that you should
    run anyway. Requires nuclei installed. Intrusive: MOONMCP_ALLOW_INTRUSIVE +
    MOONMCP_ALLOW_EXTERNAL_TOOLS + the host in scope.
    """

    host = normalize_target(target)
    ctx = get_context()
    raw = target.strip()
    url = raw if "://" in raw else f"https://{host}"
    args = nucleimod.build_args(url, tags=tags, templates=templates, severity=severity, dast=dast)
    result = await cli.run_tool(
        "nuclei", args, timeout=ctx.settings.external_timeout, allow=ctx.settings.allow_external_tools
    )
    if not result.available:
        return {
            "error": "nuclei_unavailable",
            "detail": result.error,
            "suggestion": "Install nuclei, or use analyze_headers + well_known + "
                          "content_discovery + cve_search for a native first pass.",
            "also_run_native": nucleimod.also_run_native(),
        }
    findings = [nucleimod.normalize_finding(r) for r in cli.parse_jsonl(result.stdout)]
    recorded = 0
    if record:
        for f in findings:
            ctx.findings.add(target=host, severity=f["severity"], title=f["name"],
                             type="nuclei", detail=f.get("description", ""),
                             evidence=f.get("matched_at", ""), source=f.get("template_id", ""))
            recorded += 1
    return {
        "target": url,
        "findings": findings,
        "finding_count": len(findings),
        "recorded": recorded,
        "also_run_native": nucleimod.also_run_native(),
        "note": ("nuclei is the commodity pass — now run the native-edge probes "
                 "(see scan_coverage) for bugs that survive the nuclei crowd"),
        "exit_code": result.exit_code,
        "duration_ms": result.duration_ms,
        "stderr_tail": result.stderr[-500:] if result.stderr else "",
    }


# ---------------------------------------------------------------------------
# resources & prompts
# ---------------------------------------------------------------------------
