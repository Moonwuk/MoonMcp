"""Offline / passive artifact analysis.

Extracted from server.py. Static analysis of captured artifacts with no traffic
to the target's app tier: firmware/binary triage + decompile, config-file
secret/misconfig audit, dependency-confusion manifest analysis, and DNS-based
email-security posture (SPF/DMARC/DKIM/CAA). Importing this module registers
them on the shared `mcp` instance.
"""

from __future__ import annotations

import asyncio

from ..context import to_dict
from ..external import cli
from ..intel import email as emailmod
from ..mcp_core import (
    _require_scope,
    _scope_check,
    active_tool,
    get_context,
    mcp,
    safe_tool,
)
from ..recon import binary as binarymod
from ..recon import config_audit as configmod
from ..recon import depconf as depconfmod
from ..scope import normalize_target


@mcp.tool()
@active_tool()
async def analyze_binary(target: str, decompile: bool = True) -> dict:
    """Download an in-scope compiled artifact (.dll/.exe/.jar/.so/.apk/…) and
    triage it: identify the file type (incl. .NET assemblies), extract ASCII +
    UTF-16 strings, scan them for secrets and for URLs/hosts/connection-strings.
    If it is a .NET assembly and `ilspycmd` is installed, also decompiles a
    preview (else reports how to get it). Great for thick-client / exposed-binary
    recon. In scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    fetched = await ctx.http.fetch(url, follow_redirects=True, timeout=30.0,
                                   max_body=12 * 1024 * 1024, scope_check=_scope_check())
    if fetched.status is None:
        return {"error": "unreachable", "detail": fetched.error, "url": url}
    if not fetched.body:
        return {"error": "empty_body", "detail": f"HTTP {fetched.status}", "url": url}

    # Run the multi-MB string-extraction + regex scans OFF the event loop — a 12 MiB
    # attacker-controlled artifact must never block every other concurrent MCP tool
    # (matches the crawl/secrets modules' to_thread offload).
    analysis = await asyncio.to_thread(binarymod.analyze_bytes, fetched.body,
                                       url=fetched.final_url or url)
    analysis.truncated = fetched.truncated

    # Optional real decompilation of .NET assemblies via ilspycmd.
    if analysis.is_dotnet:
        path = cli.tool_path("ilspycmd") if ctx.settings.allow_external_tools else None
        if path:
            analysis.decompiler_available = "ilspycmd"
            import os
            import tempfile
            tmp = tempfile.NamedTemporaryFile(suffix=".dll", delete=False)
            try:
                tmp.write(fetched.body)
                tmp.close()
                if decompile:
                    res = await cli.run_tool("ilspycmd", [tmp.name],
                                             timeout=min(120.0, ctx.settings.external_timeout),
                                             allow=True)
                    if res.available and res.stdout:
                        analysis.decompiled_preview = res.stdout[:20000]
                    elif res.error:
                        analysis.decompiler_hint = res.error
            finally:
                try:
                    os.unlink(tmp.name)
                except OSError:
                    pass
        else:
            analysis.decompiler_hint = (
                "Install ilspycmd for full decompilation: dotnet tool install -g ilspycmd"
            )
    return to_dict(analysis)


@mcp.tool()
@active_tool(self_scoped=True)
async def analyze_config(content: str | None = None, target: str | None = None,
                         filename: str | None = None) -> dict:
    """Parse a configuration file and lay out **every setting** so you can
    understand the whole config, then flag the risky ones. Supports .env, INI,
    JSON, YAML, .properties, XML (web.config/appsettings), PHP and a generic
    key=value fallback — auto-detected (a `filename` hint helps). Groups settings
    by category (database/secret/cloud/network/debug/…) and reports findings:
    exposed secrets, DEBUG=true, disabled TLS verification, wildcard CORS,
    default/weak credentials, bind-to-all, and credentials in connection strings.

    Pass `content` directly (e.g. from vcs_exposure / analyze_binary output), OR
    a `target` URL to an in-scope config file to fetch and analyze.
    """

    if content is None:
        if not target:
            return {"error": "invalid_input", "detail": "provide 'content' or 'target'"}
        raw = target.strip()
        url = raw if "://" in raw else f"https://{raw}"
        await _require_scope(url, tool="analyze_config")
        ctx = get_context()
        r = await ctx.http.fetch(url, follow_redirects=True, timeout=15.0,
                                 max_body=2 * 1024 * 1024, scope_check=_scope_check())
        if r.status is None:
            return {"error": "unreachable", "detail": r.error, "url": url}
        if not r.body:
            return {"error": "empty_body", "detail": f"HTTP {r.status}", "url": url}
        content = r.text(limit=2_000_000)
        if filename is None:
            from urllib.parse import urlsplit
            filename = urlsplit(url).path.rsplit("/", 1)[-1] or None
    audit = configmod.analyze_config(content, filename=filename)
    return to_dict(audit)


@mcp.tool()
@safe_tool
async def dependency_confusion(content: str, ecosystem: str = "auto",
                               filename: str | None = None) -> dict:
    """Detect **dependency confusion**: parse a manifest (package.json /
    composer.json / requirements.txt / Pipfile / Gemfile) and existence-check each
    dependency against its PUBLIC registry — a 404 means the name is unclaimed, so
    an attacker could publish a higher-version package your build would pull
    (supply-chain RCE, the Microsoft/Apple pattern). Queries the registry, never
    the target, so no scope is needed. Feed `content` from `vcs_exposure` /
    `analyze_js`; `ecosystem` (npm/pypi/composer/rubygems) auto-detects.
    """

    eco = ecosystem if ecosystem != "auto" else depconfmod.detect_ecosystem(content, filename)
    if eco is None:
        return {"error": "unknown_ecosystem",
                "detail": "could not detect the ecosystem; pass ecosystem=npm|pypi|composer|rubygems"}
    names = depconfmod.parse_dependencies(content, eco)
    if not names:
        return {"ecosystem": eco, "dependencies": 0, "results": [],
                "note": "no dependencies parsed from the manifest"}
    ctx = get_context()
    results = await depconfmod.check_dependencies(ctx.http, names, eco)
    claimable = [r for r in results if r["verdict"] == "claimable"]
    return {
        "ecosystem": eco, "dependencies": len(names), "claimable_count": len(claimable),
        "results": results,
        "note": (f"{len(claimable)} hijack candidate(s) absent on the public registry — "
                 "verify ownership before reporting" if claimable
                 else "all parsed dependencies exist on the public registry"),
    }


@mcp.tool()
@active_tool()
async def email_security(domain: str) -> dict:
    """Analyze a domain's email-spoofing posture over DNS: SPF, DMARC (policy),
    DKIM (common selectors) and CAA, with an A-F grade and specific weaknesses
    (missing/again weak SPF, DMARC p=none, no CAA, ...). Passive DNS. In scope only.
    """

    host = normalize_target(domain)
    ctx = get_context()
    result = await emailmod.analyze_email_security(ctx.http, host)
    return to_dict(result)
