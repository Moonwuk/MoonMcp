"""Knowledge-base tools — pure, offline reference lookups (no scope, no traffic).

Extracted from server.py as the first module of the per-family split. Every tool
here is `@mcp.tool()` + `@safe_tool` over the bundled knowledge catalogs; importing
this module registers them on the shared `mcp` instance.
"""

from __future__ import annotations

from ..knowledge import injections as injmod
from ..knowledge import privesc as privescmod
from ..knowledge import techniques as techmod
from ..knowledge import vulns as vulnsmod
from ..knowledge import waf_kb as wafkbmod
from ..mcp_core import mcp, safe_tool


# ---------------------------------------------------------------------------
# knowledge base — injections (patterns, causes, signatures)
# ---------------------------------------------------------------------------
@mcp.tool()
@safe_tool
async def injection_info(injection_class: str | None = None) -> dict:
    """Look up MoonMCP's injection knowledge base: patterns (detection payloads),
    causes (root causes) and signatures (exact error strings / regexes to detect
    the vuln from a response). Pass an injection class id/alias (e.g. sqli, xss,
    ssti, cmdi, xxe, ssrf, crlf, path-traversal, ldap, xpath, nosqli, ssi,
    graphql, prompt-injection) for full detail, or omit for the index + stats.
    No network — pure reference.
    """

    if not injection_class:
        return {"stats": injmod.stats(), "classes": injmod.list_classes()}
    entry = injmod.get_class(injection_class)
    if entry is None:
        return {"error": "unknown_class", "detail": f"No injection class '{injection_class}'",
                "known": [c["id"] for c in injmod.list_classes()]}
    return entry


@mcp.tool()
@safe_tool
async def injection_search(query: str) -> dict:
    """Search the injection knowledge base by keyword (name, alias, CWE, summary)."""

    return {"query": query, "results": injmod.search(query)}


@mcp.tool()
@safe_tool
async def match_injection_signatures(text: str, injection_class: str | None = None) -> dict:
    """Scan a blob of text (e.g. an HTTP response body from http_probe) for known
    injection error/regex signatures and report which injection class + technology
    each match indicates — a fast way to spot a likely SQLi/SSTI/etc. from a raw
    error message. Optionally restrict to one class. No network.
    """

    matches = injmod.match_signatures(text, class_id=injection_class)
    return {"match_count": len(matches), "matches": matches}


@mcp.tool()
@safe_tool
async def technique_info(technique: str | None = None, category: str | None = None,
                         language: str | None = None) -> dict:
    """Look up MoonMCP's techniques & notable-PoC catalog — a referenced index of
    exploitation techniques and landmark public vulnerabilities across languages
    (web, deserialization, memory-corruption/asm, famous CVEs, language-specific,
    kernel/low-level). Pass a technique id or CVE for full detail; or filter by
    `category` / `language`; or omit for the index + stats. Each entry links to
    the public PoC/research — it is a knowledge reference, not exploit code.
    """

    if technique:
        entry = techmod.get_technique(technique)
        if entry is None:
            return {"error": "unknown_technique", "detail": f"No technique '{technique}'",
                    "categories": techmod.categories()}
        return entry
    if category:
        return {"category": category, "results": techmod.by_category(category)}
    if language:
        return {"language": language, "results": techmod.by_language(language)}
    return {"stats": techmod.stats(), "techniques": techmod.list_techniques()}


@mcp.tool()
@safe_tool
async def technique_search(query: str) -> dict:
    """Search the techniques & PoC catalog by keyword, language, CVE or category."""

    return {"query": query, "results": techmod.search(query)}


# ---------------------------------------------------------------------------
# knowledge base — privilege escalation (techniques + tooling)
# ---------------------------------------------------------------------------
@mcp.tool()
@safe_tool
async def privesc_info(technique: str | None = None, platform: str | None = None,
                       category: str | None = None) -> dict:
    """Look up MoonMCP's privilege-escalation knowledge base — a referenced catalog
    of local privesc techniques across Linux, Windows, container, cloud and Active
    Directory, with benign enumeration commands, detection indicators and links to
    public research (no exploit code). Pass a technique id or CVE for full detail;
    or filter by `platform` (linux/windows/container/cloud/active-directory) or
    `category` (sudo, suid-sgid, capabilities, kernel-exploit, service-misconfig,
    token-impersonation, container-escape, cloud-iam, kerberos, adcs, …); or omit
    for the index + stats. No network — pure reference.
    """

    if technique:
        entry = privescmod.get_technique(technique)
        if entry is None:
            return {"error": "unknown_technique", "detail": f"No privesc technique '{technique}'",
                    "platforms": privescmod.platforms(), "categories": privescmod.categories()}
        return entry
    if platform:
        return {"platform": platform, "results": privescmod.by_platform(platform)}
    if category:
        return {"category": category, "results": privescmod.by_category(category)}
    return {"stats": privescmod.stats(), "techniques": privescmod.list_techniques()}


@mcp.tool()
@safe_tool
async def privesc_search(query: str) -> dict:
    """Search the privilege-escalation KB by keyword (name, platform, category, CVE,
    tool or detection indicator).
    """

    return {"query": query, "results": privescmod.search(query)}


@mcp.tool()
@safe_tool
async def privesc_tools(tool: str | None = None, query: str | None = None) -> dict:
    """Catalog of privilege-escalation TOOLING (LinPEAS/WinPEAS, GTFOBins, LOLBAS,
    PowerUp, Seatbelt, pspy, linux-exploit-suggester, the potato family, BloodHound,
    …). Pass a `tool` id/name for detail, a `query` to search, or omit for the full
    list. No network — pure reference.
    """

    if tool:
        entry = privescmod.get_tool(tool)
        if entry is None:
            return {"error": "unknown_tool", "detail": f"No privesc tool '{tool}'",
                    "known": [t["id"] for t in privescmod.list_tools()]}
        return entry
    if query:
        return {"query": query, "results": privescmod.search_tools(query)}
    return {"count": len(privescmod.list_tools()), "tools": privescmod.list_tools()}


@mcp.tool()
@safe_tool
async def match_privesc(text: str, platform: str | None = None) -> dict:
    """Scan pasted local-enumeration output (e.g. `sudo -l`, `id`, a SUID listing,
    `getcap -r /`, `whoami /priv`, `systeminfo`) for known privilege-escalation
    vectors and report which techniques the output indicates — a fast triage of a
    foothold's escalation paths. Optionally restrict to one `platform`. No network.
    """

    matches = privescmod.match_enumeration(text, platform=platform)
    return {"match_count": len(matches), "matches": matches}


# ---------------------------------------------------------------------------
# knowledge base — server-side vulnerabilities + root-cause taxonomy
# ---------------------------------------------------------------------------
@mcp.tool()
@safe_tool
async def vuln_info(vuln: str | None = None, category: str | None = None,
                    popularity: str | None = None, root_cause: str | None = None) -> dict:
    """Look up MoonMCP's server-side vulnerability catalog — popular AND obscure
    classes (SSRF, SQLi, RCE, deserialization, request smuggling, SSTI, XXE,
    cache poisoning, mass assignment, prototype pollution, race conditions,
    GraphQL/NoSQL/LDAP/XPath, header injection, …). Each entry maps to its ROOT
    CAUSE and the concrete point where real apps break (`where_it_breaks`), with
    detection, WAF notes and notable real-world incidents. Pass a `vuln` id for
    detail; filter by `category`, `popularity` (common/uncommon/rare) or
    `root_cause`; or omit for the index + stats. No network — pure reference.
    """

    if vuln:
        entry = vulnsmod.get_vuln(vuln)
        if entry is None:
            return {"error": "unknown_vuln", "detail": f"No vulnerability '{vuln}'",
                    "categories": vulnsmod.categories()}
        return entry
    if category:
        return {"category": category, "results": vulnsmod.by_category(category)}
    if popularity:
        return {"popularity": popularity, "results": vulnsmod.by_popularity(popularity)}
    if root_cause:
        return {"root_cause": root_cause, "results": vulnsmod.by_root_cause(root_cause)}
    return {"stats": vulnsmod.stats(), "vulns": vulnsmod.list_vulns()}


@mcp.tool()
@safe_tool
async def vuln_search(query: str) -> dict:
    """Search the server-side vulnerability catalog by keyword (name, category,
    root cause, real-world incident, tool).
    """

    return {"query": query, "results": vulnsmod.search(query)}


@mcp.tool()
@safe_tool
async def rootcause_info(root_cause: str | None = None) -> dict:
    """The ROOT-CAUSE TAXONOMY — the ~13 fundamental causes from which nearly all
    server-side vulnerabilities spring (code/data confusion, confused-deputy /
    trust-boundary violation, parser differential, broken authorization, insecure
    deserialization, state desync/race, insecure defaults, memory safety, crypto
    misuse, network-position abuse, supply-chain trust, implicit trust of client
    metadata, ambient authority). Pass a `root_cause` id for its full write-up —
    why it recurs, the systemic fix, and every catalog vuln that derives from it;
    omit for the list. No network — the conceptual centrepiece of the KB.
    """

    if root_cause:
        entry = vulnsmod.get_root_cause(root_cause)
        if entry is None:
            return {"error": "unknown_root_cause", "detail": f"No root cause '{root_cause}'",
                    "known": [r["id"] for r in vulnsmod.list_root_causes()]}
        return entry
    return {"root_causes": vulnsmod.list_root_causes()}


@mcp.tool()
@safe_tool
async def vuln_tools(tool: str | None = None, query: str | None = None) -> dict:
    """Catalog of server-side vulnerability tooling (sqlmap, ghauri, commix,
    tplmap/SSTImap, ysoserial, jwt_tool, XXEinjector, Gopherus, interactsh/OAST,
    Arjun/x8 param discovery, ffuf/feroxbuster, smuggler/Turbo Intruder, dalfox,
    GraphQLmap, wafw00f, …). Pass a `tool` id/name, a `query`, or omit for all.
    No network — pure reference.
    """

    if tool:
        entry = vulnsmod.get_tool(tool)
        if entry is None:
            return {"error": "unknown_tool", "detail": f"No tool '{tool}'",
                    "known": [t["id"] for t in vulnsmod.list_tools()]}
        return entry
    if query:
        return {"query": query, "results": vulnsmod.search_tools(query)}
    return {"count": len(vulnsmod.list_tools()), "tools": vulnsmod.list_tools()}


# ---------------------------------------------------------------------------
# knowledge base — WAF (how they work · fingerprints · bypass concepts)
# ---------------------------------------------------------------------------
@mcp.tool()
@safe_tool
async def waf_info(waf: str | None = None, category: str | None = None) -> dict:
    """WAF reference KB: how WAFs work (rule engines, models, cloud WAFs), vendor
    fingerprints, and conceptual/defensive bypass techniques (understanding
    evasion to detect & defend — normalization & parser differentials, encoding
    layers, HPP, origin-IP discovery, …). Pass a `waf` entry id for detail;
    filter by `category` (how-it-works / fingerprint / bypass-technique); or omit
    for the index + stats. Complements the active waf_detect tool. No network.
    """

    if waf:
        entry = wafkbmod.get_entry(waf)
        if entry is None:
            return {"error": "unknown_entry", "detail": f"No WAF entry '{waf}'"}
        return entry
    if category:
        return {"category": category, "results": wafkbmod.list_entries(category)}
    return {"stats": wafkbmod.stats(), "entries": wafkbmod.list_entries()}


@mcp.tool()
@safe_tool
async def identify_waf(text: str) -> dict:
    """Identify the WAF in front of a target from a raw HTTP response (paste the
    headers + body / blocking page). Scans the fingerprint indicators (cf-ray,
    __cfduid, x-akamai, incap_ses, awselb, BigIP, x-sucuri, …) and names the
    vendor. No network — pass it output from http_probe.
    """

    matches = wafkbmod.identify(text)
    return {"match_count": len(matches), "matches": matches}


