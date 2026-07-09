"""Render a recon report dict into a readable Markdown document.

Kept pure (no I/O, no clock) so it is trivially testable; the server tool
gathers the data and passes a timestamp in.
"""

from __future__ import annotations

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEV_BADGE = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}


def _sev_key(f: dict) -> int:
    return _SEV_ORDER.get(str(f.get("severity", "info")).lower(), 5)


# SARIF severity → level mapping (SARIF only has error/warning/note).
_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
                "low": "note", "info": "note"}


def _slug(text: str) -> str:
    out = "".join(c if c.isalnum() else "-" for c in str(text).lower()).strip("-")
    while "--" in out:
        out = out.replace("--", "-")
    return out or "finding"


def format_sarif(findings: list[dict], *, version: str = "0.0.0") -> dict:
    """Render findings as a SARIF 2.1.0 document (for GitHub code-scanning, etc.).

    Pure — no I/O, no clock. ``findings`` are dicts as stored by FindingsStore.
    """

    rules: dict[str, dict] = {}
    results: list[dict] = []
    for f in findings:
        rule_id = _slug(f.get("type") or f.get("title") or "finding")
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id.replace("-", " ").title().replace(" ", ""),
                "shortDescription": {"text": str(f.get("type") or rule_id)},
            }
        sev = str(f.get("severity", "info")).lower()
        target = str(f.get("target") or "").strip()
        uri = target if "://" in target else (f"https://{target}" if target else "unknown")
        msg = str(f.get("title") or rule_id)
        if f.get("detail"):
            msg += f" — {f['detail']}"
        result = {
            "ruleId": rule_id,
            "level": _SARIF_LEVEL.get(sev, "note"),
            "message": {"text": msg},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
            "properties": {"severity": sev},
        }
        if f.get("evidence"):
            result["properties"]["evidence"] = str(f["evidence"])[:2000]
        results.append(result)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "MoonMCP",
                "informationUri": "https://github.com/Moonwuk/MoonMcp",
                "version": version,
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }


def format_markdown(report: dict, *, generated_at: str | None = None) -> str:
    target = report.get("target", "?")
    lines: list[str] = [f"# MoonMCP recon report — `{target}`", ""]
    if generated_at:
        lines.append(f"_Generated {generated_at}_")
        lines.append("")

    findings = sorted(report.get("findings", []), key=_sev_key)
    if findings:
        by_sev: dict[str, int] = {}
        for f in findings:
            by_sev[f.get("severity", "info")] = by_sev.get(f.get("severity", "info"), 0) + 1
        summary = ", ".join(f"{_SEV_BADGE.get(s, '')} {n} {s}"
                            for s, n in sorted(by_sev.items(), key=lambda kv: _SEV_ORDER.get(kv[0], 5)))
        lines += [f"**{len(findings)} finding(s):** {summary}", ""]

    # Attack surface
    surface = report.get("surface", {})
    if surface:
        lines += ["## Attack surface", ""]
        if "subdomains" in surface:
            lines.append(f"- **Subdomains:** {surface['subdomains']}")
        if surface.get("ips"):
            lines.append(f"- **IPs:** {', '.join(surface['ips'])}")
        if surface.get("technologies"):
            lines.append(f"- **Tech:** {', '.join(surface['technologies'])}")
        if surface.get("open_ports"):
            lines.append(f"- **Open ports:** {', '.join(str(p) for p in surface['open_ports'])}")
        lines.append("")

    # Posture grades
    grades = report.get("grades", {})
    if grades:
        lines += ["## Posture", "", "| Area | Grade |", "| --- | --- |"]
        for area, grade in grades.items():
            lines.append(f"| {area} | {grade} |")
        lines.append("")

    # Findings detail
    if findings:
        lines += ["## Findings", ""]
        for f in findings:
            sev = str(f.get("severity", "info")).lower()
            badge = _SEV_BADGE.get(sev, "")
            title = f.get("title", "finding")
            lines.append(f"### {badge} [{sev.upper()}] {title}")
            if f.get("detail"):
                lines.append(f"{f['detail']}")
            if f.get("evidence"):
                lines.append(f"> {f['evidence']}")
            lines.append("")

    if not findings and not surface and not grades:
        lines.append("_No data collected (target unreachable or out of scope)._")

    lines += ["---", "", "_MoonMCP — authorised testing only. Verify findings before reporting._"]
    return "\n".join(lines)
