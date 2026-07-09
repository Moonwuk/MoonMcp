"""Export the session's recon data + knowledge bases into an Obsidian vault.

"Graphify" the engagement: turn findings, assets and the knowledge bases into a
web of linked Markdown notes so Obsidian's **graph view** renders the attack
surface and the vuln→root-cause relationships as a navigable graph — plus an
Obsidian **Canvas** (`.canvas`, JSON Canvas 1.0) for an explicit visual layout.

Pure file generation — no external dependencies, no network.  Notes use YAML
frontmatter (properties), `#tags` and `[[wikilinks]]`; Obsidian builds the graph
from the links automatically.
"""

from __future__ import annotations

import json
import os
import re

_SLUG = re.compile(r"[^a-z0-9]+")
_SEV_COLOR = {"critical": "1", "high": "2", "medium": "3", "low": "5", "info": "6"}


def slug(text: str, maxlen: int = 60) -> str:
    s = _SLUG.sub("-", str(text).strip().lower()).strip("-")
    return (s[:maxlen] or "note").strip("-")


def _safe_filename(name: str) -> str:
    # keep it readable but filesystem/Obsidian-safe (no path separators)
    return re.sub(r'[\\/:*?"<>|]+', "-", str(name)).strip() or "note"


def frontmatter(props: dict) -> str:
    """A YAML frontmatter block (Obsidian properties)."""

    lines = ["---"]
    for k, v in props.items():
        if v is None or v == "":
            continue
        if isinstance(v, (list, tuple)):
            vals = [str(x) for x in v if str(x).strip()]
            if not vals:
                continue
            lines.append(f"{k}:")
            lines.extend(f"  - {x}" for x in vals)
        else:
            sv = str(v).replace("\n", " ")
            lines.append(f'{k}: "{sv}"' if (":" in sv or "#" in sv) else f"{k}: {sv}")
    lines.append("---")
    return "\n".join(lines)


def wikilink(name: str, alias: str | None = None) -> str:
    return f"[[{name}|{alias}]]" if alias else f"[[{name}]]"


class Vault:
    """Writes notes under a root directory and tracks what was written."""

    def __init__(self, root: str) -> None:
        self.root = root
        self.written: list[str] = []

    def write(self, rel_path: str, content: str) -> None:
        full = os.path.join(self.root, rel_path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as fh:
            fh.write(content.rstrip() + "\n")
        self.written.append(rel_path)


def _canvas(nodes: list[dict], edges: list[dict]) -> str:
    return json.dumps({"nodes": nodes, "edges": edges}, indent=2)


def _host_of(target: str) -> str:
    t = str(target).strip()
    if "://" in t:
        from urllib.parse import urlsplit
        t = urlsplit(t).hostname or t
    return t.split("/")[0].split(":")[0].strip().lower() or "unknown-asset"


def build_vault(
    root: str,
    *,
    engagement: str = "engagement",
    findings: list[dict] | None = None,
    injections: list[dict] | None = None,
    vulns: list[dict] | None = None,
    root_causes: list[dict] | None = None,
    techniques: list[dict] | None = None,
    want_canvas: bool = True,
) -> dict:
    """Render an Obsidian vault at *root*; return a manifest of what was written."""

    findings = findings or []
    vault = Vault(root)

    # --- Findings + Assets ------------------------------------------------
    assets: dict[str, list[str]] = {}
    finding_note_names: list[tuple[str, str]] = []  # (note_name, severity)
    for f in findings:
        host = _host_of(f.get("target", ""))
        sev = str(f.get("severity", "info")).lower()
        title = f.get("title") or f.get("type") or "finding"
        note_name = _safe_filename(f"Finding {f.get('id', '')} - {slug(title)}")
        assets.setdefault(host, []).append(note_name)
        finding_note_names.append((note_name, sev))
        ftype = str(f.get("type", "")).strip().lower()
        # link a finding to the KB note that explains its class, if we have one
        kb_link = ""
        if injections and any(i["id"] == ftype for i in injections):
            kb_link = wikilink(f"Injection - {ftype}")
        elif vulns and any(v["id"] == ftype for v in vulns):
            kb_link = wikilink(f"Vuln - {ftype}")
        elif techniques and any(t["id"] == ftype for t in techniques):
            kb_link = wikilink(f"Technique - {ftype}")
        fm = frontmatter({"type": "finding", "severity": sev, "asset": host,
                          "finding_type": ftype, "created": f.get("created_at"),
                          "tags": ["moonmcp", "finding", f"sev/{sev}"]})
        body = [fm, "", f"# {title}", "", f"**Asset:** {wikilink(host)}",
                f"**Severity:** {sev}"]
        if kb_link:
            body.append(f"**Class:** {kb_link}")
        if f.get("detail"):
            body += ["", "## Detail", str(f["detail"])]
        if f.get("evidence"):
            body += ["", "## Evidence", "```", str(f["evidence"])[:4000], "```"]
        vault.write(f"Findings/{note_name}.md", "\n".join(body))

    for host, notes in assets.items():
        fm = frontmatter({"type": "asset", "host": host,
                          "tags": ["moonmcp", "asset"]})
        body = [fm, "", f"# {host}", "", "## Findings",
                *[f"- {wikilink(n)}" for n in notes]]
        vault.write(f"Assets/{_safe_filename(host)}.md", "\n".join(body))

    # --- Knowledge graph (the vuln → root-cause web is the showcase) -------
    for rc in (root_causes or []):
        fm = frontmatter({"type": "root-cause", "id": rc["id"],
                          "tags": ["moonmcp", "kb", "root-cause"]})
        body = [fm, "", f"# {rc.get('name', rc['id'])}", "", rc.get("summary", "")]
        if rc.get("why_it_recurs"):
            body += ["", "## Why it recurs", rc["why_it_recurs"]]
        if rc.get("systemic_fix"):
            body += ["", "## Systemic fix", rc["systemic_fix"]]
        if rc.get("derived_vuln_classes"):
            body += ["", "## Spawns", *[f"- {c}" for c in rc["derived_vuln_classes"]]]
        vault.write(f"Knowledge/Root Causes/Root Cause - {_safe_filename(rc['id'])}.md",
                    "\n".join(body))

    rc_names = {rc["id"]: rc.get("name", rc["id"]) for rc in (root_causes or [])}
    for v in (vulns or []):
        rc_id = v.get("root_cause")
        fm = frontmatter({"type": "vuln", "id": v["id"], "category": v.get("category"),
                          "severity": v.get("severity"), "popularity": v.get("popularity"),
                          "root_cause": rc_id,
                          "tags": ["moonmcp", "kb", "vuln", f"cat/{v.get('category', 'other')}"]})
        body = [fm, "", f"# {v.get('name', v['id'])}", "", v.get("summary", "")]
        if rc_id and rc_id in rc_names:
            body += ["", f"**Root cause:** {wikilink(f'Root Cause - {rc_id}', rc_names[rc_id])}"]
        if v.get("where_it_breaks"):
            body += ["", "## Where it breaks", v["where_it_breaks"]]
        vault.write(f"Knowledge/Vulns/Vuln - {_safe_filename(v['id'])}.md", "\n".join(body))

    for i in (injections or []):
        fm = frontmatter({"type": "injection", "id": i["id"], "severity": i.get("severity"),
                          "cwe": i.get("cwe", []),
                          "tags": ["moonmcp", "kb", "injection"]})
        body = [fm, "", f"# {i.get('name', i['id'])}", "", i.get("summary", "")]
        vault.write(f"Knowledge/Injections/Injection - {_safe_filename(i['id'])}.md",
                    "\n".join(body))

    for t in (techniques or []):
        fm = frontmatter({"type": "technique", "id": t["id"], "category": t.get("category"),
                          "severity": t.get("severity"), "languages": t.get("languages", []),
                          "tags": ["moonmcp", "kb", "technique"]})
        body = [fm, "", f"# {t.get('name', t['id'])}", "", t.get("summary", "")]
        vault.write(f"Knowledge/Techniques/Technique - {_safe_filename(t['id'])}.md",
                    "\n".join(body))

    # --- Home MOC ---------------------------------------------------------
    home = [frontmatter({"type": "moc", "engagement": engagement,
                         "tags": ["moonmcp", "moc"]}),
            "", f"# MoonMCP — {engagement}", "",
            f"Findings: **{len(findings)}** · Assets: **{len(assets)}**", ""]
    if assets:
        home += ["## Assets", *[f"- {wikilink(h)}" for h in sorted(assets)], ""]
    if findings:
        home += ["## Findings",
                 *[f"- {wikilink(n)} ({s})" for n, s in finding_note_names], ""]
    kb_counts = {"Injections": len(injections or []), "Vulns": len(vulns or []),
                 "Root Causes": len(root_causes or []), "Techniques": len(techniques or [])}
    if any(kb_counts.values()):
        home += ["## Knowledge base",
                 *[f"- {k}: {n}" for k, n in kb_counts.items() if n], ""]
    vault.write("MoonMCP Home.md", "\n".join(home))

    # --- Canvas graph -----------------------------------------------------
    if want_canvas:
        nodes: list[dict] = []
        edges: list[dict] = []
        nodes.append({"id": "home", "type": "text", "text": f"# {engagement}",
                      "x": -300, "y": 0, "width": 260, "height": 80, "color": "4"})
        y = -200 * max(1, len(assets)) // 2
        for host, fnotes in list(assets.items())[:40]:
            aid = f"asset-{slug(host)}"
            nodes.append({"id": aid, "type": "file", "file": f"Assets/{_safe_filename(host)}.md",
                          "x": 100, "y": y, "width": 260, "height": 90})
            edges.append({"id": f"e-home-{aid}", "fromNode": "home", "toNode": aid})
            fy = y
            for note_name in fnotes[:8]:
                nid = f"f-{slug(note_name)}"
                sev = next((s for n, s in finding_note_names if n == note_name), "info")
                nodes.append({"id": nid, "type": "file", "file": f"Findings/{note_name}.md",
                              "x": 460, "y": fy, "width": 300, "height": 90,
                              "color": _SEV_COLOR.get(sev, "6")})
                edges.append({"id": f"e-{aid}-{nid}", "fromNode": aid, "toNode": nid})
                fy += 120
            y += max(200, 120 * (len(fnotes[:8]) + 1))
        vault.write("MoonMCP.canvas", _canvas(nodes, edges))

    return {"root": root, "files_written": len(vault.written),
            "assets": len(assets), "findings": len(findings),
            "manifest": vault.written[:500]}
