"""Tests for the Obsidian vault exporter."""

import json

import pytest

from moonmcp import obsidian as obs
from moonmcp import server as srv


def test_primitives():
    assert obs.wikilink("A") == "[[A]]"
    assert obs.wikilink("A", "B") == "[[A|B]]"
    fm = obs.frontmatter({"type": "finding", "tags": ["moonmcp", "sev/high"], "empty": ""})
    assert fm.startswith("---") and fm.endswith("---")
    assert "type: finding" in fm and "  - sev/high" in fm and "empty" not in fm
    assert obs.slug("SQLi on /orders!!") == "sqli-on-orders"


def test_build_vault_graph(tmp_path):
    root = str(tmp_path)
    findings = [
        {"id": 1, "target": "https://api.example.com/orders", "severity": "high",
         "title": "IDOR on orders", "type": "access-control", "detail": "user B reads A",
         "evidence": "HTTP 200", "created_at": "2026-07-09"},
    ]
    vulns = [{"id": "sqli", "name": "SQL Injection", "category": "sqli", "severity": "critical",
              "popularity": "common", "summary": "…", "root_cause": "code-data-confusion",
              "where_it_breaks": "string-built queries"}]
    root_causes = [{"id": "code-data-confusion", "name": "Code/Data Confusion",
                    "summary": "…", "why_it_recurs": "…", "systemic_fix": "parameterize",
                    "derived_vuln_classes": ["sqli"]}]
    man = obs.build_vault(root, engagement="acme", findings=findings, vulns=vulns,
                          root_causes=root_causes)
    files = set(man["manifest"])
    assert "MoonMCP Home.md" in files
    assert any(f.startswith("Findings/") for f in files)
    assert "Assets/api.example.com.md" in files
    assert "MoonMCP.canvas" in files
    # the vuln note wikilinks to its root cause (the "graphify" edge)
    vuln_note = (tmp_path / "Knowledge" / "Vulns" / "Vuln - sqli.md").read_text()
    assert "[[Root Cause - code-data-confusion|Code/Data Confusion]]" in vuln_note
    # the finding note links to its asset
    fnote = next(tmp_path.glob("Findings/*.md")).read_text()
    assert "[[api.example.com]]" in fnote and "#sev/high" not in fnote  # tag is in frontmatter list
    assert "sev/high" in fnote
    # canvas is valid JSON Canvas with nodes + edges
    canvas = json.loads((tmp_path / "MoonMCP.canvas").read_text())
    assert canvas["nodes"] and canvas["edges"]
    assert all("id" in n and "type" in n for n in canvas["nodes"])
    assert all({"fromNode", "toNode"} <= set(e) for e in canvas["edges"])
    # Graphify-style graph.json (NetworkX node-link) with provenance-tagged edges
    assert "graph.json" in files and "GRAPH_REPORT.md" in files
    graph = json.loads((tmp_path / "graph.json").read_text())
    assert graph["directed"] is True and graph["nodes"]
    assert any(n["type"] == "vuln" for n in graph["nodes"])
    assert any(e["relation"] == "derives_from" and e["provenance"] == "EXTRACTED"
               for e in graph["links"])
    assert man["graph_edges"] >= 1


@pytest.mark.asyncio
async def test_export_obsidian_tool(tmp_path, fresh_context):
    assert "export_obsidian" in {t.name for t in await srv.mcp.list_tools()}
    await srv.add_finding(target="example.com", severity="critical",
                          title="SQLi in id", type="sqli", detail="boolean-blind")
    out = await srv.export_obsidian(out_dir=str(tmp_path), include_kb=True, engagement="acme")
    assert out["findings"] == 1 and out["files_written"] > 1
    # with the KB included, the root-cause graph notes exist
    assert (tmp_path / "MoonMCP Home.md").exists()
    assert list(tmp_path.glob("Knowledge/Root Causes/*.md"))
    await srv.clear_findings()
