# MoonMCP → Obsidian (graphify your recon)

`export_obsidian` turns a MoonMCP session into an [Obsidian](https://obsidian.md)
vault you can open and explore as a **graph** — the attack surface and the
vulnerability→root-cause relationships become a web of linked notes.

## What it writes

```
<vault>/
  MoonMCP Home.md              # Map-of-Content hub (engagement overview)
  Assets/<host>.md             # one note per asset, lists its findings
  Findings/Finding <id> …​.md    # one note per finding (severity-tagged, links to asset + class)
  Knowledge/
    Root Causes/Root Cause - <id>.md
    Vulns/Vuln - <id>.md       # each [[wikilinks]] to its root cause
    Injections/Injection - <id>.md
    Techniques/Technique - <id>.md
  MoonMCP.canvas               # Obsidian Canvas (JSON Canvas 1.0) visual graph
  graph.json                   # Graphify-style NetworkX node-link graph
  GRAPH_REPORT.md              # "god nodes" (most-connected entities)
```

Open the folder as a vault → **Graph view** renders it. Relations are encoded as
`[[wikilinks]]` in note **bodies** (Obsidian only builds graph edges from body
links, not frontmatter), so `finding → asset`, `vuln → root cause`, etc. show up
as edges and produce automatic backlinks for bidirectional pivoting. Notes carry
YAML frontmatter properties and `#tags` (`#sev/critical`, `#kb/…`) so the graph
can be coloured/filtered.

## "Graphify"

[Graphify](https://github.com/safishamsi/graphify) is an open-source skill that
turns a folder into a queryable knowledge graph and is commonly paired with an
Obsidian vault + Claude Code as a "second brain". MoonMCP mirrors its output: the
exporter emits a **`graph.json`** (NetworkX node-link format) with typed nodes
(`asset`, `finding`, `vuln`, `root-cause`, `injection`, `technique`) and
**provenance-tagged edges** (`EXTRACTED` for observed relations vs `INFERRED`),
plus a `GRAPH_REPORT.md` surfacing the most-connected "god nodes" — so you can
graphify the recon dataset and feed the same graph back to an AI agent.

## Usage

```
export_obsidian(out_dir="~/vaults/acme", include_kb=true, engagement="acme")
```

- `out_dir` — where to write (or `MOONMCP_VAULT_DIR`, else `./moonmcp-vault`).
- `include_kb` — also export the knowledge bases as a linked graph (vuln↔root-cause).
- `canvas` — also emit the `.canvas` visual graph (default on).

Pure file generation — no plugins or network required. For a live two-way sync
you can additionally use the community **Local REST API** / **obsidian-mcp**
servers; MoonMCP just writes the vault.
