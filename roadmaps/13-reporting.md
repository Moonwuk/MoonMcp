# Roadmap — Layer 13: Reporting

**Scope:** the output modules — Markdown + SARIF reports, Obsidian vault
export, in-memory findings store, CVSS scoring. A bug here is either a
fingerprint leak that defeats the `TOOL_NAME` fix, PII/secret leakage into
reports, or a schema/format issue.

**Modules:** `reporting.py`, `obsidian.py`, `findings.py`, `cvss.py
(~537 lines).

**Status as of 2026-07-27:** the `reporting.py` `TOOL_NAME` env var and the
`informationUri` emptying were fixed in the earlier pass. **Verified present.**
This roadmap covers what remains — and the audit found that the `obsidian.py`
export path **was missed** by the fix.

---

## Headline finding

**RP6 (HIGH): `obsidian.py` hardcodes "MoonMCP" in vault filenames, headings,
and tags — defeating the `TOOL_NAME` env override.** An operator who sets
`MOONMCP_TOOL_NAME=recon-tool` to hide the tool name in reports still leaks
"MoonMCP" in every Obsidian vault file name (`MoonMCP Home.md`,
`MoonMCP.canvas`), heading (`# MoonMCP graph report`), and frontmatter tag
(`moonmcp`). `obsidian.py` does not import `TOOL_NAME` from `reporting.py`.

This is the same class of issue as the UA leak fixed in the first pass — just
in the export path that was missed. Fix: import `TOOL_NAME` and use it
everywhere "MoonMCP" appears in `obsidian.py`.

---

## Module: `reporting.py` (141 lines) — Markdown + SARIF

**TOOL_NAME fix verified present** (line 16, used in SARIF driver.name line 75,
markdown title line 87, footer line 140). **`informationUri` emptied verified**
(line 76). Pure (no I/O, no clock) — trivially testable. Strengths.

**RP1 (LOW):** the `or "MoonMCP"` guard (line 16) collapses an explicitly-empty
env var back to "MoonMCP" — the comment says "or blank it" but you can't.
Correct for SARIF validity (driver.name must be non-empty), but the comment is
misleading. **RP2 (LOW):** `informationUri: ""` may fail strict SARIF uri-format
validation — should be conditionally omitted. **RP3 (MEDIUM):** no PII/secret
redaction in SARIF evidence (truncated 2000 chars) or markdown blockquote —
credentials/tokens captured in finding evidence flow into reports unredacted.
**RP4 (LOW):** SARIF rules lack CWE/CVE/helpUri metadata. **RP5 (LOW):**
markdown blockquote breaks on multi-line evidence.

## Module: `obsidian.py` (304 lines) — Obsidian vault export

Pure file generation, Graphify-style entity-relation graph, Canvas + NetworkX
node-link JSON, YAML frontmatter. Strengths.

**RP6 (HIGH):** hardcoded "MoonMCP" in `MoonMCP Home.md`, `MoonMCP.canvas`,
`# MoonMCP graph report`, `# MoonMCP — {engagement}`, `moonmcp` in all
frontmatter tags, `"generator": "moonmcp"` — does NOT import `TOOL_NAME`.
**RP7 (MEDIUM):** YAML frontmatter injection — `"` and `\` not escaped; a
title like `Found "admin" panel` produces invalid YAML. No `yaml.safe_dump`.
**RP8 (LOW):** evidence truncation inconsistent (4000 here vs 2000 in
reporting/findings).

## Module: `findings.py` (183 lines) — in-memory findings store

Bounded (`cap=2000`), dedup by type+target+title, systemic cross-target
clustering in `triage()`, outcome labeling. Strengths.

**RP9 (MEDIUM):** no PII/secret redaction in stored evidence — verbatim, only
truncated to 2000 in `dedupe()`. Credentials persist in the session store and
flow into all export paths unredacted. **RP10 (LOW):** no persistence (by
design) — findings lost on restart.

## Module: `cvss.py` (109 lines) — CVSS 3.1 base score

Official CVSS 3.1 formula including exact `Roundup`, Scope:Changed modified-
impact term, conservative defaults, pure/testable. Strengths.

**RP11 (LOW):** base score only — no temporal/environmental metrics.
**RP12 (LOW):** no CVSS 4.0 support.

---

## Reporting layer — prioritized backlog

| ID | Module | Finding | Severity | Effort |
|----|--------|---------|----------|--------|
| RP6 | obsidian | hardcoded "MoonMCP" in vault filenames/headings/tags — defeats TOOL_NAME | HIGH | M |
| RP3 | reporting | no PII/secret redaction in SARIF evidence + markdown | MEDIUM | M |
| RP7 | obsidian | YAML frontmatter injection — " and \ not escaped | MEDIUM | S |
| RP9 | findings | no PII/secret redaction in stored evidence | MEDIUM | M |
| RP1 | reporting | TOOL_NAME "blank it" comment misleading | LOW | S |
| RP2 | reporting | informationUri: "" may fail strict SARIF uri validation | LOW | S |
| RP4 | reporting | SARIF rules lack CWE/CVE/helpUri metadata | LOW | S |
| RP5 | reporting | markdown blockquote breaks on multi-line evidence | LOW | S |
| RP8 | obsidian | evidence truncation inconsistent (4000 vs 2000) | LOW | S |
| RP10 | findings | no persistence (by design, surprising) | LOW | M |
| RP11 | cvss | base score only — no temporal/environmental | LOW | M |
| RP12 | cvss | no CVSS 4.0 support | LOW | L |

---

## Recommended next actions (this layer)

1. **RP6 (obsidian TOOL_NAME)** — import `TOOL_NAME` from `reporting.py` and
   replace every "MoonMCP"/"moonmcp" literal. Closes the leak the 2026-07-27
   fix missed. ~30 min.
2. **RP3 + RP9 (PII redaction)** — a shared `_redact_evidence(text)` helper
   applied in `reporting.format_sarif`, `reporting.format_markdown`,
   `findings.add`. Reuse the `secrets.py` patterns. ~1 h.
3. **RP7 (YAML injection)** — switch `frontmatter()` to `yaml.safe_dump` or
   escape `"`/`\`. ~15 min.

The rest are LOW — batch.

---

## Verification

```bash
python3 -c "from moonmcp import reporting, obsidian, findings, cvss; print('OK')"
python3 -m pytest tests/test_reporting.py tests/test_batch_export.py tests/test_cvss.py -q
```