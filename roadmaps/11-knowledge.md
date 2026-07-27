# Roadmap — Layer 11: Knowledge Base

**Scope:** the curated security knowledge bases — injections, techniques,
vulns + root-cause taxonomy, privesc, WAF. ~19,430 lines of data across 5
files, served to the agent via query APIs.

**Modules:** `__init__.py`, `injections.py` (+ `injections_data.py`),
`techniques.py` (+ `techniques_data.py`), `vulns.py` (+ `vulns_data.py`),
`privesc.py` (+ `privesc_data.py`), `waf_kb.py` (+ `waf_kb_data.py`).

**Status as of 2026-07-27:** no fixes in this layer yet. A known typo
(`implicit-trust-of-client-metadata` vs `implicit-trust-client-metadata`) was
found in `vulns_data.py` during test runs — it pre-exists the 2026-07-27 pass.

---

## Headline findings

**KB8 (HIGH):** the `vulns_data.py` typo. Two vulns (`postmessage-abuse`,
`mcp-protocol-vulns`) declare `root_cause: 'implicit-trust-of-client-metadata'`,
but the `ROOT_CAUSES` entry id is `'implicit-trust-client-metadata'` (no "of").
Result: 2 vulns are **orphaned from the root-cause taxonomy** —
`by_root_cause('implicit-trust-client-metadata')` returns 2 instead of 4, and
`get_root_cause` attaches only 2 derived vulns. The root-cause taxonomy is the
KB's "intellectual centre" per its own docstring, yet 2 of 50 vulns are silently
detached.

**KB9 (HIGH):** no FK integrity check. A one-line startup assertion
`{v['root_cause'] for v in SERVER_SIDE_VULNS} <= {r['id'] for r in ROOT_CAUSES}`
would have caught KB8 at import time. The join that broke has no guard.

**KB1/KB5/KB11/KB15 (all HIGH):** no `SCHEMA_VERSION` on any of the 5 data
files. Incompatible field additions break consumers silently. ~19k lines of
hand-maintained Python dicts with no validator and no version.

**KB2/KB6/KB10/KB12 (MEDIUM):** the maintainability core — ~19k lines of
hand-edited Python dicts across 5 files. A malformed regex is only caught at
first use. No CI validation. Merge-conflict-prone. Should be external YAML/JSON
+ loader.

---

## Per-module summary

| Module | Data file | Lines | Entries | Schema ver | Key strength |
|---|---|---|---|---|---|
| `injections.py` | `injections_data.py` | 6,418 | ~28 classes | none | `lru_cache` regexes, behavioral sigs excluded |
| `techniques.py` | `techniques_data.py` | 3,312 | ~114 | none | CVE-id fallback, severity-ranked |
| `vulns.py` | `vulns_data.py` | 2,595 | 50 + 13 root causes | none | root-cause taxonomy join |
| `privesc.py` | `privesc_data.py` | 6,419 | ~195 | none | `_is_signalish` anti-noise gate |
| `waf_kb.py` | `waf_kb_data.py` | 686 | ~31 | none | multi-match ranking |

Each loader is well-designed (`lru_cache`, graceful fallback, defensive
parsing). The problem is the **data layer**: no version, no validator, no
externalization.

---

## Knowledge layer — prioritized backlog

| ID | Module | Finding | Severity | Effort |
|----|--------|---------|----------|--------|
| KB8 | vulns_data | typo `implicit-trust-of-client-metadata` — 2 vulns orphaned from taxonomy | HIGH | S |
| KB9 | vulns | no FK integrity check — a one-line assertion would catch KB8 | HIGH | S |
| KB1 | injections_data | no SCHEMA_VERSION — incompatible field additions break consumers silently | HIGH | M |
| KB5 | techniques_data | no SCHEMA_VERSION | HIGH | M |
| KB11 | privesc_data | no SCHEMA_VERSION (largest file, 6,419 lines) | HIGH | M |
| KB15 | waf_kb_data | no SCHEMA_VERSION | HIGH | M |
| KB2 | injections | ~19k lines hand-maintained dicts, no validator — bad regex caught only at first use | MEDIUM | L |
| KB3 | injections | KB text reaches agent context with no prompt-injection scan; trust boundary implicit | MEDIUM | M |
| KB6 | techniques | same maintainability concern (3,312-line dict) | MEDIUM | L |
| KB10 | vulns | same; root-cause FK is most error-prone join | MEDIUM | L |
| KB12 | privesc | same (largest single dict, 6,419 lines) | MEDIUM | L |
| KB13 | privesc | match_enumeration substring match has no word-boundary anchoring | MEDIUM | S |
| KB16 | waf_kb | identify emits unbounded regex patterns per token (safe but uncapped) | MEDIUM | S |
| KB0 | __init__ | stale docstring — only mentions injection KB, not 5 sub-packages | LOW | S |
| KB4 | injections | search rebuilds haystack per call (no precomputed index) | LOW | S |
| KB7 | techniques | by_language substring match: `c` matches `c++`/`objc` | LOW | S |
| KB14 | privesc | _is_signalish rejects indicators >48 chars, silently dropping legit ones | LOW | S |
| KB17 | waf_kb | _distinctive_tokens keeps ≥6-char tokens with no distinctiveness marker | LOW | S |

---

## Recommended next actions (this layer)

1. **KB8 (typo fix)** — one-line: `implicit-trust-of-client-metadata` →
   `implicit-trust-client-metadata` in `vulns_data.py` (2 places). ~5 min.
2. **KB9 (FK assertion)** — one-line startup check in `vulns.py`. ~10 min.
3. **KB1/KB5/KB11/KB15 (schema version)** — add `SCHEMA_VERSION = 1` to each
   data file + a loader check. ~1 h for all 5.
4. **KB2/KB6/KB10/KB12 (externalize data)** — the big refactor. Move data to
   YAML/JSON + a loader + a CI schema validator. This is the highest-leverage
   long-term fix but a large effort (~L). Defer until the HIGHs are done.

---

## Verification

```bash
python3 -c "from moonmcp.knowledge import injections, techniques, vulns, privesc, waf_kb; print('OK')"
# The FK assertion (KB9, once added) would run at import and catch KB8.
python3 -m pytest tests/test_vulns.py tests/test_injections.py tests/test_waf_kb.py -q
```