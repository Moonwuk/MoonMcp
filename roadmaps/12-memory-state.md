# Roadmap — Layer 12: Memory / State

**Scope:** the persistence and statefulness modules — shared memory hub,
audit trail, lead classification, confirmation scoring, metrics, live console,
snapshot monitor. A bug here is either a concurrency bottleneck, unbounded
growth, a trust-tag enforcement gap, or a silent routing failure.

**Modules:** `memory.py`, `audit.py`, `leadpipe.py`, `confirm.py`,
`metrics.py`, `live.py`, `monitor.py` (~1,113 lines).

**Status as of 2026-07-27:** no fixes in this layer yet.

---

## Headline findings

**MS1 (HIGH):** SQLite single-connection + single lock serializes all reads
and writes. No WAL mode — readers blocked during writes. Under the multi-agent
chain the architecture explicitly targets (orchestrator + Strix + curator
sharing `memory.db`), this is a bottleneck.

**MS2 (HIGH):** no VACUUM / `PRAGMA auto_vacuum`. Write-heavy upserts + FTS
shadow-table churn → unbounded DB bloat over a long engagement with no
reclamation path.

**MS9 (HIGH):** no rotation / size cap on `MOONMCP_AUDIT_LOG` JSONL file. The
in-memory ring is capped at 1000, but the file grows unbounded on disk.

**MS5 (MEDIUM):** trust-tag not enforced at retrieval. `brief()` and
`recent()` don't filter by trust → untrusted items surface alongside curated
in the operator-facing brief. An agent consuming `brief()` may act on untrusted
content as if curated. The guard is storage-level, not retrieval-level.

---

## Module: `memory.py` (405 lines) — SQLite + FTS memory hub

Trust/provenance on every item with safe `untrusted` default, curated-trust
sticky (never downgraded on upsert), FTS5-with-LIKE-fallback, dedup-on-signature
upsert, FTS delete-before-update. Strong design.

**MS1 (HIGH):** single-connection + single lock, no WAL. **MS2 (HIGH):** no
VACUUM. **MS3 (MEDIUM):** FTS `rebuild` runs on every construction (full scan
at startup). **MS4 (MEDIUM):** `clear(None)` FTS op has no try/except —
failure leaves index pointing at deleted rows. **MS5 (MEDIUM):** trust-tag not
enforced at retrieval. **MS6 (LOW):** `created_at` left blank — temporal
ordering impossible. **MS7 (LOW):** `brief()` host-substring match (`api`
matches `xapi.example.com`). **MS8 (LOW):** `graph()` fetches `limit*4` then
filters in Python — ignores the target index.

## Module: `audit.py` (90 lines) — audit trail

stderr-only logging (respects stdio MCP transport), bounded in-memory ring,
best-effort JSONL append. Strengths.

**MS9 (HIGH):** no file rotation/size cap — unbounded disk growth. **MS10
(MEDIUM):** append not atomic (no fsync) — crash can lose recent events,
breaking the evidentiary trail. **MS11 (LOW):** `recent(limit=0)` returns ALL
(surprising).

## Module: `leadpipe.py` (109 lines) — lead classification + routing

Honest "leads, not confirmations" framing, explicit `confirmed_when` per kind,
smuggling routed to Strix under human confirmation. Strengths.

**MS12 (MEDIUM):** unknown lead `kind` silently routes to generic `observe` —
no error, no log. Typo'd kinds fall through. **MS13 (LOW):** no startup
coverage check that probe-emitted kinds ⊆ `_ROUTES.keys()`.

## Module: `confirm.py` (56 lines) — differential confirmation scoring

Pure function, OAST callback is strongest signal (score 5), strong-confirmation
gate requires `oast OR (signature AND reflection)`. Strengths.

**MS14 (MEDIUM):** no signal for race-condition reproduction ("side-effect
>1×") — race leads have no scoring path through this gate. **MS15 (LOW):**
`timing_delta_ms > 3000` hardcoded magic number.

## Module: `metrics.py` (84 lines) — detection scorecard

Pure, handles TP/FP by source, recall gated on operator-supplied ground truth.
Strengths.

**MS16 (LOW):** no per-lead-kind precision (only per-source) — can't tell
which lead *class* is noisy. **MS17 (LOW):** `_get` collapses `0`/`None`/
missing to `""`.

## Module: `live.py` (270 lines) — live console window

Excellent shell-injection hygiene (`shlex.quote` everywhere), broad fallback
chain, never blocks/raises. Strengths.

**MS18 (LOW):** macOS AppleScript-escape-only on `do script` — defense-in-
depth gap. **MS19 (LOW):** fire-and-forget Popen with no PID tracking →
orphaned terminals.

## Module: `monitor.py` (99 lines) — snapshot diffing

Name sanitization prevents path traversal, first-call-establishes-baseline
semantics. Strengths.

**MS20 (MEDIUM):** non-atomic disk write (`open("w")`+dump, no temp+rename) —
crash → invalid JSON → next run silently re-baselines, swallows real diff.
**MS21 (LOW):** in-memory cache never invalidated by external file change.
**MS22 (LOW):** no snapshot count/size cap.

---

## Memory/state layer — prioritized backlog

| ID | Module | Finding | Severity | Effort |
|----|--------|---------|----------|--------|
| MS1 | memory | single-connection + single lock, no WAL — concurrency bottleneck | HIGH | M |
| MS2 | memory | no VACUUM/auto_vacuum — unbounded DB bloat | HIGH | S |
| MS9 | audit | no file rotation/size cap — unbounded disk growth | HIGH | S |
| MS3 | memory | FTS rebuild on every construction (full scan at startup) | MEDIUM | S |
| MS4 | memory | clear(None) FTS op no try/except — index can dangle | MEDIUM | S |
| MS5 | memory | trust-tag not enforced at retrieval — untrusted surfaces in brief() | MEDIUM | S |
| MS10 | audit | append not atomic — crash loses recent events | MEDIUM | S |
| MS12 | leadpipe | unknown lead kind silently routes to generic observe | MEDIUM | S |
| MS14 | confirm | no race-condition signal — race leads have no scoring path | MEDIUM | S |
| MS20 | monitor | non-atomic snapshot write — crash swallows real diff | MEDIUM | S |
| MS6 | memory | created_at left blank — temporal ordering impossible | LOW | S |
| MS7 | memory | brief() host-substring match — false positives | LOW | S |
| MS8 | memory | graph() fetches limit*4 then filters in Python | LOW | S |
| MS11 | audit | recent(0) returns ALL — surprising | LOW | S |
| MS13 | leadpipe | no startup coverage check on _ROUTES keys | LOW | S |
| MS15 | confirm | timing_delta_ms > 3000 hardcoded | LOW | S |
| MS16 | metrics | no per-lead-kind precision | LOW | S |
| MS17 | metrics | _get collapses 0/None/missing to "" | LOW | S |
| MS18 | live | macOS AppleScript-escape-only — defense-in-depth gap | LOW | S |
| MS19 | live | fire-and-forget Popen — orphaned terminals | LOW | S |
| MS21 | monitor | in-memory cache never invalidated by external change | LOW | S |
| MS22 | monitor | no snapshot count/size cap | LOW | S |

---

## Recommended next actions (this layer)

1. **MS2 + MS9 (quick wins)** — `PRAGMA auto_vacuum=INCREMENTAL` + a `vacuum()`
   method; wrap the audit file in a rotating handler with a size cap. ~30 min
   for both.
2. **MS5 (trust-tag at retrieval)** — `brief()`/`recent()` should default to
   `trust="curated"` unless the caller asks for untrusted. ~15 min.
3. **MS1 (WAL + connection split)** — the concurrency fix. `PRAGMA
   journal_mode=WAL` + a read connection + a write connection. ~2-3 h. Highest
   leverage for the multi-agent architecture.
4. **MS12 (leadpipe validation)** — error on unknown kind instead of silent
   default. ~10 min.

---

## Verification

```bash
python3 -c "from moonmcp import memory, audit, leadpipe, confirm, metrics, live, monitor; print('OK')"
python3 -m pytest tests/test_memory.py tests/test_leadpipe.py tests/test_confirm.py -q
```