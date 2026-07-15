# Detection-accuracy benchmark

**"Does it actually work?"** — answered as a committed, re-runnable number rather
than a claim. This is the ground-truth complement to the live `metrics` tool (which
scores the findings store *after* an operator hand-labels each outcome).

## How it works

The test stand (`tests/conftest.py`) serves **paired endpoints** whose vulnerability
is known by construction — `/lfi-vuln` vs `/lfi-safe`, `/nosqli` vs `/nosqli-safe`,
`/interp-vuln` vs `/interp-safe`, `/parserdiff` vs `/parserdiff-safe`. The benchmark
(`tests/test_benchmark.py`) runs each probe against its vulnerable and safe target
(plus **cross-negatives** — a probe pointed at an unrelated benign endpoint), records
whether it fired, and feeds the results to the pure scorer (`moonmcp/bench.py`), which
derives the confusion matrix and the rates a detector lives or dies by:

| metric | definition |
|--------|------------|
| **precision** | TP / (TP + FP) — of the leads raised, how many were real |
| **recall** | TP / (TP + FN) — of the real bugs, how many were caught |
| **false-positive rate** | FP / (FP + TN) — how often a safe target is wrongly flagged |

A probe is counted as *fired* when it returns a `confirmed` / `likely` /
`corroborated` / `review` verdict.

## Current result

Across the four differential detectors on the controlled stand (10 cases: 4 known-
vulnerable, 6 known-safe incl. cross-negatives):

| probe | TP | FP | TN | FN | precision | recall | FP-rate |
|-------|----|----|----|----|-----------|--------|---------|
| `lfi_probe` | 1 | 0 | 2 | 0 | 1.0 | 1.0 | 0.0 |
| `interp_probe` | 1 | 0 | 1 | 0 | 1.0 | 1.0 | 0.0 |
| `nosqli_probe` | 1 | 0 | 2 | 0 | 1.0 | 1.0 | 0.0 |
| `parser_diff_probe` | 1 | 0 | 1 | 0 | 1.0 | 1.0 | 0.0 |
| **overall** | **4** | **0** | **6** | **0** | **1.0** | **1.0** | **0.0** |

Perfect separation on the controlled cases: every known-vulnerable target fired,
**no** safe or unrelated target did.

## What it is and isn't

- It **is** a reproducible regression gate: a probe that starts firing on a safe
  target trips the `false_positive_rate == 0.0` assertion in CI, so a precision
  regression fails the build.
- It is **not** a live bug-bounty success rate — controlled endpoints are cleaner
  than the wild. Real-world precision is measured separately with `label_finding` +
  the `metrics` tool as the operator labels leads during engagements.

## Extending it

Add a case to `_CASES` in `tests/test_benchmark.py`: `(label, tool, path, param,
is_vulnerable)`. Point it at an existing paired endpoint, or add a new
vuln/safe pair to `tests/conftest.py`. Re-run `pytest tests/test_benchmark.py` and
update the table above.
