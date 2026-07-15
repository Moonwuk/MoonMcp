"""Detection-accuracy benchmark scorer — turn controlled probe runs into a
reproducible precision / recall / false-positive-rate scorecard.

``metrics.py`` scores the LIVE findings store *after* an operator hand-labels each
outcome. This is the complementary, **ground-truth** half: run each probe against
controlled targets whose vulnerability is KNOWN (the paired ``*-vuln`` / ``*-safe``
endpoints on the test stand), derive the confusion matrix automatically, and report
precision, recall, and — the number a detector lives or dies by — the
**false-positive rate**. So "does it actually work" becomes a committed, re-runnable
figure and a regression gate (a probe that starts firing on a safe target trips the
FP-rate assertion), not a claim. Pure/offline.

A *result* is ``{"probe": str, "vulnerable": bool, "fired": bool}``:
``vulnerable`` is the ground truth, ``fired`` is whether the probe raised a lead.
"""

from __future__ import annotations

from collections.abc import Iterable


def _ratio(n: int, d: int) -> float | None:
    """``n/d`` rounded, or None when the denominator is 0 (nothing to divide)."""

    return round(n / d, 3) if d else None


def _confusion(rows: list[dict]) -> dict:
    tp = sum(1 for r in rows if r["vulnerable"] and r["fired"])
    fp = sum(1 for r in rows if not r["vulnerable"] and r["fired"])
    tn = sum(1 for r in rows if not r["vulnerable"] and not r["fired"])
    fn = sum(1 for r in rows if r["vulnerable"] and not r["fired"])
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    f1 = None
    if precision is not None and recall is not None and (precision + recall):
        f1 = round(2 * precision * recall / (precision + recall), 3)
    return {
        "cases": len(rows),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": precision,
        "recall": recall,
        "false_positive_rate": _ratio(fp, fp + tn),
        "accuracy": _ratio(tp + tn, tp + fp + tn + fn),
        "f1": f1,
    }


def score(results: Iterable[dict]) -> dict:
    """Score benchmark *results* into an overall + per-probe confusion scorecard
    (pure). Precision = TP/(TP+FP); recall = TP/(TP+FN); false_positive_rate =
    FP/(FP+TN). ``None`` where a rate has no samples yet."""

    rows = [
        {"probe": str(r.get("probe", "?")),
         "vulnerable": bool(r.get("vulnerable")),
         "fired": bool(r.get("fired"))}
        for r in results
    ]
    overall = _confusion(rows)
    probes = sorted({str(r["probe"]) for r in rows})
    per_probe = {p: _confusion([r for r in rows if r["probe"] == p]) for p in probes}
    return {"overall": overall, "per_probe": per_probe}
