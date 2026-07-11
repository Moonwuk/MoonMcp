"""Detection metrics — measure probe precision on real targets.

MoonMCP's edge probes emit ``review`` leads; the honest question is how many of them
are real. This turns the findings store into a live scorecard: aggregate what was
recorded (by type / severity / source tool), and — once the operator labels outcomes
with ``label_finding`` — compute **precision** overall and per source tool / per lead
kind. Recall needs a known ground-truth denominator, so it's only reported when the
operator supplies the number of *known* real bugs (`known_positives`).

Pure functions over a list of ``Finding``-like objects (anything with the same
attributes); the ``metrics`` tool feeds it the live store.
"""

from __future__ import annotations

from collections.abc import Iterable


def _get(f, attr: str, default=""):
    return getattr(f, attr, default) if not isinstance(f, dict) else f.get(attr, default)


def _precision(tp: int, fp: int) -> float | None:
    """TP / (TP + FP); None when nothing has been labelled either way."""

    return round(tp / (tp + fp), 3) if (tp + fp) else None


def compute_metrics(findings: Iterable, *, runs: dict[str, int] | None = None,
                    known_positives: int | None = None) -> dict:
    """Aggregate findings into a detection scorecard.

    ``runs`` (optional) = tool-name → invocation count. ``known_positives`` (optional)
    = the operator's count of real bugs on the target, enabling a recall figure.
    """

    items = list(findings)
    by_type: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    by_source: dict[str, int] = {}
    by_outcome: dict[str, int] = {}
    # per-source TP/FP for precision-by-tool.
    src_tp: dict[str, int] = {}
    src_fp: dict[str, int] = {}

    for f in items:
        by_type[_get(f, "type") or "?"] = by_type.get(_get(f, "type") or "?", 0) + 1
        by_severity[_get(f, "severity") or "?"] = by_severity.get(_get(f, "severity") or "?", 0) + 1
        src = _get(f, "source") or "?"
        by_source[src] = by_source.get(src, 0) + 1
        oc = _get(f, "outcome") or "unlabelled"
        by_outcome[oc] = by_outcome.get(oc, 0) + 1
        if oc == "true_positive":
            src_tp[src] = src_tp.get(src, 0) + 1
        elif oc == "false_positive":
            src_fp[src] = src_fp.get(src, 0) + 1

    tp = by_outcome.get("true_positive", 0)
    fp = by_outcome.get("false_positive", 0)
    labelled = tp + fp
    precision_by_source = {
        s: _precision(src_tp.get(s, 0), src_fp.get(s, 0))
        for s in sorted(set(src_tp) | set(src_fp))
    }

    out: dict = {
        "total_findings": len(items),
        "by_type": by_type,
        "by_severity": by_severity,
        "by_source": by_source,
        "by_outcome": by_outcome,
        "labelled": labelled,
        "precision": _precision(tp, fp),
        "precision_by_source": precision_by_source,
        "note": ("precision = true_positive / (true_positive + false_positive) over labelled "
                 "findings; label outcomes with label_finding to grow the sample"),
    }
    if runs:
        out["tool_runs"] = dict(sorted(runs.items(), key=lambda kv: -kv[1]))
        out["total_runs"] = sum(runs.values())
    if known_positives is not None and known_positives > 0:
        out["recall"] = round(tp / known_positives, 3)
        out["known_positives"] = known_positives
    return out
