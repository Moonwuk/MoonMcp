"""Detection metrics: compute_metrics + label_finding / metrics tools."""

import pytest

from moonmcp import metrics as mx
from moonmcp import server as srv
from moonmcp.findings import Finding


def _f(fid, **kw):
    return Finding(id=fid, target=kw.get("target", "x.test"), severity=kw.get("severity", "medium"),
                   title=kw.get("title", f"t{fid}"), type=kw.get("type", "lead"),
                   source=kw.get("source", "authz_probe"), outcome=kw.get("outcome", ""))


# -- pure compute_metrics ---------------------------------------------------
def test_compute_metrics_aggregates_and_precision():
    findings = [
        _f(1, source="authz_probe", outcome="true_positive", severity="high"),
        _f(2, source="authz_probe", outcome="false_positive"),
        _f(3, source="value_probe", outcome="true_positive"),
        _f(4, source="value_probe", outcome=""),                 # unlabelled
    ]
    m = mx.compute_metrics(findings, runs={"authz_probe": 5, "value_probe": 3})
    assert m["total_findings"] == 4
    assert m["by_source"]["authz_probe"] == 2
    assert m["by_outcome"]["true_positive"] == 2 and m["by_outcome"]["unlabelled"] == 1
    # overall precision = 2 TP / (2 TP + 1 FP) = 0.667
    assert m["precision"] == 0.667 and m["labelled"] == 3
    assert m["precision_by_source"]["authz_probe"] == 0.5       # 1 TP / (1 TP + 1 FP)
    assert m["precision_by_source"]["value_probe"] == 1.0       # 1 TP / (1 TP + 0 FP)
    assert m["total_runs"] == 8


def test_compute_metrics_precision_none_when_unlabelled():
    m = mx.compute_metrics([_f(1), _f(2)])
    assert m["precision"] is None and m["labelled"] == 0
    assert "tool_runs" not in m           # runs omitted when not provided


def test_compute_metrics_recall_with_known_positives():
    findings = [_f(1, outcome="true_positive"), _f(2, outcome="true_positive"),
                _f(3, outcome="false_positive")]
    m = mx.compute_metrics(findings, known_positives=4)
    assert m["recall"] == 0.5 and m["known_positives"] == 4     # 2 TP / 4 known


# -- tools ------------------------------------------------------------------
@pytest.mark.asyncio
async def test_label_finding_and_metrics_tools(fresh_context):
    from moonmcp.server import get_context
    ctx = get_context()
    f1 = ctx.findings.add(target="x.test", severity="high", title="BOLA on /orders",
                          type="lead", source="authz_probe")
    f2 = ctx.findings.add(target="x.test", severity="low", title="noise", type="lead",
                          source="authz_probe")
    assert (await srv.label_finding(f1.id, "true_positive"))["labelled"]["outcome"] == "true_positive"
    await srv.label_finding(f2.id, "false_positive")
    # an out-of-range value is coerced to 'unknown', and a missing id errors
    assert (await srv.label_finding(f1.id, "bogus"))["labelled"]["outcome"] == "unknown"
    assert "error" in await srv.label_finding(999999, "true_positive")

    # relabel f1 back to TP for the metric
    await srv.label_finding(f1.id, "true_positive")
    m = await srv.metrics()
    assert m["total_findings"] == 2
    assert m["precision_by_source"]["authz_probe"] == 0.5       # 1 TP / (1 TP + 1 FP)


@pytest.mark.asyncio
async def test_metrics_tools_registered():
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert {"label_finding", "metrics"} <= tools
