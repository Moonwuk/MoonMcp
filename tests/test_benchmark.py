"""Detection-accuracy benchmark — probes vs the controlled vuln/safe test stand.

Turns the paired ``*-vuln`` / ``*-safe`` endpoints into a reproducible precision /
recall / false-positive-rate scorecard, and gates against regressions: a probe that
starts firing on a safe target trips the false-positive assertion.
"""

import pytest

from moonmcp import bench
from moonmcp import server as srv

# A probe "fired" if it raised a lead the agent would act on.
_POSITIVE = {"confirmed", "likely", "corroborated", "review"}


def _fired(res: dict) -> bool:
    v = res.get("verdict")
    return (v in _POSITIVE) if v is not None else bool(res.get("findings"))


# (probe label, tool, path, param, is_vulnerable)
_CASES = [
    ("lfi_probe", srv.lfi_probe, "/lfi-vuln", "q", True),
    ("lfi_probe", srv.lfi_probe, "/lfi-safe", "q", False),
    ("interp_probe", srv.interp_probe, "/interp-vuln", "q", True),
    ("interp_probe", srv.interp_probe, "/interp-safe", "q", False),
    ("nosqli_probe", srv.nosqli_probe, "/nosqli", "user", True),
    ("nosqli_probe", srv.nosqli_probe, "/nosqli-safe", "user", False),
    ("parser_diff_probe", srv.parser_diff_probe, "/parserdiff", "p", True),
    ("parser_diff_probe", srv.parser_diff_probe, "/parserdiff-safe", "p", False),
    # cross-negatives: a probe pointed at an UNRELATED benign endpoint must stay quiet
    ("lfi_probe", srv.lfi_probe, "/nosqli-safe", "user", False),
    ("nosqli_probe", srv.nosqli_probe, "/lfi-safe", "q", False),
]


# -- pure scorer -------------------------------------------------------------
def test_score_confusion_and_rates():
    results = [
        {"probe": "p", "vulnerable": True, "fired": True},    # TP
        {"probe": "p", "vulnerable": True, "fired": False},   # FN
        {"probe": "p", "vulnerable": False, "fired": True},   # FP
        {"probe": "p", "vulnerable": False, "fired": False},  # TN
    ]
    o = bench.score(results)["overall"]
    assert (o["tp"], o["fn"], o["fp"], o["tn"]) == (1, 1, 1, 1)
    assert o["precision"] == 0.5
    assert o["recall"] == 0.5
    assert o["false_positive_rate"] == 0.5
    assert o["accuracy"] == 0.5


def test_score_per_probe_and_empty_rates():
    results = [
        {"probe": "a", "vulnerable": True, "fired": True},
        {"probe": "b", "vulnerable": False, "fired": False},
    ]
    card = bench.score(results)
    assert card["per_probe"]["a"]["precision"] == 1.0
    # b has no positives at all → precision/recall undefined (None), not a crash
    assert card["per_probe"]["b"]["precision"] is None
    assert card["per_probe"]["b"]["false_positive_rate"] == 0.0


# -- e2e benchmark against the ground-truth stand ----------------------------
@pytest.mark.asyncio
async def test_detection_benchmark_scorecard(local_server, fresh_context):
    base, _ = local_server
    results = []
    for label, fn, path, param, vuln in _CASES:
        res = await fn(target=f"{base}{path}", param=param)
        results.append({"probe": label, "vulnerable": vuln, "fired": _fired(res)})

    card = bench.score(results)
    o = card["overall"]
    # The detectors must separate known-vuln from known-safe on the controlled stand.
    assert o["recall"] == 1.0, card               # every known-vuln case fired
    assert o["false_positive_rate"] == 0.0, card  # no safe/unrelated case fired
    assert o["precision"] == 1.0, card
    # per-probe: each probe scored at least one vuln and one safe case
    for probe in ("lfi_probe", "interp_probe", "nosqli_probe", "parser_diff_probe"):
        assert card["per_probe"][probe]["tp"] >= 1, (probe, card)
        assert card["per_probe"][probe]["fp"] == 0, (probe, card)
