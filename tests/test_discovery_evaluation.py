"""Independent labels, actual managed budgets and honest evaluation metrics."""
import copy
import json
import math
import socket

import pytest

from moonmcp import evaluation
from moonmcp._evaluation_fixture import CASES, Application, Case


@pytest.fixture(scope="module")
def measured():
    return evaluation.run_evaluation(trials=1)


def test_candidates_receive_no_evaluator_labels_and_reset_is_fresh():
    private, fixed = CASES[:2]
    a, b = Application(private, "first"), Application(private, "fresh")
    view = a.inputs()
    assert set(view) == {"target", "owner_headers", "second_headers", "proof"}
    encoded = json.dumps(view)
    for forbidden in ("vulnerable", "ground_truth", "root_cause", "held_out", "private-record-read"):
        assert forbidden not in encoded
    assert a.target != b.target
    assert a.inputs()["owner_headers"] != b.inputs()["owner_headers"]
    assert a.inputs()["proof"]["owner"] != b.inputs()["proof"]["owner"]
    assert a.secret != b.secret
    # Both expected implementations expose exactly the same candidate schema.
    assert set(Application(fixed, "first").inputs()) == set(view)


def test_all_expected_semantic_outcomes_and_costs_are_measured(measured):
    assert measured["passed"], measured["gates"]
    assert measured["version"] == 1
    rows = measured["trials"]
    assert len(rows) == len(CASES) * 2
    semantic = {r["case_id"]: r for r in rows if r["strategy"] == "semantic"}
    assert set(semantic) == {c.id for c in CASES}
    assert semantic["private"]["verified"] and semantic["denial-body-leak"]["verified"]
    for name in ("fixed", "public", "shared", "public-lookalike", "own-object-lookalike"):
        assert not semantic[name]["verified"]
    for name in ("expired", "missing-status", "truncated", "unstable", "budget-stop"):
        assert semantic[name]["observed_verdict"] == "inconclusive"
        assert not semantic[name]["completed"] and not semantic[name]["verified"]
    assert semantic["budget-stop"]["assessment_requests"] == 3
    assert semantic["budget-stop"]["blocked"]
    assert semantic["private"]["assessment_requests"] == 8
    assert semantic["private"]["replay_requests"] == 8
    assert semantic["private"]["requests"] == 16
    assert semantic["private"]["replay_verified"]
    assert all(r["requests"] == r["assessment_requests"] + r["replay_requests"] for r in rows)
    assert all(not r["safety_errors"] for r in rows)
    assert [row["strategy"] for row in rows[:4]] == ["heuristic", "semantic", "semantic", "heuristic"]
    metrics = measured["metrics"]["semantic"]["all"]
    assert metrics["positive_trials"] > metrics["true_verified_claims"]
    assert metrics["confirmation_trial_recall"]["denominator"] == metrics["positive_trials"]
    assert metrics["confirmation_cause_recall"]["denominator"] == 3
    assert metrics["confirmation_cause_recall"]["value"] == 1
    assert metrics["provider_cost"] is None and metrics["provider_usage"] is None


def test_heuristic_leads_are_not_relabelled_as_verified_proofs(measured):
    heuristic = {r["case_id"]: r for r in measured["trials"] if r["strategy"] == "heuristic"}
    assert heuristic["public-lookalike"]["lead"]
    assert not heuristic["denial-body-leak"]["lead"]
    assert not any(r["verified"] for r in heuristic.values())
    metrics = measured["metrics"]["heuristic"]["all"]
    assert metrics["verified_claims"] == 0
    assert metrics["verified_precision"]["value"] is None
    assert metrics["requests_per_verified_cause"] is None
    assert metrics["false_review_leads"] > 0
    assert measured["protocol"]["model"] is None


def test_report_is_redacted_versioned_and_uses_actual_source_hashes(measured):
    text = json.dumps(measured, allow_nan=False)
    for case in CASES:
        for generation in ("trial-0", "replay-0"):
            app = Application(case, generation)
            for value in (app.owner_token, app.observer_token, app.secret):
                assert value not in text
    assert len(measured["protocol_sha256"]) == 64
    sources = measured["provenance"]["source_sha256"]
    assert {"evaluation.py", "_evaluation_fixture.py", "execution.py", "web/bola_proof.py", "web/authz.py"} == set(sources)
    assert all(len(digest) == 64 for digest in sources.values())
    assert measured["provenance"]["python_version"]
    assert measured["provenance"]["dependencies"]["mcp"]
    assert any("no LLM" in value for value in measured["limitations"])


def test_forbidden_network_and_credentials_are_visible_gate_failures():
    app = Application(CASES[0], "network")
    with evaluation._session(app):
        with pytest.raises(AssertionError, match="prohibits"):
            socket.getaddrinfo("outside.invalid", 443)
        with pytest.raises(AssertionError, match="unexpected traffic"):
            app.transport("https://outside.invalid/object", "GET", {}, None)
        with pytest.raises(AssertionError, match="credential"):
            app.transport(app.target, "GET", {"Authorization": "Bearer foreign"}, None)
    assert app.safety_errors == ["real_network_attempt", "unexpected_destination_or_mutation", "unexpected_credential"]


def _row(**changes):
    result = {"case_id": "one", "split": "development", "strategy": "semantic", "trial": 0,
              "ground_truth": True, "root_cause": "one-cause", "lead": True, "verified": True,
              "completed": True, "blocked": False, "replay_attempted": True, "replay_verified": True,
              "requests": 16, "assessment_requests": 8, "replay_requests": 8,
              "tool_calls": 2, "elapsed_seconds": 1.5, "safety_errors": []}
    result.update(changes)
    return result


def test_metrics_keep_blocked_positives_and_deduplicate_root_causes():
    result = evaluation.summarize_trials([
        _row(),
        _row(case_id="second-url"),
        _row(case_id="blocked-positive", root_cause="unfound-cause", verified=False,
             lead=False, completed=False, blocked=True, replay_attempted=False, replay_verified=False,
             requests=3, assessment_requests=3, replay_requests=0, tool_calls=1),
        _row(case_id="false", ground_truth=False, root_cause=None),
    ])["semantic"]["all"]
    assert result["verified_precision"] == {"numerator": 2, "denominator": 3, "value": 2 / 3}
    assert result["confirmation_trial_recall"]["denominator"] == 3
    assert result["confirmation_cause_recall"] == {"numerator": 1, "denominator": 2, "value": .5}
    assert result["false_verified_claims"] == 1
    assert result["unfinished_trials"] == 1 and result["blocked_trials"] == 1
    assert result["requests"] == 51
    assert result["requests_per_verified_cause"] == 51


@pytest.mark.parametrize("change", [
    {"requests": True}, {"requests": -1}, {"elapsed_seconds": math.nan},
    {"elapsed_seconds": math.inf}, {"ground_truth": "true"}, {"root_cause": None},
    {"completed": False}, {"replay_attempted": False}, {"replay_requests": 9},
    {"split": "invented"}, {"strategy": "oracle"},
])
def test_invalid_trial_statistics_are_rejected(change):
    with pytest.raises(ValueError):
        evaluation.summarize_trials([_row(**change)])


def test_duplicate_trials_and_empty_denominators_are_explicit():
    with pytest.raises(ValueError, match="Duplicate"):
        evaluation.summarize_trials([_row(), copy.deepcopy(_row())])
    result = evaluation.summarize_trials([])["semantic"]["all"]
    assert result["trials"] == 0
    assert result["verified_precision"]["value"] is None
    assert result["confirmation_cause_recall"]["value"] is None
    assert result["fresh_replay"]["value"] is None


def test_failed_claims_and_safety_violations_fail_the_release_gate(monkeypatch):
    monkeypatch.setattr(evaluation, "CASES", (Case("safe-control"),))

    def false_candidate(case, generation, strategy):
        return {"verified": True, "completed": True, "lead": True, "blocked": False,
                "observed_verdict": "verified", "error": None, "requests": 1,
                "tool_calls": 1, "safety_errors": ["unexpected_destination"], "elapsed_seconds": .1}

    monkeypatch.setattr(evaluation, "_observe", false_candidate)
    report = evaluation.run_evaluation(trials=1)
    assert not report["passed"]
    assert not report["gates"]["no_false_verified_claims"]
    assert not report["gates"]["safety"]
    assert report["metrics"]["semantic"]["all"]["false_verified_claims"] == 1
    assert len(report["trials"]) == 2


@pytest.mark.parametrize("trials", [True, 0, -1, 21, 1.5])
def test_protocol_rejects_unbounded_trial_counts(trials):
    with pytest.raises(ValueError, match="trials"):
        evaluation.run_evaluation(trials=trials)
