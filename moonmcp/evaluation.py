"""Independent, socket-free private-read evaluation.

Run ``python -m moonmcp.evaluation --trials 5``. The old navigation benchmark
remains unchanged. This measures two deterministic workflows, never LLM skill,
third-party preparation or general vulnerability-discovery effectiveness.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib.metadata
import json
import math
import os
import platform
import socket
import subprocess
import time
from contextlib import ExitStack, contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from . import __version__
from ._evaluation_fixture import CASES, FIXTURE_VERSION, Application, Case

REPORT_VERSION = 1
STRATEGIES = ("heuristic", "semantic")


def _rate(numerator: int, denominator: int) -> dict:
    return {"numerator": numerator, "denominator": denominator,
            "value": numerator / denominator if denominator else None}


def summarize_trials(trials: list[dict]) -> dict:
    """Aggregate evaluator-owned labels; incomplete positive trials stay counted."""
    seen = set()
    for row in trials:
        key = (row["strategy"], row["case_id"], row["trial"])
        if key in seen:
            raise ValueError("Duplicate strategy/case/trial record")
        seen.add(key)
        if row["strategy"] not in STRATEGIES or row["split"] not in {"development", "held_out"}:
            raise ValueError("Unsupported evaluation strategy or split")
        for field in ("trial", "requests", "tool_calls", "assessment_requests", "replay_requests"):
            value = row[field]
            if type(value) is not int or value < 0:
                raise ValueError(f"{field} must be a non-negative integer")
        for field in ("ground_truth", "lead", "verified", "completed", "blocked", "replay_attempted", "replay_verified"):
            if type(row[field]) is not bool:
                raise ValueError(f"{field} must be a boolean")
        if row["ground_truth"] and not row["root_cause"]:
            raise ValueError("Positive ground truth requires an adjudicated root cause")
        if row["verified"] and not row["completed"]:
            raise ValueError("Incomplete evidence cannot be a verified claim")
        if row["replay_verified"] and not row["replay_attempted"]:
            raise ValueError("Replay verification requires a fresh replay")
        if (not isinstance(row["elapsed_seconds"], (int, float))
                or isinstance(row["elapsed_seconds"], bool)
                or not math.isfinite(row["elapsed_seconds"]) or row["elapsed_seconds"] < 0):
            raise ValueError("Elapsed time must be finite and non-negative")
        if row["requests"] != row["assessment_requests"] + row["replay_requests"]:
            raise ValueError("Assessment and replay sends must reconcile")

    def summary(rows: list[dict]) -> dict:
        positive = [r for r in rows if r["ground_truth"]]
        claims = [r for r in rows if r["verified"]]
        true = [r for r in claims if r["ground_truth"]]
        leads = [r for r in rows if r["lead"]]
        true_leads = [r for r in leads if r["ground_truth"]]
        causes = {r["root_cause"] for r in positive}
        found_causes = {r["root_cause"] for r in true}
        lead_causes = {r["root_cause"] for r in true_leads}
        sends = sum(r["requests"] for r in rows)
        elapsed = sum(r["elapsed_seconds"] for r in rows)
        return {
            "trials": len(rows), "positive_trials": len(positive),
            "safe_trials": len(rows) - len(positive),
            "verified_claims": len(claims), "true_verified_claims": len(true),
            "false_verified_claims": len(claims) - len(true),
            "review_leads": len(leads), "false_review_leads": len(leads) - len(true_leads),
            "unfinished_trials": sum(not r["completed"] for r in rows),
            "blocked_trials": sum(r["blocked"] for r in rows),
            "verified_precision": _rate(len(true), len(claims)),
            "confirmation_trial_recall": _rate(len(true), len(positive)),
            "lead_trial_recall": _rate(len(true_leads), len(positive)),
            "confirmation_cause_recall": _rate(len(found_causes), len(causes)),
            "discovery_lead_cause_recall": _rate(len(lead_causes), len(causes)),
            "ground_truth_causes": sorted(causes), "verified_causes": sorted(found_causes),
            "fresh_replay": _rate(sum(r["replay_verified"] for r in claims), len(claims)),
            "requests": sends, "assessment_requests": sum(r["assessment_requests"] for r in rows),
            "replay_requests": sum(r["replay_requests"] for r in rows),
            "tool_calls": sum(r["tool_calls"] for r in rows),
            "elapsed_seconds": round(elapsed, 6),
            "requests_per_verified_cause": sends / len(found_causes) if found_causes else None,
            "seconds_per_verified_cause": elapsed / len(found_causes) if found_causes else None,
            "provider_usage": None, "provider_cost": None,
            "safety_errors": sum(len(r["safety_errors"]) for r in rows),
        }

    return {strategy: {"all": summary([r for r in trials if r["strategy"] == strategy]),
                       "by_split": {split: summary([r for r in trials if r["strategy"] == strategy and r["split"] == split])
                                    for split in ("development", "held_out")}}
            for strategy in STRATEGIES}


@contextmanager
def _session(application: Application):
    """Real MCP dispatch/accounting with only the final HTTP transport substituted."""
    from . import server
    from .config import Settings
    from .context import build_context
    from .net import http

    def no_network(*args, **kwargs):
        application.safety_errors.append("real_network_attempt")
        raise AssertionError("Evaluation prohibits real sockets and DNS")

    with ExitStack() as stack:
        directory = stack.enter_context(TemporaryDirectory(prefix="moonmcp-evaluation-"))
        stack.enter_context(patch.dict(os.environ, {"MOONMCP_STATE_DIR": directory,
            "MOONMCP_AUDIT_LOG": str(Path(directory) / "audit.jsonl"),
            "MOONMCP_OAST_DOMAIN": "", "MOONMCP_OAST_POLL_URL": ""}))
        stack.enter_context(patch.object(server, "_CTX", None))
        stack.enter_context(patch.object(http, "_USE_CURL_CFFI", False))
        stack.enter_context(patch.object(http, "_blocking_fetch", application.transport))
        for owner, name in ((socket, "getaddrinfo"), (socket, "create_connection"),
                            (socket.socket, "connect"), (socket.socket, "connect_ex"),
                            (socket.socket, "sendto")):
            stack.enter_context(patch.object(owner, name, no_network))
        context = build_context(Settings(scope=["evaluation.test"], state_dir=directory,
                                         rate_limit=0, allow_external_tools=False))
        context.scope._resolver = lambda host: ["93.184.216.34"]
        context.http._opsec = None
        context.http._proxy_rules = None
        context.auth.update_headers(application.inputs()["owner_headers"])
        server._CTX = context
        try:
            yield context
        finally:
            for value in vars(context).values():
                close = getattr(value, "close", None)
                if callable(close):
                    close()


async def _candidate(context, inputs: dict, strategy: str, request_budget: int) -> dict:
    """No evaluator labels or application object cross this interface."""
    from . import sdk, server
    from .execution import execute_tool
    from .runs import RunBudget

    registry = sdk.registered_tools(server.mcp)
    if "authz_probe" not in registry:
        raise ValueError("Evaluation requires authz_probe in the effective tool profile")
    run = context.runs.create("evaluation.test", budget=RunBudget(request_budget, 1, 0))
    arguments = {"target": inputs["target"], "second_headers": inputs["second_headers"], "max_refs": 1}
    if strategy == "semantic":
        arguments["proof"] = inputs["proof"]
    receipt = await execute_tool(context, registry, run["id"], "authz_probe", arguments,
                                 idempotency_key="evaluation-once", timeout_seconds=30, result_mode="full")
    budget = context.runs.get(run["id"])["budget"]
    return {"receipt": receipt, "requests": budget["requests"]["used"],
            "tool_calls": budget["tool_calls"]["used"]}


def _observe(case: Case, generation: str, strategy: str) -> dict:
    started = time.monotonic()
    app = Application(case, generation)
    with _session(app) as context:
        value = asyncio.run(_candidate(context, app.inputs(), strategy, case.request_budget))
    receipt = value["receipt"]
    data = receipt.get("data", {})
    if not isinstance(data, dict):
        data = {}
    verified = bool(receipt.get("ok") and data.get("verdict") == "verified"
                    and data.get("proof", {}).get("verified"))
    complete = bool(receipt.get("ok") and data.get("coverage", {}).get("complete"))
    errors = list(app.safety_errors)
    if value["requests"] != app.requests:
        errors.append("request_counter_mismatch")
    if app.requests > case.request_budget or value["tool_calls"] > 1:
        errors.append("budget_overrun")
    serialized = json.dumps(receipt, sort_keys=True)
    if any(secret in serialized for secret in (app.owner_token, app.observer_token, app.secret)):
        errors.append("secret_in_receipt")
    return {"verified": verified, "completed": complete,
            "lead": bool(data.get("findings")),
            "blocked": receipt.get("error") in {"budget_exhausted", "out_of_scope", "run_target_mismatch"},
            "observed_verdict": data.get("verdict", "inconclusive"),
            "error": receipt.get("error"), "requests": app.requests,
            "tool_calls": value["tool_calls"], "safety_errors": errors,
            "elapsed_seconds": time.monotonic() - started}


def _provenance() -> dict:
    paths = ("evaluation.py", "_evaluation_fixture.py", "web/bola_proof.py", "web/authz.py", "execution.py")
    root = Path(__file__).parent
    dependencies: dict[str, str | None] = {}
    for name in ("mcp", "pydantic", "defusedxml"):
        try:
            dependencies[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            dependencies[name] = None
    try:
        revision = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                                  capture_output=True, text=True, timeout=2, check=False)
        git_revision = revision.stdout.strip() if revision.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        git_revision = None
    return {"package_version": __version__, "python_version": platform.python_version(),
            "git_revision": git_revision, "dependencies": dependencies,
            "source_sha256": {path: hashlib.sha256((root / path).read_bytes()).hexdigest() for path in paths},
            "profile": os.environ.get("MOONMCP_PROFILE") or "full"}


def run_evaluation(*, trials: int = 5) -> dict:
    """Run a frozen deterministic protocol, including failed/incomplete trials."""
    if type(trials) is not int or not 1 <= trials <= 20:
        raise ValueError("trials must be an integer between 1 and 20")
    # Import/registration happens once, outside either strategy's attempt clock.
    # Actual context construction and cleanup still count in every attempt.
    from . import sdk, server
    if "authz_probe" not in sdk.registered_tools(server.mcp):
        raise ValueError("Evaluation requires authz_probe in the effective tool profile")
    protocol = {"version": 1, "fixture_version": FIXTURE_VERSION,
                "strategies": list(STRATEGIES), "trials_per_case_strategy": trials,
                "strategy_order": "counterbalanced by case and trial; one-time server import excluded",
                "cases": [{"id": c.id, "split": c.split, "expected_semantic_verdict": c.expected,
                           "request_budget_per_attempt": c.request_budget} for c in CASES],
                "tool_budget_per_attempt": 1, "fresh_replay_required_for_verified_claims": True,
                "model": None, "provider": None, "network": "socket-free synthetic HTTP transport",
                "gate": "all semantic case expectations, fresh proof replay, no false verification or safety errors"}
    records = []
    for trial in range(trials):
        for case_index, case in enumerate(CASES):
            order = STRATEGIES if (case_index + trial) % 2 == 0 else tuple(reversed(STRATEGIES))
            for strategy in order:
                initial = _observe(case, f"trial-{trial}", strategy)
                replay = _observe(case, f"replay-{trial}", strategy) if initial["verified"] else None
                records.append({"case_id": case.id, "split": case.split, "strategy": strategy, "trial": trial,
                    "ground_truth": case.vulnerable, "root_cause": case.root_cause,
                    "expected_verdict": case.expected, "observed_verdict": initial["observed_verdict"],
                    "expectation_met": initial["observed_verdict"] == case.expected,
                    "lead": initial["lead"], "verified": initial["verified"], "completed": initial["completed"],
                    "blocked": initial["blocked"], "error": initial["error"],
                    "replay_attempted": replay is not None, "replay_verified": bool(replay and replay["verified"]),
                    "assessment_requests": initial["requests"], "replay_requests": replay["requests"] if replay else 0,
                    "requests": initial["requests"] + (replay["requests"] if replay else 0),
                    "tool_calls": initial["tool_calls"] + (replay["tool_calls"] if replay else 0),
                    "elapsed_seconds": initial["elapsed_seconds"] + (replay["elapsed_seconds"] if replay else 0),
                    "safety_errors": initial["safety_errors"] + (replay["safety_errors"] if replay else [])})
    metrics = summarize_trials(records)
    semantic = [r for r in records if r["strategy"] == "semantic"]
    gates = {"semantic_expected_outcomes": all(r["expectation_met"] for r in semantic),
             "no_false_verified_claims": all(not r["verified"] or r["ground_truth"] for r in records),
             "fresh_replay_of_every_claim": all(not r["verified"] or r["replay_verified"] for r in records),
             "safety": all(not r["safety_errors"] for r in records)}
    return {"schema": "moonmcp.discovery_evaluation", "version": REPORT_VERSION,
            "protocol": protocol,
            "protocol_sha256": hashlib.sha256(json.dumps(protocol, sort_keys=True).encode()).hexdigest(),
            "provenance": _provenance(), "trials": records, "metrics": metrics,
            "gates": gates, "passed": all(gates.values()),
            "limitations": ["Two deterministic tool workflows; no LLM/model comparison or autonomous discovery claim.",
                "Synthetic in-process transport; no third-party project preparation or Docker fidelity measurement.",
                "Held-out cases are versioned challenge variants, not evidence of real-project generalisation.",
                "Candidate input separation is an API contract, not a sandbox against malicious Python introspection.",
                "Fresh replay has a separate equal attempt budget; total cost includes those extra sends.",
                "Provider token use and monetary cost are unavailable, not zero.",
                "Repeated deterministic resets are not independent population samples; no statistical confidence or real-target gain is estimated.",
                "Incomplete positive trials remain in recall denominators; required incomplete controls must not become clean negatives."]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trials", type=int, default=5, help="Fresh deterministic resets per case and strategy (1–20)")
    args = parser.parse_args(argv)
    try:
        report = run_evaluation(trials=args.trials)
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
