"""Run-bound dispatch tests use a stub transport: no external requests."""

from __future__ import annotations

import asyncio
import hashlib
import json
import threading
from types import SimpleNamespace

import pytest
from mcp.server.fastmcp.tools.base import Tool

from moonmcp.auth import AuthContext
from moonmcp.config import Settings
from moonmcp.execution import ExecutionBlocked, ResultCache, execute_tool, expand_result
from moonmcp.findings import FindingsStore
from moonmcp.flags import EvidenceRef
from moonmcp.net import http
from moonmcp.net.http import HttpClient, HttpResult
from moonmcp.net.ratelimit import Governor
from moonmcp.runs import RunBudget, RunStore
from moonmcp.scope import ScopeManager
from moonmcp.telemetry.collector import TelemetryCollector


@pytest.fixture
def ctx():
    context = SimpleNamespace(
        runs=RunStore(), auth=AuthContext(), scope=ScopeManager(block_private=False),
        settings=Settings(block_private=False), telemetry=TelemetryCollector(),
    )
    context.scope.add("example.test")
    context.http = HttpClient(Governor(0, 20), user_agent="test", telemetry=context.telemetry)
    yield context
    context.runs.close()


def registry(fn, name="http_probe", *, intrusive=False):
    fn.__moonmcp_intrusive__ = intrusive
    return {name: Tool.from_function(fn, name=name)}


def response(url, *, status=200, headers=None, error=None):
    return HttpResult(url, url, status, "", headers or [], b"ok", 1.0, error=error)


def start(ctx, *, requests=10, tools=20, intrusive=2):
    return ctx.runs.create("example.test", budget=RunBudget(requests, tools, intrusive))["id"]


async def test_redirects_reserve_each_send_and_record_telemetry_once(ctx, monkeypatch):
    sent = []

    def transport(url, *args):
        sent.append(url)
        return response(url, status=302, headers=[("Location", f"/{len(sent)}")])

    monkeypatch.setattr(http, "_blocking_fetch", transport)
    run = start(ctx, requests=2)

    async def probe(target: str):
        await ctx.http.fetch(target, follow_redirects=True)
        return {"done": True}

    result = await execute_tool(ctx, registry(probe), run, "http_probe",
                                {"target": "https://example.test/"})
    assert result["error"] == "budget_exhausted"
    assert len(sent) == 2
    budget = ctx.runs.get(run)["budget"]
    assert budget["requests"]["used"] == 2
    assert budget["tool_calls"]["used"] == 1
    assert ctx.telemetry.get_stats()["requests_total"] == 2
    events = ctx.runs.events(run)
    assert sum(e["kind"] == "invocation_finished" for e in events) == 1


async def test_concurrent_calls_cannot_overspend(ctx, monkeypatch):
    sent = []
    monkeypatch.setattr(http, "_blocking_fetch", lambda url, *a: sent.append(url) or response(url))
    run = start(ctx, requests=3)

    async def probe(target: str):
        return {"status": (await ctx.http.fetch(target)).status}

    tools = registry(probe)
    results = await asyncio.gather(*[
        execute_tool(ctx, tools, run, "http_probe", {"target": f"https://example.test/{i}"})
        for i in range(12)
    ])
    assert sum(r["ok"] for r in results) == 3
    assert len(sent) == 3
    assert ctx.runs.get(run)["budget"]["requests"]["used"] == 3
    assert ctx.runs.get(run)["budget"]["tool_calls"]["used"] == 12


async def test_composite_cannot_swallow_budget_failure(ctx, monkeypatch):
    monkeypatch.setattr(http, "_blocking_fetch", lambda url, *a: response(url))
    run = start(ctx, requests=1)

    async def batch():
        results = await asyncio.gather(
            *(ctx.http.fetch(f"https://example.test/{i}") for i in range(3)),
            return_exceptions=True,
        )
        return {"count": len(results)}

    result = await execute_tool(ctx, registry(batch, "probe_batch"), run, "probe_batch", {})
    assert result["error"] == "budget_exhausted"
    assert result["data"]["count"] == 3


async def test_parallel_idempotency_and_completed_replay(ctx):
    entered, release = asyncio.Event(), asyncio.Event()
    calls = []

    async def probe(target: str):
        calls.append(target)
        entered.set()
        await release.wait()
        return {"value": target}

    run, tools = start(ctx), registry(probe)
    args = {"target": "example.test"}
    first = asyncio.create_task(execute_tool(ctx, tools, run, "http_probe", args,
                                            idempotency_key="one"))
    await entered.wait()
    duplicate = await execute_tool(ctx, tools, run, "http_probe", args, idempotency_key="one")
    assert duplicate["error"] == "execution_in_progress"
    release.set()
    original = await first
    replay = await execute_tool(ctx, tools, run, "http_probe", args, idempotency_key="one")
    assert replay == {**original, "replayed": True}
    assert calls == ["example.test"]
    assert ctx.runs.get(run)["budget"]["tool_calls"]["used"] == 1
    with pytest.raises(ExecutionBlocked, match="different invocation"):
        await execute_tool(ctx, tools, run, "http_probe", {"target": "https://example.test/changed"},
                           idempotency_key="one")


async def test_cancellation_records_unknown_and_never_retries_same_key(ctx):
    entered = asyncio.Event()
    calls = []

    async def probe():
        calls.append(1)
        entered.set()
        await asyncio.Event().wait()

    run, tools = start(ctx), registry(probe)
    task = asyncio.create_task(execute_tool(ctx, tools, run, "http_probe", {},
                                           idempotency_key="cancelled"))
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    replay = await execute_tool(ctx, tools, run, "http_probe", {}, idempotency_key="cancelled")
    assert replay["state"] == "unknown"
    assert replay["retryable"] is False
    assert calls == [1]


@pytest.mark.parametrize("state", ["paused", "cancelled"])
async def test_run_control_stops_awaiting_tool(ctx, state):
    entered = asyncio.Event()
    stopped = asyncio.Event()

    async def probe():
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            stopped.set()

    run = start(ctx)
    task = asyncio.create_task(execute_tool(ctx, registry(probe), run, "http_probe", {}))
    await entered.wait()
    ctx.runs.set_state(run, state)
    result = await asyncio.wait_for(task, 1)
    assert result["state"] == "unknown"
    assert stopped.is_set()


async def test_transport_timeout_is_unknown_even_if_tool_reports_success(ctx, monkeypatch):
    monkeypatch.setattr(http, "_blocking_fetch",
                        lambda url, *a: response(url, status=None, error="timed out"))

    async def probe():
        await ctx.http.fetch("https://example.test/", method="POST", body=b"action")
        return {"accepted": True}

    result = await execute_tool(ctx, registry(probe), start(ctx), "http_probe", {})
    assert result["error"] == "outcome_unknown"
    assert result["requests"] == 1
    assert ctx.telemetry.get_stats()["requests_total"] == 1


async def test_dispatch_timeout_does_not_retry(ctx):
    async def probe():
        await asyncio.Event().wait()

    run, tools = start(ctx), registry(probe)
    result = await execute_tool(ctx, tools, run, "http_probe", {}, timeout_seconds=0.01,
                                idempotency_key="timeout")
    assert result["state"] == "unknown"
    assert (await execute_tool(ctx, tools, run, "http_probe", {}, idempotency_key="timeout"))["replayed"]


async def test_hidden_control_unmetered_and_schema_fail_before_reservation(ctx):
    async def probe(target: str):
        raise AssertionError("must not execute")

    run = start(ctx)
    for name, tools, args, code in [
        ("http_probe", {}, {}, "tool_unavailable"),
        ("run_execute", {}, {}, "execution_control"),
        ("browser_open", registry(probe, "browser_open"), {}, "execution_unmetered"),
    ]:
        with pytest.raises(ExecutionBlocked) as exc:
            await execute_tool(ctx, tools, run, name, args)
        assert exc.value.code == code
    for args in ({"target": 123}, {"target": "example.test", "invented": True}, {}):
        with pytest.raises(ValueError):
            await execute_tool(ctx, registry(probe), run, "http_probe", args)
    assert ctx.runs.get(run)["budget"]["tool_calls"]["used"] == 0


async def test_intrusive_and_capability_gates(ctx):
    async def probe():
        raise AssertionError("must not execute")

    run = start(ctx)
    with pytest.raises(ExecutionBlocked) as exc:
        await execute_tool(ctx, registry(probe, intrusive=True), run, "http_probe", {})
    assert exc.value.code == "disabled"
    with pytest.raises(ExecutionBlocked) as exc:
        await execute_tool(ctx, registry(probe), run, "http_probe", {}, availability={
            "http_probe": {"available": False, "reasons": ["dependency absent"]},
        })
    assert exc.value.code == "missing_dependency"


async def test_reference_cache_isolated_by_auth_scope_run_and_callable(ctx):
    calls = []

    async def info():
        calls.append(1)
        return {"reference": ["value"]}

    run, tools = start(ctx), registry(info, "injection_info")
    first = await execute_tool(ctx, tools, run, "injection_info", {})
    first["data"]["reference"].append("changed")
    second = await execute_tool(ctx, tools, run, "injection_info", {})
    assert second["cached"]
    assert second["data"] == {"reference": ["value"]}
    ctx.auth.set_bearer("credential")
    assert not (await execute_tool(ctx, tools, run, "injection_info", {}))["cached"]
    ctx.scope.add("other.test")
    assert not (await execute_tool(ctx, tools, run, "injection_info", {}))["cached"]
    assert not (await execute_tool(ctx, tools, start(ctx), "injection_info", {}))["cached"]
    assert len(calls) == 4


async def test_mutations_and_failures_are_not_cached(ctx):
    calls = []

    async def mutation():
        calls.append(1)
        return {"done": True}

    run, tools = start(ctx), registry(mutation, "memory_add")
    for _ in range(2):
        result = await execute_tool(ctx, tools, run, "memory_add", {})
        assert not result["cached"]

    async def failure():
        calls.append(1)
        return {"error": "invalid_input"}

    tools = registry(failure, "injection_info")
    for _ in range(2):
        result = await execute_tool(ctx, tools, run, "injection_info", {})
        assert result["state"] == "failed"
        assert not result["cached"]
    assert len(calls) == 4


def test_cache_is_bounded_and_expires(monkeypatch):
    now = [10.0]
    monkeypatch.setattr("moonmcp.execution.time.monotonic", lambda: now[0])
    cache = ResultCache(max_entries=1, ttl=1, max_bytes=20)
    cache.put("one", {"a": 1})
    cache.put("two", {"a": 2})
    assert cache.get("one") == (False, None)
    assert cache.get("two") == (True, {"a": 2})
    now[0] += 2
    assert cache.get("two") == (False, None)
    cache.put("large", {"large": "x" * 50})
    assert cache.get("large") == (False, None)


async def test_receipt_write_failure_does_not_imply_action_failed(ctx, monkeypatch):
    calls = []

    async def mutate():
        calls.append(1)
        return {"done": True}

    def unavailable(*args):
        raise OSError("storage unavailable")

    monkeypatch.setattr(ctx.runs, "finish_invocation", unavailable)
    run, tools = start(ctx), registry(mutate, "memory_add")
    result = await execute_tool(ctx, tools, run, "memory_add", {}, idempotency_key="write")
    assert result["state"] == "unknown"
    assert result["error"] == "receipt_write_failed"
    replay = await execute_tool(ctx, tools, run, "memory_add", {}, idempotency_key="write")
    assert replay["error"] == "execution_in_progress"
    assert calls == [1]


async def test_direct_http_telemetry_and_scope_blocking(ctx, monkeypatch):
    monkeypatch.setattr(http, "_blocking_fetch", lambda url, *a: response(url))
    await ctx.http.fetch("https://example.test/")
    await ctx.http.fetch("https://other.test/", scope_check=ctx.scope.is_in_scope)
    assert ctx.telemetry.get_stats()["requests_total"] == 1


async def test_real_registered_tool_retains_scope_gate(ctx, monkeypatch):
    from moonmcp import server

    monkeypatch.setattr(server, "_CTX", ctx)
    ctx.audit = SimpleNamespace(record=lambda *a, **k: None)
    tools = {"http_probe": server.mcp._tool_manager.get_tool("http_probe")}
    run = ctx.runs.create("not-authorised.test")["id"]
    result = await execute_tool(ctx, tools, run, "http_probe",
                                {"target": "https://not-authorised.test/"})
    assert result["error"] == "out_of_scope"
    assert result["requests"] == 0


async def test_task_cannot_cross_runs(ctx):
    first, second = start(ctx), start(ctx)
    task = ctx.runs.add_task(second, "other run")
    ctx.runs.update_task(task["id"], "running")

    async def probe():
        raise AssertionError("must not execute")

    with pytest.raises(ExecutionBlocked, match="belong"):
        await execute_tool(ctx, registry(probe), first, "http_probe", {}, task_id=task["id"])


async def test_lossless_unicode_output_replay_does_not_duplicate_artifacts(ctx):
    original = {"evidence": "漢字🌓Привет" * 40_000, "error_detail": "not a top-level failure"}

    async def probe():
        return original

    run, tools = start(ctx), registry(probe)
    result = await execute_tool(ctx, tools, run, "http_probe", {}, idempotency_key="large")
    assert result["ok"]
    manifest = result["output_manifest"]
    assert manifest["complete"]
    assert len(manifest["chunks"]) > 1
    assert all(chunk["bytes"] < 1_000_000 for chunk in manifest["chunks"])
    full = expand_result(ctx, result)
    assert full["data"] == original
    assert hashlib.sha256(json.dumps(original, ensure_ascii=False).encode()).hexdigest() == manifest["sha256"]
    before = len(ctx.runs.artifacts(run))
    replay = await execute_tool(ctx, tools, run, "http_probe", {}, idempotency_key="large",
                                result_mode="full")
    assert replay["data"] == original
    assert replay["replayed"]
    assert len(ctx.runs.artifacts(run)) == before


async def test_compact_execution_error_remains_top_level(ctx):
    async def probe():
        return {"error": "invalid_input", "detail": "x" * 10_000}

    result = await execute_tool(ctx, registry(probe), start(ctx), "http_probe", {})
    assert result["error"] == "invalid_input"
    assert result["ok"] is False
    assert result["output_manifest"]["complete"]


async def test_run_binding_rejects_globally_scoped_other_target_and_redirect(ctx, monkeypatch):
    ctx.scope.add("other.test")
    sent = []

    def transport(url, *args):
        sent.append(url)
        return response(url, status=302, headers=[("Location", "https://other.test/")])

    monkeypatch.setattr(http, "_blocking_fetch", transport)

    async def probe(target: str):
        return {"status": (await ctx.http.fetch(target, follow_redirects=True)).status}

    run, tools = start(ctx), registry(probe)
    with pytest.raises(ExecutionBlocked) as error:
        await execute_tool(ctx, tools, run, "http_probe", {"target": "https://other.test/"})
    assert error.value.code == "run_target_mismatch"
    result = await execute_tool(ctx, tools, run, "http_probe", {"target": "https://example.test/"})
    assert result["error"] == "run_target_mismatch"
    assert sent == ["https://example.test/"]


async def test_cancelled_thread_retains_governor_permit(ctx, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    sent = []

    def transport(url, *args):
        sent.append(url)
        if len(sent) == 1:
            entered.set()
            release.wait(2)
        return response(url)

    monkeypatch.setattr(http, "_blocking_fetch", transport)
    ctx.http = HttpClient(Governor(0, 1), user_agent="test")

    async def probe(target: str):
        return {"status": (await ctx.http.fetch(target)).status}

    run, tools = start(ctx), registry(probe)
    first = asyncio.create_task(execute_tool(ctx, tools, run, "http_probe",
                                             {"target": "https://example.test/first"},
                                             timeout_seconds=0.02))
    while not entered.is_set():
        await asyncio.sleep(0.001)
    assert (await first)["state"] == "unknown"
    second = asyncio.create_task(execute_tool(ctx, tools, run, "http_probe",
                                              {"target": "https://example.test/second"}))
    try:
        await asyncio.sleep(0.03)
        assert len(sent) == 1
        release.set()
        assert (await asyncio.wait_for(second, 1))["ok"]
        assert len(sent) == 2
    finally:
        release.set()


async def test_context_change_stops_next_send_and_old_key_replay(ctx, monkeypatch):
    monkeypatch.setattr(http, "_blocking_fetch", lambda url, *a: response(url))

    async def probe():
        ctx.auth.set_bearer("changed")
        await ctx.http.fetch("https://example.test/")

    run, tools = start(ctx), registry(probe)
    result = await execute_tool(ctx, tools, run, "http_probe", {}, idempotency_key="context")
    assert result["error"] == "execution_context_changed"
    assert result["requests"] == 0
    with pytest.raises(ExecutionBlocked, match="different invocation"):
        await execute_tool(ctx, tools, run, "http_probe", {}, idempotency_key="context")


async def test_suppress_auth_excludes_opsec_and_ambient_proxy_identity(monkeypatch):
    from moonmcp.opsec import OpsecConfig, OpsecEngine

    seen = []

    def transport(url, method, headers, *args):
        seen.append(headers)
        return response(url)

    monkeypatch.setattr(http, "_blocking_fetch", transport)
    rules = SimpleNamespace(apply_rules=lambda req: {
        **req, "headers": {**req["headers"], "Authorization": "ambient"},
    })
    client = HttpClient(
        Governor(0, 1), user_agent="test", auth_provider=lambda: {"Cookie": "engagement"},
        opsec=OpsecEngine(OpsecConfig(bb_header_name="X-Engagement", bb_header_value="target",
                                     jitter_ms=(0, 0))), proxy_rules=rules,
    )
    await client.fetch("https://provider.test/", suppress_auth=True, headers={"apiKey": "provider"})
    headers = {key.lower(): value for key, value in seen[0].items()}
    assert "authorization" not in headers
    assert "cookie" not in headers
    assert "x-engagement" not in headers
    assert headers["apikey"] == "provider"


async def test_program_identity_change_invalidates_replay(ctx):
    program_headers = {"X-Program": "first"}
    ctx.programs = SimpleNamespace(active=SimpleNamespace(name="program"),
                                   active_headers=lambda: dict(program_headers))

    async def info():
        return {"reference": True}

    run, tools = start(ctx), registry(info, "injection_info")
    await execute_tool(ctx, tools, run, "injection_info", {}, idempotency_key="identity")
    program_headers["X-Program"] = "second"
    with pytest.raises(ExecutionBlocked, match="different invocation"):
        await execute_tool(ctx, tools, run, "injection_info", {}, idempotency_key="identity")


@pytest.mark.parametrize("wrapped", [False, True])
async def test_unexpected_error_after_mutation_is_unknown(ctx, wrapped):
    changes = []

    async def mutate():
        changes.append("written")
        if wrapped:
            return {"error": "internal_error"}
        raise RuntimeError("failed after write")

    run, tools = start(ctx), registry(mutate, "memory_add")
    result = await execute_tool(ctx, tools, run, "memory_add", {}, idempotency_key="partial")
    assert result["state"] == "unknown"
    assert result["retryable"] is False
    await execute_tool(ctx, tools, run, "memory_add", {}, idempotency_key="partial")
    assert changes == ["written"]


@pytest.mark.parametrize("run_target,target", [
    ("https://bücher.example/", "https://xn--bcher-kva.example/"),
    ("[2001:0db8:0:0::1]", "https://[2001:db8::1]/"),
])
async def test_equivalent_target_notations_bind_to_same_run(ctx, run_target, target):
    async def probe(target: str):
        return {"target": target}

    run = ctx.runs.create(run_target)["id"]
    result = await execute_tool(ctx, registry(probe), run, "http_probe", {"target": target})
    assert result["ok"]


async def test_nested_typed_arguments_hash_canonically_and_replay_once(ctx):
    seen = []

    async def record(evidence: list[EvidenceRef]):
        assert isinstance(evidence[0], EvidenceRef)
        seen.append(evidence[0].ref)
        return {"saved": evidence[0].model_dump()}

    run, tools = start(ctx), registry(record, "flag_record")
    args = {"evidence": [{"ref": "response:1", "source_group": "source"}]}
    first = await execute_tool(ctx, tools, run, "flag_record", args, idempotency_key="typed")
    assert first["ok"]
    replay = await execute_tool(ctx, tools, run, "flag_record", args, idempotency_key="typed")
    assert replay["replayed"]
    assert seen == ["response:1"]


async def test_global_findings_mutations_cannot_run_inside_managed_execution(ctx):
    async def clear():
        raise AssertionError("must not execute")

    async def triage(apply: bool = False):
        return {"changed": apply}

    run = start(ctx)
    with pytest.raises(ExecutionBlocked) as exc:
        await execute_tool(ctx, registry(clear, "clear_findings"), run, "clear_findings", {})
    assert exc.value.code == "execution_control"
    tools = registry(triage, "triage_findings")
    with pytest.raises(ExecutionBlocked) as exc:
        await execute_tool(ctx, tools, run, "triage_findings", {"apply": True})
    assert exc.value.code == "execution_control"
    assert ctx.runs.get(run)["budget"]["tool_calls"]["used"] == 0
    assert (await execute_tool(ctx, tools, run, "triage_findings", {}))["ok"]


async def test_finding_mutations_are_bound_to_run_target_and_record_id(ctx):
    ctx.findings = FindingsStore()
    run, other = start(ctx), ctx.runs.create("other.test")["id"]
    foreign = ctx.findings.add(target="other.test", severity="info", title="Other", run_id=other)
    own = ctx.findings.add(target="example.test", severity="info", title="Own", run_id=run)

    async def finding(target: str):
        raise AssertionError("must not execute")

    async def label(finding_id: int):
        return {"labelled": finding_id}

    try:
        for name in ("add_finding", "promote_lead"):
            with pytest.raises(ExecutionBlocked) as exc:
                await execute_tool(ctx, registry(finding, name), run, name, {"target": "other.test"})
            assert exc.value.code == "run_target_mismatch"
        tools = registry(label, "label_finding")
        with pytest.raises(ExecutionBlocked) as exc:
            await execute_tool(ctx, tools, run, "label_finding", {"finding_id": foreign.id})
        assert exc.value.code == "run_target_mismatch"
        assert (await execute_tool(ctx, tools, run, "label_finding", {"finding_id": own.id}))["ok"]
        assert ctx.findings.list(run_id=other) == [foreign]
    finally:
        ctx.findings.close()


async def test_recovered_receipt_without_result_remains_unknown_after_resolution(ctx, monkeypatch):
    calls = []

    async def info():
        calls.append(1)
        return {"reference": True}

    def write_failed(*args):
        raise OSError("storage temporarily unavailable")

    run, tools = start(ctx), registry(info, "injection_info")
    with monkeypatch.context() as patch:
        patch.setattr(ctx.runs, "finish_invocation", write_failed)
        interrupted = await execute_tool(ctx, tools, run, "injection_info", {}, idempotency_key="recover")
    ctx.runs.set_state(run, "paused")
    invocation = interrupted["invocation_id"]
    ctx.runs.mark_invocation_unknown(invocation, "Worker stopped after storage failure")
    unknown = await execute_tool(ctx, tools, run, "injection_info", {}, idempotency_key="recover")
    assert unknown["error"] == "outcome_unknown"
    evidence = ctx.runs.add_artifact(run, "reconciliation", "checked", "The read completed")
    ctx.runs.reconcile_invocation(invocation, "completed", "Reviewed completed worker output", [evidence["id"]])
    resolved = await execute_tool(ctx, tools, run, "injection_info", {}, idempotency_key="recover")
    assert resolved["error"] == "outcome_unknown"
    assert resolved["resolution"]["outcome"] == "completed"
    assert resolved["retryable"] is False
    assert calls == [1]
