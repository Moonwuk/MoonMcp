"""Deterministic offline navigation baselines with semantic outcome checks.

Every scenario owns temporary stores and a new application context. Real tools,
scope checks, auth merging and HTTP response analysis run against an in-process
fixture transport; sockets and DNS are forbidden. Measurements are tool calls,
fixture requests, wall time and UTF-8 JSON schema bytes, not client context tokens
or LLM success. Run with ``python -m moonmcp.bench``.
"""

from __future__ import annotations

import asyncio
import functools
import json
import os
import socket
import time
from collections.abc import Callable
from contextlib import ExitStack
from dataclasses import dataclass, field
from tempfile import TemporaryDirectory
from typing import Any
from unittest.mock import patch
from urllib.parse import urlsplit

from .outcomes import failure


@dataclass
class ScenarioResult:
    name: str
    description: str
    calls: list[str] = field(default_factory=list)
    duration_s: float = 0.0
    schema_bytes: int = 0
    notes: list[str] = field(default_factory=list)
    outcomes: dict[str, bool] = field(default_factory=dict)
    fixture_requests: int = 0
    expected_errors: int = 0


def _schemas() -> dict[str, dict]:
    """Use SDK tools/list definitions, including output schemas when present."""
    from .server import mcp

    return {tool.name: tool.model_dump(by_alias=True, exclude_none=True)
            for tool in asyncio.run(mcp.list_tools())}


def _schema_bytes(tool_names: list[str]) -> int:
    schemas = _schemas()
    missing = set(tool_names) - schemas.keys()
    if missing:
        raise AssertionError(f"baseline tools not exposed by current profile: {sorted(missing)}")
    return len(json.dumps([schemas[name] for name in sorted(set(tool_names))],
                          ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def _full_schema_bytes() -> int:
    return _schema_bytes(list(_schemas()))


class _Sandbox:
    """A standalone fixture session, including a real close/reopen operation."""

    def __enter__(self) -> _Sandbox:
        from . import server as srv
        from .config import Settings
        from .net import http

        self.stack = ExitStack()
        self.requests: list[dict] = []
        self.network_attempts: list[str] = []
        state_dir = self.stack.enter_context(TemporaryDirectory(prefix="moonmcp-baseline-"))
        self.stack.enter_context(patch.dict(os.environ, {
            "MOONMCP_STATE_DIR": state_dir,
            "MOONMCP_AUDIT_LOG": os.path.join(state_dir, "audit.jsonl"),
            "MOONMCP_OAST_DOMAIN": "", "MOONMCP_OAST_POLL_URL": "",
        }))
        self.settings = Settings(scope=["baseline.test"], state_dir=state_dir,
                                 rate_limit=0, allow_external_tools=False)
        self.stack.enter_context(patch.object(srv, "_CTX", None))
        self.stack.enter_context(patch.object(http, "_blocking_fetch", self._transport))
        self.stack.enter_context(patch.object(http, "_USE_CURL_CFFI", False))
        self.stack.enter_context(patch.object(socket, "getaddrinfo", self._deny_network))
        self.stack.enter_context(patch.object(socket, "create_connection", self._deny_network))
        self.stack.enter_context(patch.object(socket.socket, "connect", self._deny_network))
        try:
            self._open()
        except BaseException:
            self.stack.close()
            raise
        return self

    def _open(self) -> None:
        from . import server as srv
        from .context import build_context

        self.ctx = build_context(self.settings)
        # Real scope/SSRF checks, deterministic public-address DNS fixture.
        # No actual connection is made to the returned address.
        self.ctx.scope._resolver = lambda host: ["93.184.216.34"]
        self.ctx.http._opsec = None  # no random delay in offline measurements
        self.ctx.http._proxy_rules = None
        srv._CTX = self.ctx

    def _close(self) -> None:
        for store in vars(self.ctx).values():
            close = getattr(store, "close", None)
            if callable(close):
                close()

    def restart(self) -> None:
        self._close()
        self._open()

    def _deny_network(self, *args, **kwargs):
        self.network_attempts.append(repr(args[:1]))
        raise AssertionError("baseline attempted real network I/O")

    def _transport(self, url, method, headers, body, *args):
        from .net.http import HttpResult

        assert urlsplit(url).hostname == "baseline.test", url
        self.requests.append({"url": url, "method": method, "headers": headers, "body": body})
        path = urlsplit(url).path
        status, content_type, content = 404, "text/plain", b"not found"
        if path == "/graphql" and method == "POST":
            query = json.loads(body)["query"]
            data = ({"__schema": {"queryType": {"name": "Query"},
                                   "types": [{"name": "Query", "kind": "OBJECT"}]}}
                    if "__schema" in query else {"__typename": "Query"})
            status, content_type, content = 200, "application/json", json.dumps({"data": data}).encode()
        elif path == "/private":
            token = next((value for key, value in headers.items()
                          if key.lower() == "authorization"), "")
            status, content = ((200, b'{"owner":"A","private":"fixture record"}')
                               if token == "Bearer fixture-A" else (403, b"access denied"))
        elif path == "/unchanged":
            status, content = 200, b"The same public response for both control and test."
        elif path == "/app.js":
            status, content_type, content = 200, "application/javascript", b'fetch("/api/profile");'
        return HttpResult(url=url, final_url=url, status=status, reason="fixture",
                          headers=[("Content-Type", content_type)], body=content, elapsed_ms=1)

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        try:
            self._close()
        finally:
            self.stack.close()
        if exc_type is None and self.network_attempts:
            raise AssertionError(f"real network attempted: {self.network_attempts}")


def _isolated(fn: Callable[[_Sandbox], ScenarioResult]) -> Callable[[], ScenarioResult]:
    @functools.wraps(fn)
    def wrapped() -> ScenarioResult:
        with _Sandbox() as sandbox:
            return fn(sandbox)
    return wrapped


class Harness:
    """Count tool calls and fail immediately on an unexpected error or outcome."""

    def __init__(self, sandbox: _Sandbox, name: str, description: str) -> None:
        self.sandbox = sandbox
        self.result = ScenarioResult(name=name, description=description)
        self._t0 = time.monotonic()

    def call(self, name: str, *, expect_error: str | None = None, **kwargs) -> dict:
        from .server import mcp

        self.result.calls.append(name)
        async def invoke():
            # Same schema validation and profile-filtered lookup as the SDK.
            return await mcp._tool_manager.call_tool(name, kwargs, convert_result=False)
        result = asyncio.run(invoke())
        error = failure(result)
        if expect_error is not None:
            assert error is not None and error.code == expect_error, (name, result)
            self.result.expected_errors += 1
        else:
            assert error is None, (name, result)
        assert isinstance(result, dict), (name, result)
        return result

    def check(self, name: str, condition: object) -> None:
        assert condition, f"{self.result.name}: {name}"
        self.result.outcomes[name] = True

    def finish(self) -> ScenarioResult:
        self.result.duration_s = time.monotonic() - self._t0
        self.result.schema_bytes = _schema_bytes(self.result.calls)
        self.result.fixture_requests = len(self.sandbox.requests)
        assert self.result.outcomes, "a scenario must assert a semantic outcome"
        return self.result


@_isolated
def scenario_new_target(sandbox: _Sandbox) -> ScenarioResult:
    h = Harness(sandbox, "new_target", "Orient on a fresh target and verify empty target memory.")
    h.call("server_status")
    catalog = h.call("tool_catalog", family="light_active")
    memory = h.call("memory_brief", target="baseline.test")
    h.check("catalog_contains_graphql_check", "graphql_check" in json.dumps(catalog))
    h.check("fresh_target_has_no_findings", memory["counts"]["findings"] == 0)
    return h.finish()


@_isolated
def scenario_run_continuation(sandbox: _Sandbox) -> ScenarioResult:
    h = Harness(sandbox, "run_continuation", "Close and reopen stores, then resume the correct task.")
    earlier = h.call("run_start", target="baseline.test", focus="unrelated run")
    earlier_task = earlier["next"]["id"]
    created = h.call("run_start", target="baseline.test", focus="continuation probe")
    run_id, task_id = created["run"]["id"], created["next"]["id"]
    h.call("run_task_update", task_id=task_id, state="running", result="checkpoint saved")
    original_store = sandbox.ctx.runs
    sandbox.restart()
    status = h.call("run_status", run_id=run_id)
    resumed = next(task for task in status["tasks"] if task["id"] == task_id)
    h.check("store_reopened", sandbox.ctx.runs is not original_store)
    h.check("task_state_survived_restart", resumed["state"] == "running"
            and resumed["result"] == "checkpoint saved")
    h.call("run_task_update", task_id=task_id, state="completed", result="resumed and completed")
    h.call("run_next", run_id=run_id)
    h.check("other_run_untouched", sandbox.ctx.runs.task(earlier_task)["state"] == "pending")
    return h.finish()


@_isolated
def scenario_graphql_signs(sandbox: _Sandbox) -> ScenarioResult:
    h = Harness(sandbox, "graphql_signs", "Discover and inspect a GraphQL fixture endpoint.")
    result = h.call("graphql_check", target="https://baseline.test/graphql")
    h.check("one_graphql_endpoint", len(result["endpoints"]) == 1)
    endpoint = result["endpoints"][0]
    h.check("introspection_observed", endpoint["introspection_enabled"] and endpoint["type_count"] == 1)
    h.check("fixture_requests_counted", len(sandbox.requests) == 15)
    return h.finish()


@_isolated
def scenario_authed_surface(sandbox: _Sandbox) -> ScenarioResult:
    h = Harness(sandbox, "authed_surface", "Compare owner, second user and anonymous access on a fixture.")
    h.call("auth_set", bearer="fixture-A")
    result = h.call("access_control_check", target="https://baseline.test/private",
                    second_headers={"Authorization": "Bearer fixture-B"})
    h.check("owner_can_access", result["identities"]["auth_A"]["status"] == 200)
    h.check("other_identities_denied", all(result["identities"][name]["status"] == 403
                                          for name in ("user_B", "anonymous")))
    h.check("no_false_authz_lead", result["verdict"] == "no_obvious_idor" and not result["concerns"])
    h.check("three_identity_requests", len(sandbox.requests) == 3)
    return h.finish()


@_isolated
def scenario_false_lead(sandbox: _Sandbox) -> ScenarioResult:
    h = Harness(sandbox, "false_lead", "Reject an unchanged differential response and recall the lesson.")
    result = h.call("confirm_finding", target="https://baseline.test/unchanged",
                    payload="fixture-marker", param="q", record=True)
    h.check("control_refutes_lead", result["verdict"] == "unconfirmed")
    h.check("no_finding_recorded", not sandbox.ctx.findings.list())
    h.call("memory_lesson", action="add", title="Unchanged fixture response",
           body="The control and candidate matched; do not repeat this candidate unchanged.")
    lesson = h.call("memory_lesson", query="Unchanged fixture")
    h.check("negative_result_recalled", lesson["count"] == 1)
    h.check("control_and_candidate_requested", len(sandbox.requests) == 2)
    return h.finish()


@_isolated
def scenario_no_browser(sandbox: _Sandbox) -> ScenarioResult:
    from .web import browser

    h = Harness(sandbox, "no_browser", "Observe a missing browser, then extract static JavaScript endpoints.")
    with patch.object(browser, "playwright_available", return_value=False):
        result = h.call("browser_open", target="https://baseline.test/app.js",
                        expect_error="missing_dependency")
    h.check("browser_dependency_reported", result["available"] is False and result["install_hint"])
    static = h.call("analyze_js", target="https://baseline.test/app.js")
    h.check("static_fallback_found_endpoint", "/api/profile" in static["endpoints"])
    h.check("only_static_request_sent", len(sandbox.requests) == 1)
    return h.finish()


@_isolated
def scenario_budget_exhausted(sandbox: _Sandbox) -> ScenarioResult:
    h = Harness(sandbox, "budget_exhausted", "Refuse an overrun, preserve counters and block the actual task.")
    created = h.call("run_start", target="baseline.test", focus="budget probe",
                     max_requests=1, max_tool_calls=2)
    run_id, task_id = created["run"]["id"], created["next"]["id"]
    h.call("run_usage", run_id=run_id, requests=5, expect_error="budget_exhausted")
    h.call("run_task_update", task_id=task_id, state="blocked", result="request budget exhausted")
    result = h.call("run_status", run_id=run_id)
    h.check("refusal_did_not_consume_budget", result["run"]["budget"]["requests"]["used"] == 0)
    h.check("task_blocked", next(t for t in result["tasks"] if t["id"] == task_id)["state"] == "blocked")
    h.check("no_request_after_refusal", len(sandbox.requests) == 0)
    return h.finish()


ALL_SCENARIOS = [scenario_new_target, scenario_run_continuation, scenario_graphql_signs,
                 scenario_authed_surface, scenario_false_lead, scenario_no_browser,
                 scenario_budget_exhausted]


def run_baselines() -> dict[str, Any]:
    results = [scenario() for scenario in ALL_SCENARIOS]
    full = _full_schema_bytes()
    return {
        "stage": "0-baseline", "total_scenarios": len(results), "full_schema_bytes": full,
        "measurement": "UTF-8 JSON tools/list schema bytes; not client context tokens or LLM task success",
        "network": "in-process fixture transport only; no sockets or DNS",
        "scenarios": [{
            "name": r.name, "description": r.description, "tool_calls": len(r.calls),
            "calls": r.calls, "duration_s": round(r.duration_s, 3),
            "slice_schema_bytes": r.schema_bytes,
            "slice_vs_full_pct": round(100 * r.schema_bytes / max(full, 1), 1),
            "fixture_requests": r.fixture_requests, "expected_errors": r.expected_errors,
            "outcomes": r.outcomes, "notes": r.notes,
        } for r in results],
        "totals": {
            "tool_calls": sum(len(r.calls) for r in results),
            "fixture_requests": sum(r.fixture_requests for r in results),
            "duration_s": round(sum(r.duration_s for r in results), 3),
            "avg_slice_pct": round(sum(r.schema_bytes for r in results) / len(results) /
                                   max(full, 1) * 100, 1),
        },
    }


def main() -> int:
    import sys

    json.dump(run_baselines(), sys.stdout, indent=1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
