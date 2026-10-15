"""Proof fixtures, protocol status and real HttpClient managed accounting."""

import asyncio
import json

import pytest

from moonmcp import sdk, server
from moonmcp.execution import execute_tool, expand_result
from moonmcp.net import http
from moonmcp.net.http import HttpClient
from moonmcp.net.ratelimit import Governor
from moonmcp.outcomes import outcome
from moonmcp.runs import RunBudget
from moonmcp.web.bola_proof import verify_private_read
from tests.bola_fixture import BolaApplication, manifest

TARGET = "https://example.test/orders/100"
OWNER = {"Authorization": "Bearer owner-token"}
OBSERVER = {"Authorization": "Bearer observer-token"}


async def verify(monkeypatch, app, spec=None, transport=None):
    monkeypatch.setattr(http, "_blocking_fetch", transport or app.transport)
    client = HttpClient(Governor(0, 20), user_agent="fixture")
    return await verify_private_read(client, TARGET, spec or manifest(), owner_headers=OWNER,
                                     second_headers=OBSERVER, scope_check=lambda _: True)


@pytest.mark.parametrize("vulnerable,expected", [(True, "verified"), (False, "not_verified")])
async def test_private_read_uses_independent_policy_and_concrete_object(monkeypatch, vulnerable, expected):
    app = BolaApplication(vulnerable=vulnerable)
    assert not app.may_read("bob")
    result = await verify(monkeypatch, app)
    assert result["verdict"] == expected
    assert outcome(result).ok
    assert result["proof"]["verified"] is vulnerable
    assert len(app.requests) == 8
    assert result["coverage"]["complete"]
    assert all("body_sha256" in c for c in result["checks"])
    serialized = json.dumps(result)
    for secret in (app.secret, "owner-token", "observer-token"):
        assert secret not in serialized
    assert all(method == "GET" for _, method, _ in app.requests)


@pytest.mark.parametrize("visibility", ["public", "shared"])
async def test_permitted_reads_are_not_private_object_violations(monkeypatch, visibility):
    app = BolaApplication(visibility=visibility)
    assert app.may_read("bob")
    result = await verify(monkeypatch, app, manifest(visibility=visibility))
    assert result["verdict"] == "not_applicable"
    assert not result["proof"]["verified"]
    assert app.requests == []


@pytest.mark.parametrize("fault", ["expired", "wrong_identity", "wrong_tenant", "wrong_type",
                                  "truncated", "timeout", "changed_object", "bad_control",
                                  "login_shell", "expired_after"])
async def test_missing_or_inconsistent_evidence_cannot_verify(monkeypatch, fault):
    app = BolaApplication(vulnerable=True)
    def transport(url, method, headers, *args):
        response = app.transport(url, method, headers, *args)
        n = len(app.requests)
        body = json.loads(response.body)
        if fault == "expired" and n == 2:
            response.status = 401
        elif fault == "wrong_identity" and n == 2:
            body["subject"] = "alice"
        elif fault == "wrong_tenant" and n == 2:
            body["tenant"] = "north"
        elif fault == "wrong_type" and n == 3:
            body["type"] = "invoice"
        elif fault == "truncated" and n == 4:
            response.truncated = True
        elif fault == "timeout" and n == 4:
            response.status, response.error = None, "timeout"
        elif fault == "changed_object" and n == 8:
            body["secret"] = "changed"
        elif fault == "bad_control" and n == 5:
            response.status = 200
        elif fault == "login_shell" and n == 4:
            response.body = b"<html>login</html>"
            return response
        elif fault == "expired_after" and n == 7:
            response.status = 401
        response.body = json.dumps(body).encode()
        return response
    result = await verify(monkeypatch, app, transport=transport)
    assert result["verdict"] == "inconclusive"
    assert not result["proof"]["verified"] and not outcome(result).ok


async def test_same_prefix_with_different_protected_suffix_does_not_verify(monkeypatch):
    app = BolaApplication(vulnerable=True)
    def transport(url, method, headers, *args):
        response = app.transport(url, method, headers, *args)
        if len(app.requests) == 4:
            body = json.loads(response.body)
            body["secret"] = "unrelated public value"
            response.body = json.dumps(body).encode()
        return response
    result = await verify(monkeypatch, app, transport=transport)
    assert result["verdict"] == "not_verified"
    assert not result["proof"]["verified"]


@pytest.mark.parametrize("field,value", [("identity_url", "https://outside.test/me"),
                                        ("control_url", TARGET), ("version", 2)])
async def test_invalid_proof_sends_nothing(monkeypatch, field, value):
    app = BolaApplication()
    spec = manifest()
    spec[field] = value
    with pytest.raises(ValueError):
        await verify(monkeypatch, app, spec)
    assert app.requests == []


@pytest.fixture
def managed(monkeypatch, fresh_context):
    ctx = fresh_context
    ctx.scope.add("example.test")
    ctx.auth.update_headers(OWNER)
    # No DNS or network is needed: all actual sends reach the fixture transport.
    ctx.http = HttpClient(Governor(0, 20), user_agent="fixture")
    async def admit(*args, **kwargs):
        return "example.test"
    monkeypatch.setattr(server, "_require_scope", admit)
    return ctx


async def test_managed_proof_accounts_all_sends_and_replays_receipt_without_resending(monkeypatch, managed):
    ctx = managed
    app = BolaApplication(vulnerable=True)
    monkeypatch.setattr(http, "_blocking_fetch", app.transport)
    run = ctx.runs.create("example.test", budget=RunBudget(8, 4, 0))["id"]
    args = {"target": TARGET, "second_headers": OBSERVER, "proof": manifest()}
    tools = sdk.registered_tools(server.mcp)
    receipt = await execute_tool(ctx, tools, run, "authz_probe", args, idempotency_key="proof")
    assert receipt["ok"]
    data = expand_result(ctx, receipt)["data"]
    assert data["proof"]["verified"]
    artifact = ctx.runs.get_artifact(run, data["evidence"]["artifact_id"])
    assert artifact["sha256"] == data["evidence"]["sha256"]
    assert json.loads(artifact["content"])["proof"]["verified"]
    assert ctx.runs.get(run)["budget"]["requests"]["used"] == 8
    replay = await execute_tool(ctx, tools, run, "authz_probe", args, idempotency_key="proof")
    assert replay["replayed"] and len(app.requests) == 8
    assert len(ctx.runs.artifacts(run)) == 1
    persisted = json.dumps(ctx.runs.events(run)) + json.dumps(receipt)
    for secret in (app.secret, "owner-token", "observer-token"):
        assert secret not in persisted


async def test_fresh_independent_fixture_reproduces_with_new_private_data(monkeypatch, managed):
    for value in ("first-independent-secret", "fresh-independent-secret"):
        app = BolaApplication(vulnerable=True, secret=value)
        monkeypatch.setattr(http, "_blocking_fetch", app.transport)
        run = managed.runs.create("example.test", budget=RunBudget(8, 2, 0))["id"]
        receipt = await execute_tool(managed, sdk.registered_tools(server.mcp), run, "authz_probe",
                                     {"target": TARGET, "second_headers": OBSERVER, "proof": manifest()})
        assert expand_result(managed, receipt)["data"]["proof"]["verified"]
        assert len(app.requests) == 8


@pytest.mark.parametrize("budget", [0, 3, 7])
async def test_budget_stop_cannot_leave_verified_proof(monkeypatch, managed, budget):
    app = BolaApplication(vulnerable=True)
    monkeypatch.setattr(http, "_blocking_fetch", app.transport)
    run = managed.runs.create("example.test", budget=RunBudget(budget, 2, 0))["id"]
    receipt = await execute_tool(managed, sdk.registered_tools(server.mcp), run, "authz_probe",
                                 {"target": TARGET, "second_headers": OBSERVER, "proof": manifest()})
    assert not receipt["ok"] and receipt["error"] == "budget_exhausted"
    assert len(app.requests) == budget
    assert not expand_result(managed, receipt)["data"]["proof"]["verified"]


async def test_cancellation_retains_unknown_receipt_without_retry(monkeypatch, managed):
    started = asyncio.Event()
    async def interrupted(*args, **kwargs):
        started.set()
        await asyncio.Event().wait()
    monkeypatch.setattr(managed.http, "fetch", interrupted)
    run = managed.runs.create("example.test")["id"]
    tools = sdk.registered_tools(server.mcp)
    args = {"target": TARGET, "second_headers": OBSERVER, "proof": manifest()}
    task = asyncio.create_task(execute_tool(managed, tools, run, "authz_probe", args, idempotency_key="stop"))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    receipt = await execute_tool(managed, tools, run, "authz_probe", args, idempotency_key="stop")
    assert receipt["state"] == "unknown" and not receipt["retryable"]
