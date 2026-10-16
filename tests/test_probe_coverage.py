"""Unavailable evidence must not become a clean negative at any boundary."""

import asyncio
from types import SimpleNamespace

import pytest

from moonmcp import server
from moonmcp.net.http import HttpResult
from moonmcp.outcomes import RESULT_META, outcome
from moonmcp.web.authz import probe_bola
from moonmcp.web.checks import ProbeChecks
from moonmcp.web.workflow import probe_workflow_skip

URL = "https://example.test/orders/100"
FLOW = [{"url": URL}, {"url": URL + "/confirm"}]


def response(status=200, body=b'{"id":100,"private":"object-value"}', **kwargs):
    return HttpResult(URL, URL, status, "", [], body, 0, **kwargs)


class Client:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    async def fetch(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]


@pytest.mark.parametrize("bad", [
    response(None, error="timeout"), response(503), response(429),
    response(truncated=True), response(None, blocked_reason="out of scope"),
])
async def test_no_usable_response_is_inconclusive(bad):
    for result in [await probe_bola(Client(bad), URL),
                   await probe_workflow_skip(Client(bad), FLOW)]:
        assert not outcome(result).ok
        assert result["verdict"] == "inconclusive"
        assert not result["coverage"]["complete"]
        assert result["checks"][0]["error"]
        assert result["retryable"] is False


async def test_partial_probe_keeps_leads_without_claiming_coverage():
    result = await probe_workflow_skip(Client(response(), response(None, error="timeout")),
                                       FLOW + [{"url": URL + "/finish"}])
    assert result["state"] == "partial"
    assert result["verdict"] == "review"
    assert len(result["findings"]) == 1
    assert result["coverage"] == {"version": 1, "complete": False, "completed": 1, "total": 2}


@pytest.mark.parametrize("status", [401, 403, 404])
async def test_unavailable_owner_is_not_negative_bola(status):
    result = await probe_bola(Client(response(status)), URL)
    assert result["verdict"] == "inconclusive"
    assert any(c["error"] == "owner_object_unavailable" for c in result["checks"])


async def test_valid_negative_remains_completed():
    result = await probe_bola(Client(response(), response(403)), URL)
    assert outcome(result).ok and result["verdict"] == "no_obvious_bola"
    result = await probe_workflow_skip(Client(response(302)), FLOW)
    assert outcome(result).ok and result["verdict"] == "no_step_skip"


async def test_no_steps_are_not_a_completed_check():
    for steps in ([], FLOW[:1], FLOW + [{"invalid": True}]):
        result = await probe_workflow_skip(Client(response(403)), steps)
        assert result["verdict"] == "inconclusive"


@pytest.mark.parametrize("bad", [response(None, error="timeout"), response(500)])
async def test_ambiguous_mutation_stops_subsequent_steps(bad):
    client = Client(bad, response())
    steps = [FLOW[0], {**FLOW[1], "method": "POST"}, {"url": URL + "/finish"}]
    result = await probe_workflow_skip(client, steps)
    assert result["state"] == "unknown"
    assert result["checks"][-1]["state"] == "skipped"
    assert len(client.responses) == 1


@pytest.mark.parametrize("method", ["GET", "HEAD"])
async def test_rate_limit_stops_later_reads(method):
    checks = ProbeChecks()
    client = Client(response(429), response())
    assert await checks.fetch(client, URL, check="first", method=method) is None
    assert await checks.fetch(client, URL + "/later", check="later", method="GET") is None
    assert len(client.calls) == 1
    result = checks.finish({"findings": []}, negative="negative")
    assert result["verdict"] == "inconclusive"
    assert result["checks"][0]["error"] == "rate_limited"
    assert result["checks"][1]["error"] == "prior_check_stopped"
    assert result["coverage"] == {"version": 1, "complete": False, "completed": 0, "total": 2}


async def test_rate_limit_stops_bola_siblings_and_later_workflow_steps():
    bola = Client(response(), response(429), response())
    workflow = Client(response(429), response())
    results = [await probe_bola(bola, URL),
               await probe_workflow_skip(workflow, FLOW + [{"url": URL + "/finish"}])]
    assert len(bola.calls) == 2 and len(workflow.calls) == 1
    for result in results:
        assert not result["ok"] and result["verdict"] == "inconclusive"
        assert result["checks"][-1]["error"] == "prior_check_stopped"


async def test_workflow_does_not_discard_decisive_trailing_bytes():
    client = Client(response(body=b"x" * 50_001 + b"confirmed"))
    result = await probe_workflow_skip(client, [FLOW[0], {**FLOW[1], "success": "confirmed"}])
    assert result["ok"] and result["verdict"] == "review"


async def test_cancellation_propagates_for_durable_recovery():
    class Cancelled:
        async def fetch(self, *args, **kwargs):
            raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        await probe_workflow_skip(Cancelled(), FLOW)


async def test_mcp_exposes_incomplete_bola_without_reassuring_note(monkeypatch, fresh_context):
    monkeypatch.setattr(fresh_context, "http", Client(response(None, error="timeout")))
    async def admitted(*args, **kwargs):
        return "example.test"
    monkeypatch.setattr(server, "_require_scope", admitted)
    monkeypatch.setattr(server, "_scope_check", lambda: lambda _: True)
    result = await server.mcp.call_tool("authz_probe", {"target": URL})
    assert result.isError
    assert result.meta[RESULT_META]["ok"] is False
    assert result.structuredContent["verdict"] == "inconclusive"
    assert "incomplete" in result.structuredContent["note"]


async def test_execution_block_preserves_earlier_leads():
    from moonmcp.execution import ExecutionBlocked

    calls = []
    async def fetch(*args, **kwargs):
        calls.append(1)
        if len(calls) > 1:
            raise ExecutionBlocked("budget_exhausted", "budget exhausted")
        return response()
    result = await probe_workflow_skip(SimpleNamespace(fetch=fetch), FLOW * 2)
    assert result["state"] == "partial"
    assert result["findings"]
    assert result["checks"][1]["error"] == "budget_exhausted"
    assert len(calls) == 2
