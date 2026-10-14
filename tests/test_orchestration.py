"""Agent workflow errors and unreviewed observations retain their meaning."""

import pytest
from mcp.types import CallToolResult, TextContent

from moonmcp.memory import MemoryStore
from moonmcp.orchestration import (
    BaseAgent,
    ExploitAgent,
    OrchestratorAgent,
    PostExAgent,
    ReconAgent,
)
from moonmcp.strix_adapted import AgentGraph


@pytest.fixture
def memory():
    store = MemoryStore()
    yield store
    store.close()


@pytest.mark.parametrize("agent_cls", [BaseAgent, ReconAgent, ExploitAgent, PostExAgent])
def test_shared_agent_content_defaults_to_untrusted_inferred(agent_cls, memory):
    agent = agent_cls("example.com", memory=memory)
    item_id = agent.share("observation", "target supplied content")
    item = memory.get(item_id)
    assert item["trust"] == "untrusted" and item["provenance"] == "inferred"
    assert item["source"] == agent.agent_id
    reviewed = agent.share("reviewed conclusion", "checked evidence", trust="curated",
                           provenance="manual")
    assert memory.get(reviewed)["trust"] == "curated"
    assert memory.get(reviewed)["provenance"] == "manual"


def test_agent_share_cannot_overwrite_vetted_revision(memory):
    agent = ReconAgent("example.com", memory=memory)
    item_id = memory.add(kind="observation", title="same", body="reviewed", target="example.com",
                         trust="curated")
    assert agent.share("same", "unreviewed") == item_id
    assert memory.get(item_id)["body"] == "reviewed"
    assert memory.revisions(item_id)[0]["trust"] == "untrusted"


def test_recall_is_scoped_to_agent_target(memory):
    expected = memory.add(kind="observation", title="wanted", target="https://example.com/Case")
    memory.add(kind="observation", title="other", target="notexample.com")
    assert [item["id"] for item in ReconAgent("example.com", memory=memory).recall()] == [expected]


@pytest.mark.parametrize(("agent_cls", "callback_key"), [
    (ReconAgent, "actions"), (ExploitAgent, "probes"), (PostExAgent, "actions"),
])
@pytest.mark.parametrize("tool_result", [
    {"error": "out_of_scope"}, {"success": False}, {"ok": False},
    CallToolResult(content=[TextContent(type="text", text="tool failed")], isError=True),
])
def test_callback_error_stops_following_actions_and_marks_partial(
        agent_cls, callback_key, tool_result, memory):
    invoked = []

    def first(agent):
        invoked.append("first")
        agent.share("first action evidence", "recorded before later error")

    def failed(agent):
        invoked.append("failed")
        return tool_result

    def forbidden(agent):
        invoked.append("must not run")

    agent = agent_cls("example.com", memory=memory,
                      metadata={callback_key: [first, failed, forbidden]})
    result = agent.run()
    assert not result.success and result.state == "partial"
    assert result.errors[0]["action_index"] == 1
    assert result.errors[0]["skipped_actions"] == 1
    assert result.errors[0]["retryable"] is False
    assert invoked == ["first", "failed"]
    assert any(item["title"] == "first action evidence" for item in result.findings)
    assert all(item["trust"] == "untrusted" for item in memory.search(""))


def test_callback_exception_is_not_success_and_exposes_no_exception_message(memory):
    def raises(agent):
        raise RuntimeError("private token in error message")

    agent = ReconAgent("example.com", memory=memory, metadata={"actions": [raises]})
    result = agent.run()
    assert not result.success and result.state == "failed"
    assert result.errors[0]["error"] == "callback_exception"
    assert result.errors[0]["exception_type"] == "RuntimeError"
    assert "private token" not in str(result.errors)


def test_unconfirmed_verdict_and_nested_observations_are_valid_outcomes(memory):
    agent = ExploitAgent("example.com", memory=memory, metadata={"probes": [
        lambda _: {"verdict": "unconfirmed", "evidence": {"error": "negative control"}},
        lambda _: None,
    ]})
    result = agent.run()
    assert result.success and result.state == "completed" and not result.errors


@pytest.mark.filterwarnings("error::RuntimeWarning")
def test_sync_driver_rejects_async_callback_instead_of_claiming_it_executed(memory):
    invoked = []

    async def callback(agent):
        invoked.append("executed")
        return {"ok": True}

    result = ReconAgent("example.com", memory=memory,
                        metadata={"actions": [callback]}).run()
    assert not result.success and not invoked
    assert result.errors[0]["error"] == "async_callback_unsupported"


def test_generated_report_keeps_untrusted_source_label_and_is_not_curated(memory):
    memory.add(kind="finding", title="unverified claim", target="example.com", trust="untrusted")
    agent = PostExAgent("example.com", memory=memory)
    result = agent.run()
    assert result.success
    report = memory.search("", kind="knowledge", target="example.com")[0]
    assert report["title"] == "Report: example.com"
    assert report["trust"] == "untrusted" and report["provenance"] == "inferred"
    assert "unverified claim (trust: untrusted)" in report["body"]


def test_partial_report_records_execution_limitations(memory):
    agent = PostExAgent("example.com", memory=memory, metadata={"actions": [
        lambda _: {"error": "missing_dependency"},
    ]})
    result = agent.run()
    assert not result.success
    assert "Incomplete execution" in agent.report
    assert "Later actions were skipped" in agent.report


def test_orchestrator_propagates_child_failure_and_blocks_later_phases(memory):
    graph = AgentGraph()
    parent = OrchestratorAgent("example.com", memory=memory, graph=graph)
    parent.register()
    recon = parent.spawn_child("recon", metadata={"actions": [lambda _: {"error": "out_of_scope"}]})
    later = []
    exploit = parent.spawn_child("exploit", metadata={"probes": [lambda _: later.append("bad")]})
    result = parent.run()
    assert not result.success and result.state == "blocked"
    assert "0/2" in result.summary and not later
    assert recon.status == graph.statuses[recon.agent_id] == "blocked"
    assert exploit.status == graph.statuses[exploit.agent_id] == "blocked"
    assert {error["error"] for error in result.errors} == {"out_of_scope", "prerequisite_failed"}


def test_orchestrator_reports_partial_completion(memory):
    parent = OrchestratorAgent("example.com", memory=memory)
    recon = parent.spawn_child("recon", metadata={"actions": [lambda _: {"ok": True}]})
    parent.spawn_child("exploit", metadata={"probes": [lambda _: {"error": "disabled"}]})
    result = parent.run()
    assert not result.success and result.state == "partial" and "1/2" in result.summary
    assert recon.status == "completed"


def test_successful_workflow_completes_all_children_without_promoting_observations(memory):
    parent = OrchestratorAgent("example.com", memory=memory)
    parent.spawn_child("recon", metadata={"actions": [lambda agent: agent.add_endpoint("/api")]})
    parent.spawn_child("exploit", metadata={"probes": [lambda _: {"verdict": "unconfirmed"}]})
    parent.spawn_child("post-ex")
    result = parent.run()
    assert result.success and result.state == "completed" and not result.errors
    assert "3/3" in result.summary and all(child.status == "completed" for child in parent.children)
    assert all(item["trust"] == "untrusted" for item in memory.search(""))


def test_budget_stop_records_each_skipped_child_instead_of_zero_of_zero_success(memory):
    graph = AgentGraph()
    parent = OrchestratorAgent("example.com", memory=memory, graph=graph)
    invoked = []
    for role in ("recon", "exploit", "post-ex"):
        key = "probes" if role == "exploit" else "actions"
        parent.spawn_child(role, metadata={key: [lambda _: invoked.append("bad")]})
    graph.trigger_budget_stop()
    result = parent.run()
    assert not result.success and result.state == "blocked" and "0/3" in result.summary
    assert not invoked and len(result.errors) == 3
    assert all(child.status == "blocked" for child in parent.children)


def test_budget_stop_between_callbacks_keeps_partial_outcome(memory):
    graph = AgentGraph()
    invoked = []
    agent = ReconAgent("example.com", memory=memory, graph=graph, metadata={"actions": [
        lambda _: graph.trigger_budget_stop(), lambda _: invoked.append("bad"),
    ]})
    result = agent.run()
    assert not result.success and result.state == "partial" and not invoked
    assert result.errors[0]["error"] == "budget_exhausted"
    assert result.errors[0]["skipped_actions"] == 1


def test_unknown_child_outcome_stays_unknown_at_parent(memory):
    parent = OrchestratorAgent("example.com", memory=memory)
    child = parent.spawn_child("exploit", metadata={"probes": [
        lambda _: {"ok": False, "state": "unknown", "error": "outcome_unknown"},
    ]})
    result = parent.run()
    assert not result.success and result.state == child.status == "unknown"


def test_child_exception_preserves_failure_and_blocks_later_work(memory, monkeypatch):
    parent = OrchestratorAgent("example.com", memory=memory)
    child = parent.spawn_child("recon")
    next_child = parent.spawn_child("exploit")

    def raises():
        raise RuntimeError("failed before callback handling")

    monkeypatch.setattr(child, "run", raises)
    result = parent.run()
    assert not result.success and result.errors[0]["error"] == "child_crashed"
    assert child.status == "crashed" and next_child.status == "blocked"


@pytest.mark.parametrize("state", ["unknown", "partial", "blocked", "cancelled"])
def test_native_protocol_outcome_reaches_agent_state(state, memory):
    from moonmcp.outcomes import RESULT_META, outcome

    status = outcome({"ok": False, "state": state})
    native = CallToolResult(content=[TextContent(type="text", text="receipt")], isError=True,
                            _meta={RESULT_META: status.metadata()})
    agent = ReconAgent("example.com", memory=memory, metadata={"actions": [lambda _: native]})
    result = agent.run()
    assert result.state == state
    assert not result.success
    assert result.errors[0]["error"] == status.error.code
