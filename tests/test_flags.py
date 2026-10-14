"""Observation-to-hypothesis workflows retain context, provenance and uncertainty."""

import pytest

from moonmcp import server as srv
from moonmcp.config import Settings
from moonmcp.context import build_context
from moonmcp.flags import EvidenceRef, FlagStore


def source(ref="artifact:response-1", group="response-1"):
    return {"ref": ref, "source_group": group}


def record(store, observation="Old API path in JS", **kwargs):
    return store.record("assessment", "https://api.example.com/App", observation,
                        [source()], **kwargs)["flag"]


def test_puzzle_has_evidence_but_never_promotes_a_finding(tmp_path):
    path = str(tmp_path / "memory.db")
    store = FlagStore(path)
    js = record(store, entities=["component:orders"], next_check="Read the API contract")
    route = store.record("assessment", "api.example.com", "Old route exists",
                         [source("artifact:response-2", "response-2")],
                         entities=["component:orders"], auth_context="role:reader")["flag"]
    assert store.related("assessment", route["id"])[0]["flag_id"] == js["id"]
    hypothesis = store.propose("assessment", "api.example.com", "Versions apply different access rules",
                              [js["id"], route["id"]], "Compare a matched role/control pair",
                              "Stable difference with the same resource", alternatives=["Stale cache"])
    assert hypothesis["status"] == "proposed"
    assert len(hypothesis["support_source_groups"]) == 2
    with pytest.raises(ValueError, match="completed check"):
        store.review_hypothesis("assessment", hypothesis["id"], "refuted", "Transport failed",
                                [source("artifact:timeout", "check-1")], "failed")
    checked = store.review_hypothesis("assessment", hypothesis["id"], "inconclusive", "Transport failed",
                                      [source("artifact:timeout", "check-1")], "failed")
    assert checked["status"] == "inconclusive"
    supported = store.review_hypothesis("assessment", hypothesis["id"], "supported", "Control differed consistently",
                                        [source("artifact:control", "check-2")], "completed")
    assert supported["finding_promoted"] is False
    store.close()
    reopened = FlagStore(path)
    restored = reopened.hypothesis("assessment", hypothesis["id"], include_history=True)
    assert restored["status"] == "supported"
    assert [e["detail"].get("test_outcome") for e in restored["history"]][1:] == ["failed", "completed"]
    reopened.close()


def test_same_response_is_one_declared_source_and_roles_remain_visible():
    store = FlagStore()
    first = record(store, auth_context="role:A", importance="high")
    second = record(store, observation="Another clue from the same response", auth_context="role:B")
    hypothesis = store.propose("assessment", "api.example.com", "Possible role difference",
                               [first["id"], second["id"]], "Use distinct fresh controls", "Role-dependent output")
    assert hypothesis["support_source_groups"] == ["response-1"]
    assert {f["auth_context"] for f in hypothesis["flags"]} == {"role:A", "role:B"}
    assert first["observation_kind"] == "direct" and first["importance"] == "high"
    assert first["trust"] == "untrusted" and first["status"] == "new"
    assert store.related("assessment", first["id"])[0]["shared_source"] is True


def test_project_boundary_is_required_even_for_same_target():
    store = FlagStore()
    first = record(store)
    store.record("other-project", first["target"], "Other assessment", [source()])
    assert store.query("assessment")["total"] == 1
    for operation in (
        lambda: store.get("other-project", first["id"]),
        lambda: store.update("other-project", first["id"], "stale", "Wrong project"),
        lambda: store.propose("other-project", first["target"], "Cannot borrow evidence",
                              [first["id"]], "Compare", "Difference"),
        lambda: store.query(""),
    ):
        with pytest.raises(ValueError):
            operation()


def test_pagination_filters_status_target_and_unicode_before_limit():
    store = FlagStore()
    wanted = record(store, observation="Проверить авторизацию API")
    record(store, observation="Other relevant clue")
    for n in range(25):
        store.record("assessment", "notapi.example.com", f"Проверить другое {n}", [source()])
    page = store.query("assessment", target="api.example.com", query="авторизацию", limit=1)
    assert [f["id"] for f in page["flags"]] == [wanted["id"]]
    assert page["next_offset"] is None
    page = store.query("assessment", target="api.example.com", limit=1)
    assert page["total"] == 2 and page["next_offset"] == 1
    assert store.query("assessment", target="api.example.com", limit=1, offset=1)["next_offset"] is None
    store.update("assessment", wanted["id"], "reviewed", "Reproduced observation", [source("artifact:check", "check")])
    assert store.query("assessment", target="api.example.com", status="reviewed")["total"] == 1


def test_expiration_is_not_refutation_and_original_fact_is_immutable():
    store = FlagStore()
    flag = record(store, observed_at="2020-01-01T00:00:00Z", expires_at="2021-01-01T00:00:00Z")
    assert flag["status"] == "new" and flag["effective_status"] == "stale"
    assert store.query("assessment", status="new")["total"] == 0
    assert store.query("assessment", status="stale")["total"] == 1
    with pytest.raises(ValueError, match="fresh evidence"):
        store.update("assessment", flag["id"], "reviewed", "Cannot renew with old source", [source()])
    refuted = store.update("assessment", flag["id"], "refuted", "Control disproved observation",
                           [source("artifact:control", "control")])
    assert refuted["observation"] == flag["observation"]
    assert refuted["evidence"] == flag["evidence"]
    assert refuted["effective_status"] == "refuted"
    assert store.query("assessment", status="stale")["total"] == 0


@pytest.mark.parametrize("kwargs", [
    {"observation_kind": "confirmed"}, {"importance": "critical"},
    {"observed_at": "2020-01-01"}, {"expires_at": "yesterday"},
    {"observed_at": "2020-01-01T00:00:00Z", "expires_at": "2019-01-01T00:00:00Z"},
])
def test_invalid_lifecycle_inputs_do_not_create_partial_records(kwargs):
    store = FlagStore()
    with pytest.raises(ValueError):
        record(store, **kwargs)
    assert store.query("assessment")["total"] == 0


def test_explicit_context_storage_does_not_follow_another_environment(monkeypatch, tmp_path):
    environment_dir = tmp_path / "ambient"
    explicit_dir = tmp_path / "explicit"
    monkeypatch.setenv("MOONMCP_STATE_DIR", str(environment_dir))
    ctx = build_context(Settings(state_dir=str(explicit_dir)))
    try:
        assert ctx.memory.db_path == ctx.flags.db_path == str(explicit_dir / "memory.db")
        assert ctx.findings.db_path == str(explicit_dir / "findings.db")
        assert ctx.programs.state_dir == str(explicit_dir)
        flag = record(ctx.flags)
        assert ctx.flags.get("assessment", flag["id"])["observation"] == flag["observation"]
        assert not environment_dir.exists()
    finally:
        for obj in vars(ctx).values():
            close = getattr(obj, "close", None)
            if callable(close):
                close()


@pytest.mark.asyncio
async def test_mcp_tools_persist_flags_and_findings_across_context_restart(monkeypatch, tmp_path):
    monkeypatch.setenv("MOONMCP_STATE_DIR", str(tmp_path))
    ctx = build_context()
    ctx.scope.add("api.example.com")
    monkeypatch.setattr(srv, "_CTX", ctx)
    created_run = await srv.run_start("api.example.com")
    run_id = created_run["run"]["id"]
    flag = await srv.flag_record("assessment", "api.example.com", "Old API version observed",
                                 [EvidenceRef(**source())], run_id=run_id)
    assert "error" not in flag
    assert (await srv.memory_brief("api.example.com", project="assessment"))["analysis"]["flags"]["total"] == 1
    result = await srv.run_execute(run_id, "add_finding", {"target": "api.example.com", "severity": "info",
                                                          "title": "Explicit reviewed result"},
                                   idempotency_key="record-1")
    assert result["ok"], result
    assert ctx.findings.list(run_id=run_id)[0].run_id == run_id
    assert ctx.telemetry.get_stats()["findings_by_severity"]["info"] == 1
    replacement = build_context()
    monkeypatch.setattr(srv, "_CTX", replacement)
    summary = await srv.run_brief(run_id, project="assessment")
    assert summary["analysis"]["flags"]["total"] == 1
    assert len(summary["findings"]["findings"]) == 1
    assert summary["findings"]["findings"][0]["title"] == "Explicit reviewed result"
    assert (await srv.flag_record("assessment", "notapi.example.com", "Mismatched run",
                                  [EvidenceRef(**source())], run_id=run_id))["error"] == "invalid_input"
    for app in (ctx, replacement):
        for obj in vars(app).values():
            close = getattr(obj, "close", None)
            if callable(close):
                close()


@pytest.mark.asyncio
async def test_managed_observations_bind_the_executing_run(monkeypatch, tmp_path):
    monkeypatch.setenv("MOONMCP_STATE_DIR", str(tmp_path))
    ctx = build_context()
    monkeypatch.setattr(srv, "_CTX", ctx)
    run = ctx.runs.create("*.example.com")
    other = ctx.runs.create("api.example.com")
    arguments = {"project": "assessment", "target": "api.example.com",
                 "observation": "Version marker", "evidence": [source()]}
    try:
        recorded = await srv.run_execute(run["id"], "flag_record", arguments)
        assert recorded["ok"], recorded
        flag = recorded["data"]["flag"]
        assert flag["run_id"] == run["id"]
        proposed = await srv.run_execute(run["id"], "hypothesis_record", {
            "project": "assessment", "target": "api.example.com", "claim": "A version difference",
            "flag_ids": [flag["id"]], "test_plan": "Compare fresh responses",
            "expected_observation": "Different version markers",})
        assert proposed["ok"], proposed
        assert proposed["data"]["run_id"] == run["id"]
        for name, inputs in (
            ("flag_record", {**arguments, "run_id": other["id"]}),
            ("add_finding", {"target": "api.example.com", "severity": "info",
                             "title": "Other run", "run_id": other["id"]}),
            ("flag_record", {**arguments, "target": "notexample.com"}),
        ):
            rejected = await srv.run_execute(run["id"], name, inputs)
            assert rejected["error"] == "invalid_input", rejected
        assert ctx.flags.query("assessment")["total"] == 1
        assert ctx.findings.summary()["total"] == 0
    finally:
        for obj in vars(ctx).values():
            close = getattr(obj, "close", None)
            if callable(close):
                close()


@pytest.mark.asyncio
async def test_recovery_tools_preserve_unknown_receipt_and_record_evidence(monkeypatch, tmp_path):
    monkeypatch.setenv("MOONMCP_STATE_DIR", str(tmp_path))
    ctx = build_context()
    monkeypatch.setattr(srv, "_CTX", ctx)
    try:
        run = ctx.runs.create("api.example.com")
        receipt = ctx.runs.begin_invocation(run["id"], "fixture", "arguments")
        refused = await srv.run_recover(receipt["id"], "Worker stopped")
        assert refused["error"] == "invalid_input"
        await srv.run_control(run["id"], "pause")
        recovered = await srv.run_recover(receipt["id"], "Previous worker stopped")
        assert recovered["state"] == "unknown"
        proof = ctx.runs.add_artifact(run["id"], "review", "Outcome check", "Action was not executed")
        resolution = await srv.run_reconcile(receipt["id"], "not_executed", "Checked action log", [proof["id"]])
        assert resolution["resolution"]["outcome"] == "not_executed"
        stored = ctx.runs.get_invocation(receipt["id"])
        assert stored["state"] == "unknown"
        assert stored["resolution"]["evidence_artifact_ids"] == [proof["id"]]
    finally:
        for obj in vars(ctx).values():
            close = getattr(obj, "close", None)
            if callable(close):
                close()
