"""Evidence integrity and lifecycle regressions from the flag-system review."""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from moonmcp.flags import FlagStore, target_key


def evidence(name):
    return [{"ref": f"artifact:{name}", "source_group": f"observation:{name}"}]


def record(store, observation, *, project="assessment", target="example.test", **kwargs):
    return store.record(project, target, observation, evidence(observation), **kwargs)["flag"]


def propose(store, flag_id, **kwargs):
    return store.propose(
        "assessment", "example.test", "The two routes apply different access rules",
        [flag_id], "Compare equivalent requests in the same role", "A repeatable difference",
        **kwargs,
    )


@pytest.fixture
def store():
    instance = FlagStore()
    try:
        yield instance
    finally:
        instance.close()


def test_normalized_project_keeps_every_mutation_in_the_same_audit_history(store):
    first = record(store, "First observation")
    second = record(store, "Second observation")
    store.update(" assessment ", first["id"], "reviewed", "Checked source", evidence("review"))
    store.link(" assessment ", first["id"], second["id"], "related", "Same route")
    hypothesis = propose(store, first["id"])
    store.review_hypothesis(" assessment ", hypothesis["id"], "testing", "Started comparison")

    assert [event["kind"] for event in store.history("assessment", first["id"])] == [
        "recorded", "review",
    ]
    assert store.history("assessment", second["id"])[-1]["kind"] == "linked"
    assert store.history("assessment", hypothesis["id"])[-1]["detail"]["status"] == "testing"
    assert store.history(" assessment ", hypothesis["id"]) == store.history(
        "assessment", hypothesis["id"],
    )


def test_link_reason_edits_match_persisted_result_and_identical_retries_add_no_events(store):
    first = record(store, "First source")
    second = record(store, "Second source")
    store.link("assessment", first["id"], second["id"], "related", "First explanation")
    updated = store.link(
        "assessment", first["id"], second["id"], "related", "Revised explanation",
    )
    persisted = store.get("assessment", first["id"])["links"][0]
    history = store.history("assessment", second["id"])

    assert updated["reason"] == persisted["reason"] == "Revised explanation"
    assert history[-1]["detail"]["before"]["reason"] == "First explanation"
    assert store.link(
        "assessment", first["id"], second["id"], "related", "Revised explanation",
    ) == updated
    assert store.history("assessment", second["id"]) == history


def test_concurrent_duplicate_records_across_connections_are_idempotent(tmp_path):
    path = str(tmp_path / "flags.db")
    stores = [FlagStore(path), FlagStore(path)]
    start = Barrier(2)

    def writer(instance):
        results = []
        for index in range(12):
            # Synchronize before entering either transaction; never hold a database lock here.
            start.wait(timeout=10)
            results.append(instance.record(
                "assessment", "example.test", f"Observation {index}", evidence(str(index)),
            ))
        return results

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            left, right = list(executor.map(writer, stores))
        for first, second in zip(left, right, strict=True):
            assert first["flag"]["id"] == second["flag"]["id"]
            assert sum((first["created"], second["created"])) == 1
            assert len(stores[0].history("assessment", first["flag"]["id"])) == 1
        assert stores[0].query("assessment")["total"] == 12
    finally:
        for instance in stores:
            instance.close()


def test_expired_support_can_be_replaced_without_erasing_history(store):
    old = record(
        store, "Earlier observation", observed_at="2000-01-01T00:00:00Z",
        expires_at="2000-01-02T00:00:00Z",
    )
    hypothesis = propose(store, old["id"])
    fresh = record(store, "Repeated observation")
    store.link("assessment", fresh["id"], hypothesis["id"], "supports", "Fresh repetition")

    with pytest.raises(ValueError, match="retire"):
        store.review_hypothesis(
            "assessment", hypothesis["id"], "supported", "Checked again", evidence("check"),
            test_outcome="completed",
        )

    store.link(
        "assessment", old["id"], hypothesis["id"], "supports", "Superseded by fresh evidence",
        active=False,
    )
    reviewed = store.review_hypothesis(
        "assessment", hypothesis["id"], "supported", "Checked again", evidence("check"),
        test_outcome="completed",
    )
    assert reviewed["effective_status"] == "supported"
    assert reviewed["invalid_support"] == []
    assert reviewed["finding_promoted"] is False
    old_link = next(flag for flag in reviewed["flags"] if flag["flag_id"] == old["id"])
    assert not old_link["active"]
    assert old_link["effective_status"] == "stale"
    assert any(event["kind"] == "relation_retired" for event in reviewed["history"])
    assert store.get("assessment", old["id"])["observation"] == "Earlier observation"


def test_contradiction_requires_explicit_resolution_and_remains_in_history(store):
    supporting = record(store, "Different responses")
    contradicting = record(store, "Equivalent control response")
    hypothesis = propose(store, supporting["id"], contradicting_flags=[contradicting["id"]])
    with pytest.raises(ValueError, match="contradicting"):
        store.review_hypothesis(
            "assessment", hypothesis["id"], "supported", "Test finished", evidence("check"),
            test_outcome="completed",
        )
    store.link(
        "assessment", contradicting["id"], hypothesis["id"], "contradicts",
        "Control used a different role, established by the check artifact", active=False,
    )
    reviewed = store.review_hypothesis(
        "assessment", hypothesis["id"], "supported", "Compared matching roles", evidence("check"),
        test_outcome="completed",
    )
    assert not reviewed["needs_review"]
    assert reviewed["contradicting_flags"] == []
    assert any(not link["active"] for link in reviewed["flags"])
    assert store.get("assessment", contradicting["id"])["status"] == "new"


def test_retiring_last_support_invalidates_current_supported_verdict(store):
    supporting = record(store, "Difference observed")
    hypothesis = propose(store, supporting["id"])
    store.review_hypothesis(
        "assessment", hypothesis["id"], "supported", "Completed comparison", evidence("check"),
        test_outcome="completed",
    )
    store.link(
        "assessment", supporting["id"], hypothesis["id"], "supports",
        "Evidence belongs to another context", active=False,
    )
    current = store.hypothesis("assessment", hypothesis["id"])
    assert current["needs_review"]
    assert current["effective_status"] != "supported"
    assert current["support_evidence_refs"] == []


def test_entities_and_alternative_claims_preserve_case_sensitive_identifiers(store):
    upper = record(store, "Uppercase route", entities=["/Admin"])
    lower = record(store, "Lowercase route", entities=["/admin"])
    related = store.related("assessment", upper["id"])
    match = next(item for item in related if item["flag_id"] == lower["id"])
    assert match["same_host"]
    assert match["shared_entities"] == []
    assert upper["entities"] == ["/Admin"]
    alternatives = ["/Admin is separate from /admin", "User ABC owns the object"]
    hypothesis = propose(store, upper["id"], alternatives=alternatives)
    assert set(hypothesis["alternatives"]) == set(alternatives)


@pytest.mark.parametrize("target", [".", "..", "exa mple.test", "https://exa mple.test/path"])
def test_invalid_hosts_do_not_create_empty_or_ambiguous_correlation_keys(target):
    with pytest.raises(ValueError):
        target_key(target)


def test_old_exact_context_match_survives_large_unrelated_history_without_linear_reads(store):
    old = record(store, "Original clue", target="older.test", entities=["object:SharedCaseID"])
    for index in range(205):
        record(store, f"Unrelated {index}", target=f"unrelated-{index}.test")
    current = record(store, "Fresh clue", target="newer.test", entities=["object:SharedCaseID"])

    statements = []
    store._db.set_trace_callback(statements.append)
    try:
        related = store.related("assessment", current["id"], limit=1)
    finally:
        store._db.set_trace_callback(None)
    assert [item["flag_id"] for item in related] == [old["id"]]
    # Bound database round trips, not wall-clock latency, to avoid a timing-sensitive test.
    assert sum(statement.lstrip().upper().startswith("SELECT") for statement in statements) < 20


def test_failed_audit_write_rolls_back_flag_and_releases_other_connection(tmp_path, monkeypatch):
    path = str(tmp_path / "flags.db")
    first, second = FlagStore(path), FlagStore(path)
    second._db.execute("PRAGMA busy_timeout=0")

    def fail_event(*_args):
        raise RuntimeError("audit write failed")

    try:
        monkeypatch.setattr(first, "_event", fail_event)
        with pytest.raises(RuntimeError, match="audit write failed"):
            record(first, "Observation with failed audit")
        assert second.query("assessment")["total"] == 0
        created = record(second, "Observation with failed audit")
        assert second.get("assessment", created["id"])["observation"] == created["observation"]
        assert len(second.history("assessment", created["id"])) == 1
    finally:
        first.close()
        second.close()


def test_same_observation_time_normalizes_timezone_but_later_occurrence_is_distinct(store):
    first = record(store, "Repeated clue", observed_at="2025-01-01T12:00:00+03:00")
    retry = record(store, "Repeated clue", observed_at="2025-01-01T09:00:00Z")
    later = record(store, "Repeated clue", observed_at="2025-01-02T09:00:00Z")
    assert first["id"] == retry["id"]
    assert later["id"] != first["id"]
    assert store.query("assessment")["total"] == 2
