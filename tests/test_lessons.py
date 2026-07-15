"""Lesson hygiene — confidence (voting), staleness, contradiction detection."""

import pytest

from moonmcp import lessons as L
from moonmcp import server as srv
from moonmcp.memory import MemoryStore

_NOW = "2026-07-15T00:00:00+00:00"
_OLD = "2025-01-01T00:00:00+00:00"


# -- pure --------------------------------------------------------------------
def test_confidence_label():
    assert L.confidence_label(1) == "unverified"
    assert L.confidence_label(2) == "supported"
    assert L.confidence_label(3) == "corroborated"
    assert L.confidence_label(9) == "corroborated"


def test_polarity():
    assert L.polarity("SSTI works on the search param") == 1
    assert L.polarity("bypass succeeded") == 1
    assert L.polarity("technique does not work") == -1
    assert L.polarity("the WAF blocked it") == -1


def test_find_contradictions_opposite_polarity_same_subject():
    rows = [
        {"id": 1, "title": "SSTI works on the search param", "body": ""},
        {"id": 2, "title": "SSTI does not work on the search param", "body": ""},
    ]
    c = L.find_contradictions(rows)
    assert len(c) == 1
    assert {c[0]["a"]["id"], c[0]["b"]["id"]} == {1, 2}


def test_no_contradiction_when_same_polarity():
    rows = [
        {"id": 1, "title": "SSTI works on the search param", "body": ""},
        {"id": 2, "title": "SSTI works on the login param", "body": ""},
    ]
    assert L.find_contradictions(rows) == []


def test_no_contradiction_when_different_subject():
    rows = [
        {"id": 1, "title": "SSTI works on search", "body": ""},
        {"id": 2, "title": "XXE does not work on upload", "body": ""},
    ]
    assert L.find_contradictions(rows) == []


def test_staleness():
    assert L.is_stale(_OLD, _NOW, ttl_days=180) is True
    assert L.is_stale(_NOW, _NOW, ttl_days=180) is False
    assert L.is_stale("", _NOW, ttl_days=180) is False        # undated → never stale
    assert L.is_stale("not-a-date", _NOW, ttl_days=180) is False
    assert L.age_days(_OLD, _NOW) is not None and L.age_days(_OLD, _NOW) > 500
    assert L.age_days("", _NOW) is None


def test_annotate_adds_fields():
    rows = [{"id": 1, "title": "t", "body": "b", "tags": "lesson",
             "confidence": 3, "created_at": _OLD}]
    out = L.annotate(rows, now_iso=_NOW, ttl_days=180)
    assert out[0]["confidence_label"] == "corroborated"
    assert out[0]["stale"] is True
    assert out[0]["age_days"] > 500


# -- MemoryStore integration -------------------------------------------------
def test_record_lesson_corroborates_on_repeat():
    m = MemoryStore()
    first = m.record_lesson(title="parser_diff blocked by Cloudflare", body="v1", now=_NOW)
    assert first["confidence"] == 1 and first["corroborated"] is False
    second = m.record_lesson(title="parser_diff blocked by Cloudflare", body="v2 refined", now=_NOW)
    assert second["confidence"] == 2 and second["corroborated"] is True
    assert second["id"] == first["id"]                        # same row, not a dup
    # the recalled row reflects the bumped confidence + latest body
    hit = next(x for x in m.lessons("parser_diff") if x["id"] == first["id"])
    assert hit["confidence"] == 2 and hit["body"] == "v2 refined"


def test_prune_lessons_drops_only_stale_uncorroborated():
    m = MemoryStore()
    m.record_lesson(title="stale one-off", body="", now=_OLD)              # stale, conf 1 → prune
    m.record_lesson(title="stale but trusted", body="", now=_OLD)
    m.record_lesson(title="stale but trusted", body="", now=_OLD)          # conf 2 → keep
    m.record_lesson(title="fresh one-off", body="", now=_NOW)             # fresh → keep
    m.record_lesson(title="undated one-off", body="", now="")             # undated → keep
    removed = m.prune_lessons(now=_NOW, ttl_days=180)
    assert removed == 1
    titles = {x["title"] for x in m.lessons("", limit=50)}
    assert "stale one-off" not in titles
    assert {"stale but trusted", "fresh one-off", "undated one-off"} <= titles


# -- tool e2e ----------------------------------------------------------------
@pytest.mark.asyncio
async def test_memory_lesson_tool_confidence_and_contradiction(fresh_context):
    a = await srv.memory_lesson(action="add", title="SSTI works on the q param",
                                body="jinja2 marker reflected")
    assert a["added"]["confidence"] == 1
    assert a["added"]["confidence_label"] == "unverified"
    # corroborate it
    a2 = await srv.memory_lesson(action="add", title="SSTI works on the q param", body="again")
    assert a2["added"]["confidence"] == 2 and a2["added"]["confidence_label"] == "supported"
    # add a contradicting lesson, then recall surfaces the contradiction
    await srv.memory_lesson(action="add", title="SSTI does not work on the q param", body="patched")
    rec = await srv.memory_lesson(action="recall", query="SSTI")
    assert rec["contradictions"]
    assert all("confidence_label" in le for le in rec["lessons"])


@pytest.mark.asyncio
async def test_memory_lesson_prune_action(fresh_context):
    res = await srv.memory_lesson(action="prune", ttl_days=180)
    assert "pruned" in res
