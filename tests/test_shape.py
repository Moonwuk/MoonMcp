"""response_format shaping — concise/detailed views of large results."""

import pytest

from moonmcp import server as srv
from moonmcp.shape import apply, concise


# -- pure --------------------------------------------------------------------
def test_short_list_untouched():
    obj = {"items": [1, 2, 3], "name": "x"}
    assert concise(obj, max_list=20) == obj


def test_long_list_trimmed_with_sentinel():
    obj = {"items": list(range(50))}
    out = concise(obj, max_list=20)
    assert len(out["items"]) == 21              # 20 + sentinel
    assert out["items"][:20] == list(range(20))
    sentinel = out["items"][-1]
    assert sentinel["_truncated"] == 50
    assert sentinel["_shown"] == 20
    assert "detailed" in sentinel["_hint"]


def test_exactly_at_threshold_not_trimmed():
    obj = {"items": list(range(20))}
    assert concise(obj, max_list=20)["items"] == list(range(20))


def test_nested_lists_are_trimmed():
    obj = {"a": {"b": list(range(30))}, "c": [{"d": list(range(25))}]}
    out = concise(obj, max_list=10)
    assert len(out["a"]["b"]) == 11
    assert len(out["c"][0]["d"]) == 11


def test_scalars_and_other_types_passthrough():
    assert concise("hello") == "hello"
    assert concise(42) == 42
    assert concise(None) is None


def test_apply_detailed_is_identity():
    obj = {"items": list(range(50))}
    assert apply(obj, "detailed") is obj


def test_apply_detailed_case_insensitive():
    obj = {"items": list(range(50))}
    assert apply(obj, "DETAILED") is obj


def test_apply_concise_trims():
    obj = {"items": list(range(50))}
    out = apply(obj, "concise")
    assert len(out["items"]) == 21


def test_apply_unknown_value_defaults_to_concise():
    obj = {"items": list(range(50))}
    out = apply(obj, "garbage")
    assert len(out["items"]) == 21   # anything != "detailed" is concise (safe default)


# -- e2e: a wired tool honours the param -------------------------------------
@pytest.mark.asyncio
async def test_memory_graph_concise_vs_detailed(fresh_context):
    ctx = srv.get_context()
    for i in range(35):
        ctx.memory.add_entity(kind="endpoint", name=f"/api/e{i}", target="t.example")
    concise_res = await srv.memory_graph(target="t.example", response_format="concise")
    detailed_res = await srv.memory_graph(target="t.example", response_format="detailed")
    assert len(detailed_res["entities"]) >= len(concise_res["entities"])
    assert len(detailed_res["entities"]) == 35
    assert len(concise_res["entities"]) == 21  # 20 + sentinel


@pytest.mark.asyncio
async def test_list_findings_accepts_response_format(fresh_context):
    # small result: concise and detailed are identical (nothing to trim).
    c = await srv.list_findings(response_format="concise")
    d = await srv.list_findings(response_format="detailed")
    assert c == d
