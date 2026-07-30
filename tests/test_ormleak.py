"""ORM leak / relational-filter injection — pure candidates + differential eval."""

import pytest

from moonmcp import server as srv
from moonmcp.web import ormleak as orm


# -- pure --------------------------------------------------------------------
def test_django_candidates():
    cands = dict(orm.django_candidates())
    assert cands["password"] == "password__startswith"
    assert cands["user__password"] == "user__password__startswith"


def test_prisma_ransack_candidates():
    assert orm.prisma_candidates("filter")[0][1] == "filter[password][startsWith]"
    assert orm.ransack_candidates("q")[0][1] == "q[password_start]"


def test_candidates_selection():
    families = {f for f, _, _ in orm.candidates("auto", "filter")}
    assert families == {"django", "prisma", "ransack"}
    assert {f for f, _, _ in orm.candidates("django", "filter")} == {"django"}


def test_looks_applied():
    # reproducible differential (all=500 vs none=30) → gate passes
    assert orm.looks_applied(((200, 500), (200, 500)), ((200, 30), (200, 30))) is True
    # no differential → gate fails
    assert orm.looks_applied(((200, 500), (200, 500)), ((200, 500), (200, 500))) is False
    # a status flip that beats no length change is still a real differential
    assert orm.looks_applied(((200, 500), (200, 500)), ((404, 500), (404, 500))) is True
    # non-reproducible status on an arm → rejected as noise
    assert orm.looks_applied(((200, 500), (500, 500)), ((200, 30), (200, 30))) is False
    # sub-jitter length wobble is tolerated (nonce/timestamp), not a hit on its own
    assert orm.looks_applied(((200, 500), (200, 508)), ((200, 503), (200, 505))) is False


def test_assess_lookup_reflection_control():
    # genuine filter: the "no rows" page is value-independent, so the longer alt
    # no-match value renders the same length as CONTROL_NONE → hit.
    assert orm.assess_lookup(
        ((200, 500), (200, 500)),      # all: matches everything
        ((200, 30), (200, 30)),        # none: zero rows
        ((200, 30), (200, 30)),        # none_alt (longer value): still zero rows, same page
    ) is True
    # reflection/echo: response length tracks the injected value's length, so the
    # longer alt value produces a longer page → NOT a filter, verdict withheld.
    assert orm.assess_lookup(
        ((200, 100), (200, 100)),      # all: value="" → short
        ((200, 117), (200, 117)),      # none: 17-char value reflected
        ((200, 161), (200, 161)),      # none_alt: 61-char value reflected → longer
    ) is False
    # no differential at all → not a hit regardless of the control
    assert orm.assess_lookup(
        ((200, 500), (200, 500)), ((200, 500), (200, 500)), ((200, 500), (200, 500))
    ) is False
    # non-reproducible alt control → rejected (can't trust the reflection check)
    assert orm.assess_lookup(
        ((200, 500), (200, 500)), ((200, 30), (200, 30)), ((200, 30), (200, 90))
    ) is False


# -- end-to-end --------------------------------------------------------------
@pytest.mark.asyncio
async def test_orm_leak_detects(local_server, fresh_context):
    base, _ = local_server
    res = await srv.orm_leak_probe(target=f"{base}/orm-search", orm="django")
    assert res["verdict"] in ("likely", "confirmed"), res
    assert res["findings"] and any(f["field"] == "password" for f in res["findings"])


@pytest.mark.asyncio
async def test_orm_leak_no_false_positive(local_server, fresh_context):
    base, _ = local_server
    res = await srv.orm_leak_probe(target=f"{base}/orm-safe", orm="django")
    assert res["findings"] == [] and res["verdict"] == "unconfirmed"


@pytest.mark.asyncio
async def test_orm_leak_reflection_not_reported(local_server, fresh_context):
    # An endpoint that merely ECHOES the injected value produces a reproducible
    # empty-vs-nonempty length differential, but is not an ORM leak. The reflection
    # control (a longer no-match value) must keep it out of the findings.
    base, _ = local_server
    res = await srv.orm_leak_probe(target=f"{base}/orm-reflect", orm="django")
    assert res["findings"] == [], res
    assert res["verdict"] == "unconfirmed"


@pytest.mark.asyncio
async def test_orm_leak_intrusive_gated(local_server, fresh_context):
    from dataclasses import replace
    base, _ = local_server
    fresh_context.settings = replace(fresh_context.settings, allow_intrusive=False)
    res = await srv.orm_leak_probe(target=f"{base}/orm-search")
    assert res["error"] == "disabled"


@pytest.mark.asyncio
async def test_orm_leak_registered():
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "orm_leak_probe" in tools
