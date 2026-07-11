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


def test_assess_lookup():
    # empty-prefix "all" (200, 500) reproducible; "none" (200, 30) reproducible; differ → hit
    assert orm.assess_lookup(((200, 500), (200, 500)), ((200, 30), (200, 30))) is True
    # no differential → not a hit
    assert orm.assess_lookup(((200, 500), (200, 500)), ((200, 500), (200, 500))) is False
    # non-reproducible "all" → rejected (noise)
    assert orm.assess_lookup(((200, 500), (200, 480)), ((200, 30), (200, 30))) is False


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
