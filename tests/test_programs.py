"""Bug-bounty program / engagement profiles + per-program header injection."""

import json

import pytest

from moonmcp import server as srv
from moonmcp.programs import Program, ProgramStore, parse_header


def test_parse_header_ok():
    assert parse_header("X-Bug-Bounty: me@example.com") == ("X-Bug-Bounty", "me@example.com")
    # Only the first colon splits — values may contain colons.
    assert parse_header("X-H1: a:b:c") == ("X-H1", "a:b:c")


def test_parse_header_bad():
    with pytest.raises(ValueError):
        parse_header("no-colon-here")
    with pytest.raises(ValueError):
        parse_header(":  value")


def test_program_headers_view():
    p = Program(name="acme", header_name="X-Bug-Bounty", header_value="me@x.com",
                user_agent="acme-ua/1.0")
    assert p.headers() == {"X-Bug-Bounty": "me@x.com", "User-Agent": "acme-ua/1.0"}
    assert Program(name="bare").headers() == {}
    # An empty header value is still a valid (present) identifier.
    assert Program(name="e", header_name="X-Flag", header_value="").headers() == {"X-Flag": ""}


def test_program_store_persistence(tmp_path):
    store = ProgramStore(state_dir=str(tmp_path))
    store.add(Program(name="acme", scope=["acme.com"], scope_exclude=["blog.acme.com"],
                      header_name="X-BB", header_value="h"))
    store.use("acme")
    assert (tmp_path / "programs.json").exists()
    # A fresh store over the same dir resumes the program and its active selection.
    store2 = ProgramStore(state_dir=str(tmp_path))
    assert store2.active_name == "acme"
    reloaded = store2.get("acme")
    assert reloaded.scope == ["acme.com"]
    assert reloaded.scope_exclude == ["blog.acme.com"]
    assert store2.active_headers() == {"X-BB": "h"}


def test_program_store_remove_clears_active(tmp_path):
    store = ProgramStore(state_dir=str(tmp_path))
    store.add(Program(name="a"))
    store.use("a")
    assert store.remove("a") is True
    assert store.active_name is None
    assert store.active_headers() == {}


@pytest.mark.asyncio
async def test_program_add_activates_scope_and_injects_header(local_server, fresh_context):
    base, _ = local_server
    res = await srv.program_add(
        name="local", scope="127.0.0.1",
        header="X-Bug-Bounty: hunter@example.com", user_agent="MoonHunter/9.9",
    )
    assert res["active"] is True
    assert "127.0.0.1" in res["scope"]["in_scope"]

    # The program's identifying header + User-Agent must reach an in-scope request.
    r = await fresh_context.http.fetch(f"{base}/echo")
    echoed = json.loads(r.text())
    assert echoed.get("x-bug-bounty") == "hunter@example.com"
    assert echoed.get("user-agent") == "MoonHunter/9.9"


@pytest.mark.asyncio
async def test_program_use_switches_active_header(local_server, fresh_context):
    base, _ = local_server
    await srv.program_add(name="p1", scope="127.0.0.1",
                          header="X-Program: one", activate=True)
    await srv.program_add(name="p2", scope="127.0.0.1",
                          header="X-Program: two", activate=False)

    r1 = await fresh_context.http.fetch(f"{base}/echo")
    assert json.loads(r1.text()).get("x-program") == "one"

    used = await srv.program_use(name="p2")
    assert used["active"] == "p2"
    r2 = await fresh_context.http.fetch(f"{base}/echo")
    assert json.loads(r2.text()).get("x-program") == "two"


@pytest.mark.asyncio
async def test_program_use_unknown_returns_error(fresh_context):
    res = await srv.program_use(name="nope")
    assert res["error"] == "not_found"


@pytest.mark.asyncio
async def test_program_list_and_remove(fresh_context):
    await srv.program_add(name="acme", scope="acme.com",
                          header="X-BB: h", activate=False)
    listing = await srv.program_list()
    assert listing["count"] >= 1
    assert any(p["name"] == "acme" for p in listing["programs"])

    rem = await srv.program_remove(name="acme")
    assert rem["removed"] is True
    assert "acme" not in [p["name"] for p in (await srv.program_list())["programs"]]


@pytest.mark.asyncio
async def test_auth_overrides_program_header_on_collision(local_server, fresh_context):
    base, _ = local_server
    await srv.program_add(name="p", scope="127.0.0.1",
                          header="X-Team: program", activate=True)
    # Engagement auth sets the same header — credentials win over the program value.
    await srv.auth_set(headers={"X-Team": "auth"})
    r = await fresh_context.http.fetch(f"{base}/echo")
    assert json.loads(r.text()).get("x-team") == "auth"


def test_program_load_coerces_scalar_scope_fields(tmp_path):
    import json
    import os

    from moonmcp.programs import ProgramStore
    d = str(tmp_path)
    # A hand-edited profile stores scope / scope_exclude as bare strings (and a null).
    with open(os.path.join(d, "programs.json"), "w") as fh:
        json.dump({"active": "acme", "programs": [
            {"name": "acme", "scope": "example.com",
             "scope_exclude": "admin.example.com"},
        ]}, fh)
    store = ProgramStore(state_dir=d)
    prog = store.get("acme")
    assert prog is not None
    # coerced to single-element lists — NOT iterated per character
    assert prog.scope == ["example.com"]
    assert prog.scope_exclude == ["admin.example.com"]
