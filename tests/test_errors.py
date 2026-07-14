"""Structured error envelopes — a recovery `action` on the common failures."""

import pytest

from moonmcp import errors as errmod
from moonmcp import server as srv


# -- pure --------------------------------------------------------------------
def test_err_fills_default_action():
    e = errmod.err("out_of_scope", detail="x not in scope")
    assert e["error"] == "out_of_scope"
    assert e["detail"] == "x not in scope"
    assert "scope_add" in e["action"]


def test_err_explicit_action_overrides_default():
    e = errmod.err("out_of_scope", action="do the thing")
    assert e["action"] == "do the thing"


def test_err_unknown_code_has_empty_action():
    e = errmod.err("some_novel_code", detail="d")
    assert e["error"] == "some_novel_code"
    assert e["action"] == ""


def test_err_extra_keys_preserved():
    e = errmod.err("unreachable", detail="timeout", url="https://x", url_ok=False)
    assert e["url"] == "https://x"
    assert e["url_ok"] is False
    assert e["action"]  # unreachable has a default action


def test_action_for_known_and_unknown():
    assert errmod.action_for("oast_unconfigured")
    assert errmod.action_for("not_a_code") == ""


def test_all_default_actions_are_nonempty():
    for code, action in errmod.DEFAULT_ACTIONS.items():
        assert action.strip(), code


# -- e2e: the scope-denial envelope carries an action ------------------------
@pytest.mark.asyncio
async def test_out_of_scope_call_carries_action(fresh_context):
    ctx = srv.get_context()
    ctx.scope.clear() if hasattr(ctx.scope, "clear") else None
    # a host that is definitely not in scope → the wrapper's ScopeError envelope
    res = await srv.fingerprint(target="definitely-not-in-scope.invalid")
    assert res["error"] == "out_of_scope"
    assert res["action"]  # non-empty recovery hint
    assert "scope_add" in res["action"]


@pytest.mark.asyncio
async def test_invalid_token_envelope_carries_action(fresh_context):
    # jwt_jku_probe forges from a captured token; a junk token → invalid_token.
    # jwt tools are offline, so no network/scope needed.
    res = await srv.jwt_jku_probe(target="127.0.0.1", token="not-a-jwt")
    if res.get("error") == "invalid_token":
        assert res["action"]
