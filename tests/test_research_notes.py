"""Cookie contract and a deliberately invalid middleware-bypassing harness."""
import io
import json
from types import SimpleNamespace

import pytest

from moonmcp import research, server
from moonmcp.research_notes_app import Notes, create_application
from moonmcp.research_recipes import recipe
from moonmcp.research_setup import session_headers
from moonmcp.runs import RunStore


def call(app, path, *, method="GET", payload=None, headers=None):
    raw = json.dumps(payload).encode() if payload is not None else b""
    env = {"PATH_INFO": path, "REQUEST_METHOD": method, "HTTP_HOST": "fixture.test",
           "HTTP_ORIGIN": "http://fixture.test", "CONTENT_LENGTH": str(len(raw)),
           "wsgi.input": io.BytesIO(raw), **(headers or {})}
    result = {}
    def start(status, response_headers):
        result.update(status=int(status.split()[0]), headers=dict(response_headers))
    result["body"] = json.loads(b"".join(app(env, start)))
    return result


def normal_flow(tmp_path, variant="fixed"):
    path = str(tmp_path / "notes.sqlite")
    app = create_application(path, variant)
    users = []
    for who in ("owner", "observer"):
        identity = {"subject": who, "tenant": who + "-tenant", "password": "synthetic-password"}
        assert call(app, "/accounts", method="POST", payload=identity)["status"] == 201
        logged = call(app, "/session", method="POST", payload=identity)
        assert logged["status"] == 200
        users.append({"HTTP_COOKIE": logged["headers"]["Set-Cookie"].split(";")[0],
                      "HTTP_X_CSRF_TOKEN": logged["body"]["csrf"]})
    created = call(app, "/notes", method="POST", headers=users[0],
                   payload={"secret": "synthetic-private-value", "visibility": "private"})
    assert created["status"] == 201
    return app, path, users, "/notes/" + created["body"]["id"]


def test_invalid_harness_exposes_object_but_real_middleware_denies_it(tmp_path):
    app, database, users, target = normal_flow(tmp_path)
    # Exactly the same path/cookie/state: only the middleware stack differs.
    invalid = call(Notes(database), target, headers=users[1])
    real = call(app, target, headers=users[1])
    assert invalid["status"] == 200 and invalid["body"]["secret"] == "synthetic-private-value"
    assert real["status"] == 403 and "secret" not in real["body"]
    assert call(app, target, headers=users[0])["body"] == invalid["body"]
    assert call(app, target)["status"] == 401
    assert call(app, target, headers={"HTTP_X_SUBJECT": "owner"})["status"] == 401


def test_vulnerable_case_preserves_authentication_but_omits_object_policy(tmp_path):
    app, _, users, target = normal_flow(tmp_path, "vulnerable")
    assert call(app, target, headers=users[1])["body"]["secret"] == "synthetic-private-value"
    assert call(app, target)["status"] == 401


def test_session_revocation_and_csrf_protect_normal_entrypoint(tmp_path):
    app, database, users, _ = normal_flow(tmp_path)
    headers = users[1]
    before = call(app, "/identity", headers=headers)
    assert before["body"]["subject"] == "observer"
    assert call(app, "/notes", method="POST", headers={"HTTP_COOKIE": headers["HTTP_COOKIE"]},
                payload={"secret": "forbidden", "visibility": "private"})["status"] == 403
    import sqlite3
    with sqlite3.connect(database) as db:
        assert db.execute("SELECT COUNT(*) FROM notes").fetchone()[0] == 1
    assert call(app, "/session/logout", method="POST", headers=headers)["status"] == 200
    assert call(app, "/identity", headers=headers)["status"] == 401
    assert call(app, "/identity", headers=users[0])["status"] == 200


@pytest.mark.parametrize("cookie", [
    [], ["other=abc; Path=/; HttpOnly; SameSite=Lax"],
    ["session=abc; Path=/; HttpOnly; SameSite=Lax; Domain=example.com"],
    ["session=abc; Path=/other; HttpOnly; SameSite=Lax"],
    ["session=abc; Path=/; SameSite=Lax"],
    ["session=abc; Path=/; HttpOnly; SameSite=None"],
    ["session=abc; Path=/; HttpOnly; SameSite=Lax"] * 2,
])
def test_login_cannot_widen_cookie_contract(cookie):
    response = SimpleNamespace(get_all=lambda name: cookie)
    with pytest.raises(ValueError):
        session_headers(recipe("sqlite-notes-v1"), response, {"csrf": "synthetic"})


async def test_second_recipe_discovery_and_cross_recipe_capsules_fail_closed(tmp_path):
    description = await server.research_environment(recipe="sqlite-notes-v1")
    assert description["recipe"] == "sqlite-notes-v1"
    assert {r["authentication"] for r in description["recipes"]} == {"bearer", "cookie_session"}
    store = RunStore(str(tmp_path / "runs.sqlite"))
    for bad in ({**research.capsule("private_fixed"), "recipe": "sqlite-notes-v1"},
                {**research.capsule("private_fixed"), "recipe": "../../etc/passwd"},
                {**research.capsule("private_fixed", "sqlite-notes-v1"), "entrypoint": "domain_handler"}):
        with pytest.raises(ValueError):
            await research.replay(store, bad, execute=True)
    assert not store.list_runs()
