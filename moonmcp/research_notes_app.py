"""Synthetic WSGI notes app with cookie sessions, CSRF and separate middleware.

Only the composed WSGI entry point is reachable over HTTP. Calling Notes directly
bypasses material identity/access checks and is an intentionally invalid harness.
No network-accessible bypass route or privileged setup endpoint exists.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
import socket
import socketserver
import sqlite3
from contextlib import closing
from http import HTTPStatus
from http.cookies import SimpleCookie
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer


def reply(start_response, status, data, headers=()):
    body = json.dumps(data).encode()
    start_response(f"{status} {HTTPStatus(status).phrase}", [
        ("Content-Type", "application/json"), ("Content-Length", str(len(body))),
        ("Cache-Control", "no-store"), *headers])
    return [body]


def connect(path):
    db = sqlite3.connect(path, timeout=5)
    db.row_factory = sqlite3.Row
    return closing(db)


def body(environ):
    length = int(environ.get("CONTENT_LENGTH") or "0")
    if not 0 <= length <= 16384:
        raise ValueError("body limit")
    data = json.loads(environ["wsgi.input"].read(length)) if length else {}
    if not isinstance(data, dict):
        raise ValueError("object required")
    return data


def digest(password, salt):
    if not isinstance(password, str) or not 1 <= len(password) <= 200:
        raise ValueError("invalid password")
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000).hex()


class Notes:
    """Domain handler. The upstream middleware owns identity and read policy."""

    def __init__(self, database):
        self.database = database

    def __call__(self, env, start):
        path, method = env["PATH_INFO"], env["REQUEST_METHOD"]
        with connect(self.database) as db:
            if path == "/identity" and method == "GET":
                return reply(start, 200, env["principal"])
            if path == "/notes" and method == "POST":
                data = body(env)
                if (data.get("visibility") not in {"private", "public", "shared"}
                        or not isinstance(data.get("secret"), str) or not 1 <= len(data["secret"]) <= 1000
                        or not isinstance(data.get("shared_with", ""), str)):
                    return reply(start, 400, {"error": "invalid note"})
                ident = secrets.token_hex(12)
                user = env["principal"]
                db.execute("INSERT INTO notes VALUES(?,?,?,?,?,?)", (
                    ident, user["subject"], user["tenant"], data["secret"],
                    data["visibility"], data.get("shared_with", "")))
                db.commit()
                return reply(start, 201, {"id": ident})
            if path.startswith("/notes/") and method == "GET":
                row = db.execute("SELECT * FROM notes WHERE id=?", (path[len("/notes/"):],)).fetchone()
                if row is None:
                    return reply(start, 404, {"error": "missing note"})
                return reply(start, 200, {"padding": "x" * 5000, "id": row["id"], "type": "note",
                                          "owner": row["owner"], "tenant": row["tenant"], "secret": row["secret"]})
        return reply(start, 404, {"error": "unknown route"})


class ObjectPolicy:
    def __init__(self, app, database, variant):
        self.app, self.database, self.variant = app, database, variant

    def __call__(self, env, start):
        if env["REQUEST_METHOD"] == "GET" and env["PATH_INFO"].startswith("/notes/"):
            with connect(self.database) as db:
                row = db.execute("SELECT * FROM notes WHERE id=?", (env["PATH_INFO"][len("/notes/"):],)).fetchone()
            if row is not None:
                subject = env["principal"]["subject"]
                allowed = (row["owner"] == subject or row["visibility"] == "public"
                           or row["visibility"] == "shared" and row["shared_with"] == subject)
                if self.variant == "fixed" and not allowed:
                    return reply(start, 403, {"error": "private note"})
        return self.app(env, start)


class Sessions:
    def __init__(self, app, database):
        self.app, self.database = app, database

    def __call__(self, env, start):
        try:
            return self.dispatch(env, start)
        except (ValueError, KeyError, TypeError, sqlite3.IntegrityError):
            return reply(start, 400, {"error": "invalid request"})

    def dispatch(self, env, start):
        path, method = env["PATH_INFO"], env["REQUEST_METHOD"]
        with connect(self.database) as db:
            if path == "/health" and method == "GET":
                db.execute("SELECT COUNT(*) FROM accounts").fetchone()
                return reply(start, 200, {"ready": True, "storage": "sqlite"})
            if method == "POST" and env.get("HTTP_ORIGIN") != "http://" + env.get("HTTP_HOST", ""):
                return reply(start, 403, {"error": "origin required"})
            if path == "/accounts" and method == "POST":
                data = body(env)
                if not all(isinstance(data.get(k), str) and 1 <= len(data[k]) <= 200
                           for k in ("subject", "tenant", "password")):
                    return reply(start, 400, {"error": "invalid account"})
                salt = secrets.token_hex(16)
                db.execute("INSERT INTO accounts VALUES(?,?,?,?)", (
                    data["subject"], data["tenant"], salt, digest(data["password"], salt)))
                db.commit()
                return reply(start, 201, {"subject": data["subject"], "tenant": data["tenant"]})
            if path == "/session" and method == "POST":
                data = body(env)
                row = db.execute("SELECT * FROM accounts WHERE subject=?", (data.get("subject"),)).fetchone()
                if row is None or not hmac.compare_digest(row["password"], digest(data.get("password"), row["salt"])):
                    return reply(start, 401, {"error": "invalid login"})
                token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
                db.execute("INSERT INTO sessions VALUES(?,?,?)", (token, row["subject"], csrf))
                db.commit()
                return reply(start, 200, {"csrf": csrf}, [
                    ("Set-Cookie", f"session={token}; Path=/; HttpOnly; SameSite=Lax")])
            cookies = SimpleCookie()
            cookies.load(env.get("HTTP_COOKIE", ""))
            token = cookies["session"].value if "session" in cookies else ""
            user = db.execute("SELECT a.subject,a.tenant,s.csrf FROM sessions s JOIN accounts a ON a.subject=s.subject WHERE s.token=?", (token,)).fetchone()
            if user is None:
                return reply(start, 401, {"error": "session required"})
            if method == "POST" and not hmac.compare_digest(user["csrf"], env.get("HTTP_X_CSRF_TOKEN", "")):
                return reply(start, 403, {"error": "csrf required"})
            if path == "/session/logout" and method == "POST":
                db.execute("DELETE FROM sessions WHERE token=?", (token,))
                db.commit()
                return reply(start, 200, {"logged_out": True}, [("Set-Cookie", "session=; Path=/; Max-Age=0")])
            # Never accept caller-supplied HTTP identity headers as authentication.
            env["principal"] = {"subject": user["subject"], "tenant": user["tenant"]}
        return self.app(env, start)


def create_application(database, variant):
    if variant not in {"fixed", "vulnerable"}:
        raise ValueError("Unsupported application variant")
    with connect(database) as db:
        db.executescript("""
            CREATE TABLE accounts(subject TEXT PRIMARY KEY, tenant TEXT, salt TEXT, password TEXT);
            CREATE TABLE sessions(token TEXT PRIMARY KEY, subject TEXT, csrf TEXT);
            CREATE TABLE notes(id TEXT PRIMARY KEY, owner TEXT, tenant TEXT,
                               secret TEXT, visibility TEXT, shared_with TEXT);
        """)
    return Sessions(ObjectPolicy(Notes(database), database, variant), database)


def serve(database, variant, socket_path):
    class Handler(WSGIRequestHandler):
        def log_message(self, *args):
            pass

    class UnixWSGI(socketserver.ThreadingMixIn, WSGIServer):
        address_family = socket.AF_UNIX
        daemon_threads = True

        def server_bind(self):
            socketserver.TCPServer.server_bind(self)
            self.server_name, self.server_port = "localhost", 0
            self.setup_environ()

        def get_request(self):
            client, _ = super().get_request()
            return client, ("127.0.0.1", 0)

    application = create_application(database, variant)
    with UnixWSGI(socket_path, Handler) as server:
        server.set_app(application)
        os.chmod(socket_path, 0o666)
        server.serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--variant", choices=("fixed", "vulnerable"), required=True)
    parser.add_argument("--database", default="/tmp/notes.sqlite")
    parser.add_argument("--socket", required=True)
    options = parser.parse_args()
    serve(options.database, options.variant, options.socket)
