"""Builtin synthetic orders application for the isolated research recipe.

Runs as a separate process with SQLite. All test data is created through normal
registration/login/create routes. Never use this deliberately vulnerable fixture
with production data or expose it beyond the recipe's loopback port.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
import socketserver
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def serve(variant: str, port: int, database: str, socket_path: str | None = None) -> None:
    with sqlite3.connect(database) as db:
        db.executescript("""
            CREATE TABLE users(subject TEXT PRIMARY KEY, tenant TEXT, salt TEXT, password TEXT);
            CREATE TABLE sessions(token TEXT PRIMARY KEY, subject TEXT);
            CREATE TABLE orders(id TEXT PRIMARY KEY, owner TEXT, tenant TEXT,
                                secret TEXT, visibility TEXT, shared_with TEXT);
        """)

    def password_hash(password, salt):
        return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000).hex()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass  # HTTP bodies and credentials must never enter container logs.

        def reply(self, status, value):
            body = json.dumps(value).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def handle_request(self):
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 <= length <= 16_384:
                return self.reply(413, {"error": "body too large"})
            data = json.loads(self.rfile.read(length)) if length else {}
            with sqlite3.connect(database, timeout=5) as db:
                db.row_factory = sqlite3.Row
                if self.path == "/health" and self.command == "GET":
                    db.execute("SELECT COUNT(*) FROM users").fetchone()
                    return self.reply(200, {"ready": True, "storage": "sqlite"})
                if self.path == "/register" and self.command == "POST":
                    subject, tenant, password = (data[k] for k in ("subject", "tenant", "password"))
                    if not all(isinstance(v, str) and 1 <= len(v) <= 200 for v in (subject, tenant, password)):
                        return self.reply(400, {"error": "invalid registration"})
                    salt = secrets.token_hex(16)
                    db.execute("INSERT INTO users VALUES(?,?,?,?)",
                               (subject, tenant, salt, password_hash(password, salt)))
                    db.commit()
                    return self.reply(201, {"subject": subject, "tenant": tenant})
                if self.path == "/login" and self.command == "POST":
                    row = db.execute("SELECT * FROM users WHERE subject=?", (data.get("subject"),)).fetchone()
                    if row is None or not hmac.compare_digest(row["password"], password_hash(data.get("password", ""), row["salt"])):
                        return self.reply(401, {"error": "invalid login"})
                    token = secrets.token_urlsafe(32)
                    db.execute("INSERT INTO sessions VALUES(?,?)", (token, row["subject"]))
                    db.commit()
                    return self.reply(200, {"token": token})
                token = self.headers.get("Authorization", "").removeprefix("Bearer ")
                user = db.execute("SELECT u.* FROM sessions s JOIN users u ON u.subject=s.subject WHERE s.token=?", (token,)).fetchone()
                if user is None:
                    return self.reply(401, {"error": "login required"})
                if self.path == "/me" and self.command == "GET":
                    return self.reply(200, {"subject": user["subject"], "tenant": user["tenant"]})
                if self.path == "/orders" and self.command == "POST":
                    if data.get("visibility") not in {"private", "public", "shared"}:
                        return self.reply(400, {"error": "invalid visibility"})
                    if not isinstance(data.get("secret"), str) or len(data["secret"]) > 1000:
                        return self.reply(400, {"error": "invalid secret"})
                    ident = secrets.token_hex(12)
                    db.execute("INSERT INTO orders VALUES(?,?,?,?,?,?)",
                               (ident, user["subject"], user["tenant"], data["secret"],
                                data["visibility"], data.get("shared_with", "")))
                    db.commit()
                    return self.reply(201, {"id": ident})
                if self.path.startswith("/orders/") and self.command == "GET":
                    row = db.execute("SELECT * FROM orders WHERE id=?", (self.path[len("/orders/"):],)).fetchone()
                    if row is None:
                        return self.reply(404, {"error": "missing order"})
                    permitted = (row["owner"] == user["subject"] or row["visibility"] == "public"
                                 or row["visibility"] == "shared" and row["shared_with"] == user["subject"])
                    if variant == "fixed" and not permitted:
                        return self.reply(403, {"error": "private order"})
                    return self.reply(200, {"padding": "x" * 5000, "id": row["id"], "type": "order",
                                            "owner": row["owner"], "tenant": row["tenant"], "secret": row["secret"]})
                return self.reply(404, {"error": "unknown route"})

        def do_GET(self):
            try:
                self.handle_request()
            except (ValueError, KeyError, TypeError, sqlite3.IntegrityError):
                self.reply(400, {"error": "invalid request"})

        do_POST = do_GET

    server: socketserver.BaseServer
    if socket_path:
        class UnixHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
            daemon_threads = True
        server = UnixHTTPServer(socket_path, Handler)
        os.chmod(socket_path, 0o666)  # enclosing host directory is private to the runner
    else:
        server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--variant", choices=("fixed", "vulnerable"), required=True)
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--database", default="/tmp/orders.sqlite")
    parser.add_argument("--socket")
    options = parser.parse_args()
    serve(options.variant, options.port, options.database, options.socket)
