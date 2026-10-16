"""Synthetic two-tenant application, independent of MoonMCP proof evaluation.

The fixed variant enforces the application's read policy. The vulnerable variant
omits that check for authenticated reads. Controls and identity endpoints remain
unchanged; a response flag is never treated as an oracle by the verifier.
"""

import json
from urllib.parse import urlsplit

from moonmcp.net.http import HttpResult


class BolaApplication:
    def __init__(self, *, vulnerable=False, visibility="private", secret="synthetic-private-value"):
        self.vulnerable = vulnerable
        self.visibility = visibility
        self.secret = secret
        self.sessions = {"Bearer owner-token": ("alice", "north"),
                         "Bearer observer-token": ("bob", "south")}
        self.requests: list[tuple] = []

    def may_read(self, subject):
        return (self.visibility == "public" or subject == "alice"
                or self.visibility == "shared" and subject == "bob")

    def transport(self, url, method, headers, *args):
        self.requests.append((url, method, dict(headers)))
        token = next((v for k, v in headers.items() if k.lower() == "authorization"), None)
        identity = self.sessions.get(token)
        path = urlsplit(url).path
        status = 200
        if identity is None:
            status, data = 401, {"error": "login required"}
        elif path == "/me":
            data = {"subject": identity[0], "tenant": identity[1]}
        elif path != "/orders/100":
            status, data = 404, {"error": "unknown object"}
        elif not self.vulnerable and not self.may_read(identity[0]):
            status, data = 403, {"error": "not permitted"}
        else:
            # Decisive fields occur beyond the old 4 KiB similarity prefix.
            data = {"padding": "x" * 5000, "id": "100", "type": "order", "owner": "alice",
                    "tenant": "north", "secret": self.secret}
        return HttpResult(url, url, status, "", [], json.dumps(data).encode(), 0)


def manifest(base="https://example.test", *, visibility="private"):
    return {"version": 1, "identity_url": base + "/me", "control_url": base + "/orders/missing",
            "owner": {"subject": "alice", "tenant": "north"},
            "observer": {"subject": "bob", "tenant": "south"},
            "resource": {"id": "100", "type": "order", "owner": "alice", "tenant": "north"},
            "policy": {"id": "fixture-read-v1", "source": "synthetic application read policy",
                       "visibility": visibility,
                       "allowed_subjects": ["alice", "bob"] if visibility == "shared" else ["alice"]},
            "protected_fields": ["secret"]}
