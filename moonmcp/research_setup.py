"""Finite normal HTTP setup flows for the two admitted research applications."""
from __future__ import annotations

import asyncio
import json
import secrets
from http.cookies import SimpleCookie

from .research_recipes import Recipe


def session_headers(definition: Recipe, response, data: dict) -> dict[str, str]:
    """Extract only this app's session; no global cookie jar or ambient credentials."""
    if definition.authentication == "bearer":
        token = data.get("token")
        if not isinstance(token, str) or not token:
            raise ValueError("Login did not establish a bearer session")
        return {"Authorization": "Bearer " + token}
    values = response.get_all("Set-Cookie")
    if len(values) != 1:
        raise ValueError("Login must set exactly one application cookie")
    cookies = SimpleCookie()
    cookies.load(values[0])
    if set(cookies) != {"session"}:
        raise ValueError("Login returned an unexpected cookie")
    cookie = cookies["session"]
    if (not cookie.value or cookie["domain"] or cookie["path"] != "/"
            or not cookie["httponly"] or cookie["samesite"].lower() != "lax"):
        raise ValueError("Login cookie does not match the local recipe contract")
    if not isinstance(data.get("csrf"), str) or not data["csrf"]:
        raise ValueError("Login did not establish a CSRF token")
    return {"Cookie": "session=" + cookie.value}


async def prepare(http, base_url: str, definition: Recipe, case: str) -> dict:
    cookie_auth = definition.authentication == "cookie_session"

    async def request(path, *, method="GET", payload=None, headers=None, status=200):
        response = await http.fetch(base_url + path, method=method,
                                    headers={"Content-Type": "application/json", **(
                                        {"Origin": base_url} if cookie_auth else {}), **(headers or {})},
                                    body=json.dumps(payload).encode() if payload is not None else None,
                                    timeout=5, max_body=16384, follow_redirects=False,
                                    suppress_auth=True)
        if response.status != status or response.truncated or response.error:
            raise ValueError("Normal HTTP workflow did not meet its contract")
        data = json.loads(response.body)
        if not isinstance(data, dict):
            raise ValueError("Expected an application JSON object")
        return data, response

    for attempt in range(10):
        try:
            data, _ = await request("/health")
            if data == {"ready": True, "storage": "sqlite"}:
                break
        except ValueError:
            if attempt == 9:
                raise
        # A cold WSGI interpreter under the 0.5 CPU limit may take more than a
        # second. Keep the same finite request budget, but allow startup time.
        await asyncio.sleep(.5)
    else:
        raise ValueError("Application readiness was not established")

    identities, credentials, csrf_tokens = [], [], []
    for index in range(2):
        identity = {"subject": secrets.token_hex(12), "tenant": secrets.token_hex(12)}
        password = secrets.token_urlsafe(32)
        await request(definition.register, method="POST", payload={**identity, "password": password}, status=201)
        login = {"subject": identity["subject"], "password": password}
        logged, response = await request(definition.login, method="POST", payload=login)
        headers = session_headers(definition, response, logged)
        if cookie_auth and index == 1:
            # Exercise normal logout and login. A revoked cookie must not retain
            # access, and the new session must bind the same assessed identity.
            old = headers
            await request("/session/logout", method="POST", headers={**old, "X-CSRF-Token": logged["csrf"]})
            await request(definition.identity, headers=old, status=401)
            logged, response = await request(definition.login, method="POST", payload=login)
            headers = session_headers(definition, response, logged)
            if headers == old:
                raise ValueError("Login reused a revoked session")
        live, _ = await request(definition.identity, headers=headers)
        if live != identity:
            raise ValueError("Normal login did not bind the expected live identity")
        identities.append(identity)
        credentials.append(headers)
        csrf_tokens.append(logged.get("csrf"))

    visibility = case if case in {"public", "shared"} else "private"
    secret = secrets.token_urlsafe(32)
    payload = {"secret": secret, "visibility": visibility,
               "shared_with": identities[1]["subject"] if visibility == "shared" else ""}
    write_headers = dict(credentials[0])
    if cookie_auth:
        await request(definition.collection, method="POST", payload=payload, headers=write_headers, status=403)
        await request(definition.identity, status=401, headers={
            "X-Subject": identities[0]["subject"], "X-Tenant": identities[0]["tenant"]})
        write_headers["X-CSRF-Token"] = csrf_tokens[0]
    created, _ = await request(definition.collection, method="POST", payload=payload, headers=write_headers, status=201)
    path = definition.collection + "/" + created["id"]
    normal, _ = await request(path, headers=credentials[0])
    expected = {"id": created["id"], "type": definition.resource_type, "owner": identities[0]["subject"],
                "tenant": identities[0]["tenant"]}
    if any(normal.get(k) != v for k, v in {**expected, "secret": secret}.items()):
        raise ValueError("Normal create/read did not preserve the bound object")
    await request(path, status=401)
    if visibility != "private":
        allowed, _ = await request(path, headers=credentials[1])
        if any(allowed.get(k) != v for k, v in {**expected, "secret": secret}.items()):
            raise ValueError("Permitted observer cannot read the bound shared/public object")
    witness = {"ok": True, "state": "completed", "normal_create_read": True,
               "anonymous_denied": True, "setup_entrypoint": "normal_http",
               "database": "sqlite", "credentials_persisted": False,
               "fidelity": {"recipe": definition.id, "authentication": definition.authentication,
                            "live_identities_checked": True, "substitutions": [], "instrumentation": [],
                            "csrf_denial_checked": cookie_auth, "session_revocation_checked": cookie_auth,
                            "forged_identity_denied": cookie_auth,
                            "scope": "Observed normal HTTP flow for this trusted fixture only"}}
    return {"identities": identities, "headers": credentials, "path": path,
            "resource": expected, "visibility": visibility, "witness": witness}
