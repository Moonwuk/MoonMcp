"""OpenAPI / Swagger spec parsing → an endpoint / parameter / method inventory.

An exposed ``openapi.json`` / ``swagger.json`` is one of the richest sources of
hidden attack surface: it enumerates every endpoint, method, parameter and which
ones require auth.  This turns a spec (fetched or pasted) into a structured
inventory the agent can drive — feed the endpoints to the batch prober, the param
names to the parameter fuzzer, and flag the operations with no security.
"""

from __future__ import annotations

import json

_METHODS = ("get", "put", "post", "delete", "patch", "head", "options", "trace")
_MAX_ENDPOINTS = 800


def _load(content: str) -> dict | None:
    try:
        data = json.loads(content)
        return data if isinstance(data, dict) else None
    except (ValueError, TypeError):
        pass
    try:  # optional YAML support (specs are often JSON, sometimes YAML)
        import yaml  # type: ignore
        data = yaml.safe_load(content)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _servers(spec: dict) -> list[str]:
    out: list[str] = []
    for s in spec.get("servers", []) or []:
        if isinstance(s, dict) and s.get("url"):
            out.append(str(s["url"]))
    if not out:  # swagger 2.0
        host = spec.get("host")
        base = spec.get("basePath", "")
        schemes = spec.get("schemes") or (["https"] if host else [])
        for sch in schemes:
            out.append(f"{sch}://{host}{base}")
    return out


def _params(op: dict, shared: list) -> list[dict]:
    out: list[dict] = []
    seen = set()
    for p in list(shared or []) + list(op.get("parameters", []) or []):
        if not isinstance(p, dict):
            continue
        name = p.get("name")
        loc = p.get("in")
        key = (name, loc)
        if not name or key in seen:
            continue
        seen.add(key)
        schema = p.get("schema") if isinstance(p.get("schema"), dict) else {}
        out.append({"name": name, "in": loc, "required": bool(p.get("required")),
                    "type": p.get("type") or schema.get("type")})
    return out


def parse_spec(content: str) -> dict:
    """Parse an OpenAPI/Swagger document into a structured inventory."""

    spec = _load(content)
    if spec is None:
        return {"error": "could not parse spec (not valid JSON, and YAML unavailable/invalid)"}

    version = ("openapi:" + str(spec["openapi"])) if spec.get("openapi") else (
        "swagger:" + str(spec["swagger"]) if spec.get("swagger") else "unknown")
    info = spec.get("info") if isinstance(spec.get("info"), dict) else {}
    _gsec = spec.get("security") or []
    global_security = bool(_gsec) and not any(not req for req in _gsec)   # [{}] => optional auth

    schemes = {}
    comp = spec.get("components") if isinstance(spec.get("components"), dict) else {}
    for src in (comp.get("securitySchemes"), spec.get("securityDefinitions")):
        if isinstance(src, dict):
            for name, defn in src.items():
                if isinstance(defn, dict):
                    schemes[name] = {"type": defn.get("type"), "scheme": defn.get("scheme"),
                                     "in": defn.get("in"), "name": defn.get("name")}

    endpoints: list[dict] = []
    paths = spec.get("paths") if isinstance(spec.get("paths"), dict) else {}
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        shared = item.get("parameters", []) or []
        for method in _METHODS:
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            # An explicit op-level `security` overrides the global requirement. Per the
            # OpenAPI spec an EMPTY list (`security: []`) OR a list containing an empty
            # requirement object (`security: [{}]`, or `[{...}, {}]`) makes auth OPTIONAL —
            # the endpoint is anonymously reachable. `bool([{}])` was True, so `[{}]` was
            # wrongly marked auth-required and dropped from public_operations.
            if "security" in op:
                sec = op.get("security") or []
                has_security = bool(sec) and not any(not req for req in sec)
            else:
                has_security = global_security
            body_types = []
            rb = op.get("requestBody")
            if isinstance(rb, dict) and isinstance(rb.get("content"), dict):
                body_types = list(rb["content"].keys())
            # summary/description may be null or non-string in a malformed spec —
            # coerce to "" rather than slicing a None/int (which would TypeError
            # and abort the whole otherwise-parseable spec).
            summ = op.get("summary") or op.get("description") or ""
            summ = summ[:120] if isinstance(summ, str) else ""
            endpoints.append({
                "method": method.upper(),
                "path": path,
                "operation_id": op.get("operationId"),
                "summary": summ,
                "tags": op.get("tags", []),
                "parameters": _params(op, shared),
                "request_body_types": body_types,
                "auth_required": bool(has_security),
                "deprecated": bool(op.get("deprecated")),
            })
            if len(endpoints) >= _MAX_ENDPOINTS:
                break
        if len(endpoints) >= _MAX_ENDPOINTS:
            break

    public = [e for e in endpoints if not e["auth_required"]]
    writes = [e for e in endpoints if e["method"] in ("POST", "PUT", "DELETE", "PATCH")]
    flags: list[str] = []
    if public:
        flags.append(f"{len(public)} operation(s) declare NO security requirement")
    if any(e["deprecated"] for e in endpoints):
        flags.append("deprecated operations present (often less-maintained)")
    if not schemes and endpoints:
        flags.append("no security schemes defined in the spec")

    return {
        "spec_version": version,
        "title": info.get("title"),
        "api_version": info.get("version"),
        "servers": _servers(spec),
        "endpoint_count": len(endpoints),
        "method_breakdown": {m: sum(1 for e in endpoints if e["method"] == m.upper())
                             for m in ("get", "post", "put", "delete", "patch")
                             if any(e["method"] == m.upper() for e in endpoints)},
        "write_operations": len(writes),
        "public_operations": len(public),
        "security_schemes": schemes,
        "flags": flags,
        "endpoints": endpoints,
    }


async def fetch_and_parse(http_client, url: str, scope_check=None) -> dict:
    """Fetch a spec from *url* and parse it."""

    r = await http_client.fetch(url, method="GET", follow_redirects=True, scope_check=scope_check)
    if r.status is None:
        return {"error": r.error or "failed to fetch spec", "url": url}
    if r.status >= 400:
        return {"error": f"spec fetch returned HTTP {r.status}", "url": url}
    out = parse_spec(r.text())
    out["source_url"] = url
    out["fetch_status"] = r.status
    return out
