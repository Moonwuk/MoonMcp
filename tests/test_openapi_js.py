"""Tests for the OpenAPI parser and the deep JS endpoint extractor."""

import pytest

from moonmcp import server as srv
from moonmcp.recon import jsendpoints as jsmod
from moonmcp.recon import openapi as openapimod

_SWAGGER2 = """
{"swagger": "2.0", "host": "api.example.com", "basePath": "/v2", "schemes": ["https"],
 "securityDefinitions": {"key": {"type": "apiKey", "in": "header", "name": "X-API-Key"}},
 "paths": {"/pets": {"get": {"operationId": "listPets"},
                      "post": {"operationId": "addPet", "security": [{"key": []}]}}}}
"""


def test_parse_spec_openapi3():
    spec = '{"openapi":"3.0.1","info":{"title":"T","version":"1"},' \
           '"security":[{"b":[]}],"paths":{"/a":{"get":{"operationId":"ga"},' \
           '"post":{"operationId":"pa","security":[]}}}}'
    out = openapimod.parse_spec(spec)
    assert out["spec_version"].startswith("openapi:")
    assert out["endpoint_count"] == 2
    methods = {(e["method"], e["path"]): e for e in out["endpoints"]}
    assert methods[("GET", "/a")]["auth_required"] is True     # global security
    assert methods[("POST", "/a")]["auth_required"] is False   # explicit security:[]
    assert out["public_operations"] == 1
    assert any("NO security" in f for f in out["flags"])


def test_parse_spec_swagger2_servers_and_params():
    out = openapimod.parse_spec(_SWAGGER2)
    assert out["spec_version"] == "swagger:2.0"
    assert out["servers"] == ["https://api.example.com/v2"]
    assert out["endpoint_count"] == 2
    assert "key" in out["security_schemes"]


def test_parse_spec_invalid():
    assert "error" in openapimod.parse_spec("<<not a spec>>")


def test_js_extract_endpoints_pure():
    js = "fetch('/api/v1/x');var u=\"/api/v2/y?id=1\";img='/logo.png';a='https://cdn.x/app.js'"
    eps = jsmod.extract_endpoints(js)
    assert "/api/v1/x" in eps and "/api/v2/y?id=1" in eps
    assert "/logo.png" not in eps  # asset filtered
    assert jsmod.extract_source_maps("//# sourceMappingURL=app.js.map") == ["app.js.map"]


@pytest.mark.asyncio
async def test_parse_openapi_tool_fetch(local_server, fresh_context):
    base, _ = local_server
    out = await srv.parse_openapi(target=f"{base}/openapi.json")
    assert out["title"] == "Demo API" and out["endpoint_count"] == 3
    paths = {(e["method"], e["path"]) for e in out["endpoints"]}
    assert ("GET", "/users/{id}") in paths and ("DELETE", "/users/{id}") in paths
    assert out["public_operations"] >= 1  # /public/health + delUser have security:[]
    # inline content path
    out2 = await srv.parse_openapi(content=_SWAGGER2)
    assert out2["endpoint_count"] == 2


@pytest.mark.asyncio
async def test_analyze_js_tool(local_server, fresh_context):
    base, _ = local_server
    out = await srv.analyze_js(target=f"{base}/spa")
    eps = set(out["endpoints"])
    # from inline HTML script and from the fetched same-origin JS file
    assert "/api/v2/users" in eps and "/api/v2/orders" in eps
    assert "/api/internal/config" in eps and "/api/v1/admin/users?id=1" in eps
    assert out["source_maps"] and out["source_maps"][0]["map"].endswith("app.js.map")


@pytest.mark.asyncio
async def test_tools_registered():
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "parse_openapi" in tools and "analyze_js" in tools
