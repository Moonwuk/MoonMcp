"""Dependency-confusion recon — manifest parsing + registry existence check."""

import json

import pytest

from moonmcp import server as srv
from moonmcp.recon import depconf


# -- parsing -----------------------------------------------------------------
def test_detect_and_parse_npm():
    content = json.dumps({"dependencies": {"react": "^18", "@acme/internal-ui": "1.0.0"},
                          "devDependencies": {"jest": "^29"}})
    assert depconf.detect_ecosystem(content, "package.json") == "npm"
    names = depconf.parse_dependencies(content, "npm")
    assert set(names) == {"react", "@acme/internal-ui", "jest"}


def test_parse_requirements_and_pipfile():
    reqs = "requests==2.31.0\n# comment\ninternal-lib>=1.2\n-e .\n"
    assert set(depconf.parse_dependencies(reqs, "pypi")) == {"requests", "internal-lib"}
    pipfile = "[packages]\nflask = \"*\"\ncorp-secrets = \"*\"\n[dev-packages]\npytest = \"*\"\n"
    assert set(depconf.parse_dependencies(pipfile, "pypi")) == {"flask", "corp-secrets", "pytest"}


def test_parse_composer_keeps_vendor_names():
    content = json.dumps({"require": {"php": ">=8", "acme/internal": "^1", "monolog/monolog": "^3"}})
    names = depconf.parse_dependencies(content, "composer")
    assert "acme/internal" in names and "monolog/monolog" in names
    assert "php" not in names  # php/ext-* are not registry packages


# -- registry existence check ------------------------------------------------
class _R:
    def __init__(self, status):
        self.status = status

    def text(self, limit=None):
        return ""


class _Client:
    def __init__(self, present):
        self._present = set(present)  # names that "exist" (200); others 404

    async def fetch(self, url, **kwargs):
        return _R(200 if any(p in url for p in self._present) else 404)


@pytest.mark.asyncio
async def test_check_flags_claimable_and_scoped():
    client = _Client(present=["react"])  # react exists; the rest 404
    res = await depconf.check_dependencies(client, ["react", "internal-ui", "@acme/private"], "npm")
    by = {r["name"]: r for r in res}
    assert by["react"]["verdict"] == "exists"
    assert by["internal-ui"]["verdict"] == "claimable" and by["internal-ui"]["severity"] == "medium"
    # a scoped 404 is higher signal (claim the whole scope)
    assert by["@acme/private"]["verdict"] == "claimable" and by["@acme/private"]["severity"] == "high"


@pytest.mark.asyncio
async def test_dependency_confusion_tool_end_to_end(local_server, fresh_context, monkeypatch):
    # patch the shared HTTP client so no real registry call is made
    content = json.dumps({"dependencies": {"@corp/secret-sdk": "1.0.0"}})

    async def fake_check(client, names, ecosystem, **kw):
        return [{"name": n, "ecosystem": ecosystem, "registry_status": 404,
                 "verdict": "claimable", "severity": "high", "detail": "x"} for n in names]

    monkeypatch.setattr(depconf, "check_dependencies", fake_check)
    res = await srv.dependency_confusion(content=content, filename="package.json")
    assert res["ecosystem"] == "npm" and res["claimable_count"] == 1


@pytest.mark.asyncio
async def test_dependency_confusion_registered():
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "dependency_confusion" in tools
