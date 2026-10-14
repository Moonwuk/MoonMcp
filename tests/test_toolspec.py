"""Capability presence is distinct from runtime scope/auth authorization."""

from __future__ import annotations

import json
from types import SimpleNamespace

from moonmcp import server, toolspec
from moonmcp.config import Settings


def _snapshot(monkeypatch, tmp_path, *, intrusive=False, external=False):
    from moonmcp import pipeline

    monkeypatch.setattr(pipeline, "_PIPELINE_DIRS", [tmp_path])
    monkeypatch.setattr(toolspec.shutil, "which", lambda name: None)
    monkeypatch.setattr(toolspec, "_browser_capability", lambda: {
        "status": "unavailable", "reason": "playwright_package_missing"})
    return toolspec.capabilities(Settings(allow_intrusive=intrusive, allow_external_tools=external))


def test_schema_and_wrapper_markers_are_authoritative(monkeypatch, tmp_path):
    cap = _snapshot(monkeypatch, tmp_path)
    specs = toolspec.registry(snapshot=cap)
    registered = {t.name: t for t in server.mcp._tool_manager.list_tools()}
    assert specs.keys() == registered.keys()
    for name, spec in specs.items():
        assert spec.input_schema == registered[name].parameters
        assert spec.scope_gated == bool(getattr(registered[name].fn, "__moonmcp_gated__", False))
        assert spec.intrusive == bool(getattr(registered[name].fn, "__moonmcp_intrusive__", False))
    assert specs["scope_list"].read_only is True
    assert specs["scope_add"].idempotent is None
    assert specs["sqli_probe"].read_only is None
    assert not specs["scope_list"].cache["enabled"]


def test_dependency_gates_and_contextual_unknown(monkeypatch, tmp_path):
    cap = _snapshot(monkeypatch, tmp_path)
    specs = toolspec.registry(snapshot=cap)
    assert specs["scope_list"].availability["status"] == "available"
    assert specs["http_probe"].availability["status"] == "unknown"
    assert {p["kind"] for p in specs["http_probe"].preconditions} >= {"scope", "auth"}
    for name in ("browser_open", "vuln_scan", "run_scanner", "search_datasets"):
        assert specs[name].availability["status"] == "unavailable"
    reasons = {p["reason"] for p in specs["vuln_scan"].preconditions}
    assert reasons >= {"nuclei_executable_required", "intrusive_configuration_gate", "external_tools_configuration_gate"}

    cap["configuration"].update(intrusive_allowed=True, external_tools_allowed=True)
    cap["external_cli"]["nuclei"] = True
    assert toolspec.registry(snapshot=cap)["vuln_scan"].availability["status"] == "unknown"


def test_inventory_is_local_sanitized_and_changes_version(monkeypatch, tmp_path):
    cap = _snapshot(monkeypatch, tmp_path)
    version = cap["version"]
    (tmp_path / "knowledge_base" / "airecon_datasets").mkdir(parents=True)
    monkeypatch.setenv("MOONMCP_SHODAN_API_KEY", "secret-unrelated-env-value")
    cap2 = toolspec.capabilities(Settings(shodan_api_key="secret-api-value"))
    encoded = json.dumps(cap2)
    assert "secret" not in encoded
    assert str(tmp_path) not in encoded
    assert cap2["version"] != version
    assert cap2["knowledge"]["search_datasets"] is True
    spec = toolspec.registry(snapshot=cap2)["search_datasets"]
    assert spec.availability["status"] == "unknown"  # selected DB not inspected yet


def test_registry_hash_handles_order_and_live_profile(monkeypatch, tmp_path):
    cap = _snapshot(monkeypatch, tmp_path)
    specs = toolspec.registry(snapshot=cap)
    version = toolspec.registry_version(specs)
    assert toolspec.registry_version(dict(reversed(list(specs.items())))) == version
    specs.pop("sqli_probe")
    assert toolspec.registry_version(specs) != version
    manager = server.mcp._tool_manager
    only_scope = [t for t in manager.list_tools() if t.name == "scope_list"]
    monkeypatch.setattr(manager, "list_tools", lambda: only_scope)
    monkeypatch.setattr(toolspec, "capabilities", lambda settings=None: cap)
    assert toolspec.describe("sqli_probe")["error"] == "tool_unavailable"
    assert toolspec.describe("scope_list")["input_schema"] == only_scope[0].parameters


def test_browser_package_and_executable_checks(monkeypatch, tmp_path):
    from moonmcp.web import screenshot

    monkeypatch.setattr(screenshot, "playwright_available", lambda: False)
    assert toolspec._browser_capability()["reason"] == "playwright_package_missing"
    monkeypatch.setattr(screenshot, "playwright_available", lambda: True)
    executable = tmp_path / "chromium"
    executable.write_text("not executed")
    monkeypatch.setattr(screenshot, "_chromium_executable", lambda: str(executable))
    assert toolspec._browser_capability()["status"] == "unavailable"
    executable.chmod(0o755)
    assert toolspec._browser_capability()["status"] == "available"


def test_bundled_browser_uses_installed_revision_without_starting_it(monkeypatch, tmp_path):
    from moonmcp.web import screenshot

    monkeypatch.setattr(screenshot, "playwright_available", lambda: True)
    monkeypatch.setattr(screenshot, "_chromium_executable", lambda: None)
    package = tmp_path / "playwright"
    root = package / "driver" / "package"
    root.mkdir(parents=True)
    (root / "browsers.json").write_text(json.dumps({"browsers": [
        {"name": "chromium-headless-shell", "revision": "123"}]}))
    monkeypatch.setattr(toolspec.importlib.util, "find_spec", lambda name: SimpleNamespace(origin=str(package / "__init__.py")))
    cache = tmp_path / "browsers"
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(cache))
    assert toolspec._browser_capability()["reason"] == "playwright_chromium_executable_missing"
    executable = cache / "chromium_headless_shell-123" / "chrome-headless-shell-linux64" / "chrome-headless-shell"
    executable.parent.mkdir(parents=True)
    executable.write_text("not executed")
    executable.chmod(0o755)
    assert toolspec._browser_capability()["status"] == "available"
