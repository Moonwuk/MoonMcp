"""Local, conservative capability metadata for the *exposed* tool registry.

Discovery is not authorization. Dependencies are inspected without starting a
browser, executing a CLI, resolving DNS, or exposing configuration values.
``unknown`` means an invocation needs context; it does not mean permission.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from . import catalog, sdk
from .config import Settings
from .registry import POLICIES, policy

SPEC_VERSION = "1"

# Compatibility views, derived from the same tool policies as dispatch/catalog.
ALIASES = {p.name: p.aliases for p in POLICIES.values() if p.aliases}
_KB_REQUIREMENTS = {p.name: p.knowledge_paths for p in POLICIES.values() if p.knowledge_paths}


def _digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(encoded.encode()).hexdigest()[:20]


def _settings(settings: Settings | None) -> Settings:
    if settings is not None:
        return settings
    from .server import get_context
    return get_context().settings


def _browser_capability() -> dict[str, str]:
    """Check installed package and an executable, without launching Playwright."""
    from .web.screenshot import _chromium_executable, playwright_available

    if not playwright_available():
        return {"status": "unavailable", "reason": "playwright_package_missing"}
    explicit = _chromium_executable()
    if explicit:
        if Path(explicit).is_file() and os.access(explicit, os.X_OK):
            return {"status": "available", "reason": "configured_chromium_executable_present"}
        return {"status": "unavailable", "reason": "configured_chromium_not_executable"}
    package = importlib.util.find_spec("playwright")
    if package is None or package.origin is None:
        return {"status": "unknown", "reason": "playwright_install_layout_unknown"}
    root = Path(package.origin).parent / "driver" / "package"
    try:
        manifest = json.loads((root / "browsers.json").read_text())
        if os.environ.get("PLAYWRIGHT_BROWSERS_PATH") == "0":
            cache = root / ".local-browsers"
        elif os.environ.get("PLAYWRIGHT_BROWSERS_PATH"):
            cache = Path(os.environ["PLAYWRIGHT_BROWSERS_PATH"])
        elif sys.platform == "darwin":
            cache = Path.home() / "Library" / "Caches" / "ms-playwright"
        elif sys.platform == "win32":
            cache = Path(os.environ.get("LOCALAPPDATA", "")) / "ms-playwright"
        else:
            cache = Path(os.environ.get("XDG_CACHE_HOME", str(Path.home() / ".cache"))) / "ms-playwright"
        browsers = manifest["browsers"]
        shell = next((b for b in browsers if b["name"] == "chromium-headless-shell"), None)
        required = shell or next(b for b in browsers if b["name"] == "chromium")
        if required.get("revisionOverrides"):
            # Choosing a distro-specific revision requires Playwright's platform
            # resolver. Do not claim absent merely from the default revision.
            return {"status": "unknown", "reason": "playwright_platform_revision_requires_runtime_check"}
        folder = cache / f"{required['name'].replace('-', '_')}-{required['revision']}"
        patterns = ("chrome-*/chrome", "chrome-*/chrome.exe", "chrome-*/headless_shell",
                    "chrome-*/headless_shell.exe", "chrome-*/chrome-headless-shell",
                    "chrome-mac*/Chromium.app/Contents/MacOS/Chromium")
        if any(p.is_file() and os.access(p, os.X_OK) for pat in patterns for p in folder.glob(pat)):
            return {"status": "available", "reason": "playwright_chromium_executable_present"}
        return {"status": "unavailable", "reason": "playwright_chromium_executable_missing"}
    except (OSError, ValueError, KeyError, StopIteration, TypeError):
        return {"status": "unknown", "reason": "playwright_install_layout_unknown"}


def capabilities(settings: Settings | None = None) -> dict[str, Any]:
    """Sanitized local inventory; availability never promises runtime success."""
    from . import pipeline
    from .external.cli import KNOWN_TOOLS

    configured = _settings(settings)
    snapshot: dict[str, Any] = {
        "browser": _browser_capability(),
        "external_cli": {name: shutil.which(name) is not None for name in sorted(KNOWN_TOOLS)},
        "knowledge": {name: pipeline._first(*parts) is not None
                      for name, parts in sorted(_KB_REQUIREMENTS.items())},
        "configuration": {
            "intrusive_allowed": configured.allow_intrusive,
            "external_tools_allowed": configured.allow_external_tools,
            "scope_enforced": configured.enforce_scope,
            "shodan_key_configured": bool(configured.shodan_api_key),
            "nvd_key_configured": bool(configured.nvd_api_key),
        },
        "limitations": [
            "Local presence checks only; executables are not launched and network access is not tested.",
            "Scope, authentication roles and selected resource validity are checked at invocation.",
            "A knowledge directory being present does not validate every requested dataset or source.",
        ],
    }
    snapshot["version"] = _digest(snapshot)
    return snapshot


@dataclass(frozen=True)
class ToolSpec:
    name: str
    version: str
    family: str
    purpose: str
    aliases: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any] | None
    scope_gated: bool
    intrusive: bool
    io: str
    read_only: bool | None
    idempotent: bool | None
    cache: dict[str, Any]
    preconditions: list[dict[str, str]]
    availability: dict[str, Any]

    def card(self) -> dict[str, Any]:
        return {"name": self.name, "family": self.family, "purpose": self.purpose,
                "scope_gated": self.scope_gated, "intrusive": self.intrusive,
                "availability": self.availability, "version": self.version}


def registry(settings: Settings | None = None, *,
             snapshot: dict[str, Any] | None = None) -> dict[str, ToolSpec]:
    """Only registered callables are described, including late/profile filtering."""
    from .server import mcp

    cap = snapshot if snapshot is not None else capabilities(settings)
    out: dict[str, ToolSpec] = {}
    for tool in sdk.list_registered(mcp):
        name = tool.name
        declaration = policy(name)
        gated = bool(getattr(tool.fn, "__moonmcp_gated__", False))
        intrusive = bool(getattr(tool.fn, "__moonmcp_intrusive__", False))
        checks: list[dict[str, str]] = []
        if gated:
            checks.append({"kind": "scope", "status": "unknown", "reason": "target_checked_at_invocation"})
            checks.append({"kind": "auth", "status": "unknown", "reason": "role_requirements_depend_on_target"})
        if intrusive:
            checks.append({"kind": "intrusive", "status": "available" if cap["configuration"]["intrusive_allowed"] else "unavailable",
                           "reason": "intrusive_configuration_gate"})
        if declaration.browser:
            checks.append({"kind": "browser", **cap["browser"]})
        if declaration.external_cli:
            checks.append({"kind": "external", "status": "available" if cap["configuration"]["external_tools_allowed"] else "unavailable",
                           "reason": "external_tools_configuration_gate"})
            if declaration.external_cli == "nuclei":
                checks.append({"kind": "cli", "status": "available" if cap["external_cli"].get("nuclei") else "unavailable",
                               "reason": "nuclei_executable_required"})
            else:
                status = "unknown" if any(cap["external_cli"].values()) else "unavailable"
                checks.append({"kind": "cli", "status": status, "reason": "selected_cli_and_intrusive_gate_checked_at_invocation"})
        if name in _KB_REQUIREMENTS:
            checks.append({"kind": "knowledge", "status": "available" if cap["knowledge"].get(name) else "unavailable",
                           "reason": "local_resource_required"})
            if declaration.selected_resource:
                checks.append({"kind": "resource", "status": "unknown", "reason": "selected_resource_checked_at_invocation"})
        states = {check["status"] for check in checks}
        status = "unavailable" if "unavailable" in states else "unknown" if "unknown" in states else "available"
        description = " ".join((tool.description or "").split())
        schema = tool.parameters
        output_schema = sdk.output_schema(tool)
        local_read = declaration.read_only
        out[name] = ToolSpec(
            name=name, version=_digest([SPEC_VERSION, name, description, schema, output_schema,
                                       gated, intrusive, local_read, ALIASES.get(name, ""),
                                       catalog.TOOL_FAMILY.get(name)]),
            family=catalog.TOOL_FAMILY.get(name, "uncategorized"),
            purpose=catalog._first_sentence(description), aliases=ALIASES.get(name, ""),
            input_schema=schema, output_schema=output_schema, scope_gated=gated, intrusive=intrusive,
            io="network_or_external" if gated else "local_read" if local_read else "unknown_or_stateful",
            read_only=True if local_read else None, idempotent=True if local_read else None,
            cache={"enabled": False, "reason": "requires_explicit_context_and_invalidation_policy"},
            preconditions=checks, availability={"status": status, "reasons": checks},
        )
    return out


def registry_version(specs: dict[str, ToolSpec] | None = None) -> str:
    live = specs if specs is not None else registry()
    return _digest([(name, spec.version, spec.availability) for name, spec in sorted(live.items())])


def describe(name: str, settings: Settings | None = None) -> dict[str, Any]:
    specs = registry(settings)
    if name not in specs:
        return {"error": "tool_unavailable", "detail": "Tool is not in the exposed registry."}
    return {**asdict(specs[name]), "registry_version": registry_version(specs),
            "hint": "Metadata is advisory; the registered tool enforces scope and execution gates."}


def tool_availability(name: str, ctx: Any) -> dict[str, Any]:
    """Execution adapter: ``available`` excludes only known local blockers.

    A true value is not scope/auth approval; use the wrapped callable to decide.
    """
    spec = registry(ctx.settings).get(name)
    if spec is None:
        return {"available": False, "status": "unavailable", "reasons": ["not_exposed"]}
    return {"available": spec.availability["status"] != "unavailable",
            **spec.availability}
