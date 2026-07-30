"""Runtime configuration for MoonMCP.

All settings are sourced from environment variables so the server can be
configured declaratively from an MCP client's ``env`` block.  Nothing here
performs I/O; :func:`load_settings` is a pure snapshot of the environment.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

# Generic browser UA so probe traffic doesn't fingerprint the tool (many WAFs — PT
# AF, QRATOR — block non-browser UAs). Single source of truth: the Settings default
# and load_settings() both reference this, so they can never drift apart.
_DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    v = raw.strip().lower()
    if v in {"1", "true", "yes", "on", "y", "t", "enable", "enabled"}:
        return True
    if v in {"0", "false", "no", "off", "n", "f", "disable", "disabled"}:
        return False
    # An unrecognised OR EMPTY value must NOT silently disable a safety flag
    # (enforce_scope / block_private default True) — an empty string is what MCP
    # client env blocks and shell wrappers routinely produce for an "unset" var, so
    # treat it as "use the default", never as "off". Only explicit 0/false/off/…
    # disable.
    return default


def _env_float(name: str, default: float, minimum: float | None = None) -> float:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        val = float(raw)
    except ValueError:
        return default
    # Clamp nonsensical values (e.g. a negative timeout that would break socket ops)
    # to a safe floor rather than propagating them into the networking layer.
    if minimum is not None and val < minimum:
        return minimum
    return val


def _env_int(name: str, default: int, minimum: int | None = None) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        val = int(raw)
    except ValueError:
        return default
    if minimum is not None and val < minimum:
        return minimum
    return val


def _env_list(name: str) -> list[str]:
    raw = os.environ.get(name, "")
    return [item.strip() for item in raw.replace("\n", ",").split(",") if item.strip()]


@dataclass(frozen=True)
class Settings:
    """Immutable snapshot of MoonMCP configuration."""

    # --- Scope / safety ---------------------------------------------------
    # Enforce the authorization scope on every packet-sending tool.  When True
    # (the default) active tools refuse to touch a target that is not in scope.
    enforce_scope: bool = True
    # Initial scope entries (domains / IPs / CIDRs), e.g. "*.example.com,10.0.0.0/8".
    scope: list[str] = field(default_factory=list)
    # Out-of-scope entries that always override the allowlist.
    scope_exclude: list[str] = field(default_factory=list)
    # Allow intrusive tools (port scan, content discovery, active fuzzing).
    # Even when enabled these still honour the scope. Default OFF — the safe
    # posture for a tool whose most restrictive RoE (gosuslugi/k2-cloud/rambler)
    # bans scanners. The launcher and MOONMCP_ALLOW_INTRUSIVE=1 enable per
    # engagement; the dataclass must not default to ON, or a run without the
    # launcher would violate those programs silently (audit 2026-07-27, debt #4).
    allow_intrusive: bool = False
    # Hard-block private / loopback / link-local / reserved IP targets (SSRF
    # guard). No active tool can bypass this. Turn OFF for internal-network
    # engagements where you deliberately test RFC1918 space.
    block_private: bool = True

    # --- Networking -------------------------------------------------------
    # Global default request timeout in seconds.
    timeout: float = 10.0
    # Token-bucket rate limit: max outbound requests per second (0 = unlimited).
    # Default 10 — the safe floor across targets.yaml RoE (konsolpro=5, tochka=10,
    # gosuslugi=30). A run without the launcher must not exceed the lowest
    # program's limit (audit 2026-07-27, debt #5).
    rate_limit: float = 10.0
    # Max concurrent outbound connections.
    max_concurrency: int = 20
    # User-Agent used for HTTP probing. Default is a generic browser UA (see
    # _DEFAULT_USER_AGENT) so probe traffic does not fingerprint the tool. Override
    # via MOONMCP_USER_AGENT for a program UA.
    user_agent: str = _DEFAULT_USER_AGENT
    # Follow HTTP redirects when probing.
    follow_redirects: bool = True
    max_redirects: int = 5

    # --- OSINT / API keys (all optional) ----------------------------------
    shodan_api_key: str | None = None
    # Custom NVD API key raises the CVE-lookup rate limit.
    nvd_api_key: str | None = None

    # --- External CLI integration ----------------------------------------
    # Allow MoonMCP to shell out to installed CLI tools (nuclei, httpx, ...).
    allow_external_tools: bool = True
    # Hard ceiling (seconds) on any single external CLI invocation.
    external_timeout: float = 300.0

    # Directory for saved page screenshots (Playwright, optional).
    screenshot_dir: str = ""


def load_settings() -> Settings:
    """Build a :class:`Settings` snapshot from the current environment."""

    return Settings(
        enforce_scope=_env_bool("MOONMCP_ENFORCE_SCOPE", True),
        scope=_env_list("MOONMCP_SCOPE"),
        scope_exclude=_env_list("MOONMCP_SCOPE_EXCLUDE"),
        allow_intrusive=_env_bool("MOONMCP_ALLOW_INTRUSIVE", False),
        block_private=_env_bool("MOONMCP_BLOCK_PRIVATE", True),
        timeout=_env_float("MOONMCP_TIMEOUT", 10.0, minimum=0.1),
        rate_limit=_env_float("MOONMCP_RATE_LIMIT", 10.0, minimum=0.0),
        max_concurrency=_env_int("MOONMCP_MAX_CONCURRENCY", 20, minimum=1),
        user_agent=os.environ.get("MOONMCP_USER_AGENT", _DEFAULT_USER_AGENT),
        follow_redirects=_env_bool("MOONMCP_FOLLOW_REDIRECTS", True),
        max_redirects=_env_int("MOONMCP_MAX_REDIRECTS", 5, minimum=0),
        shodan_api_key=os.environ.get("MOONMCP_SHODAN_API_KEY") or os.environ.get("SHODAN_API_KEY"),
        nvd_api_key=os.environ.get("MOONMCP_NVD_API_KEY") or os.environ.get("NVD_API_KEY"),
        allow_external_tools=_env_bool("MOONMCP_ALLOW_EXTERNAL_TOOLS", True),
        external_timeout=_env_float("MOONMCP_EXTERNAL_TIMEOUT", 300.0, minimum=1.0),
        screenshot_dir=os.environ.get("MOONMCP_SCREENSHOT_DIR", ""),
    )
