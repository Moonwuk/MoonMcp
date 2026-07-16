"""Runtime configuration for MoonMCP.

All settings are sourced from environment variables so the server can be
configured declaratively from an MCP client's ``env`` block.  Nothing here
performs I/O; :func:`load_settings` is a pure snapshot of the environment.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    v = raw.strip().lower()
    if v in {"1", "true", "yes", "on", "y", "t", "enable", "enabled"}:
        return True
    if v in {"0", "false", "no", "off", "n", "f", "disable", "disabled"}:
        return False
    # An unrecognised value must NOT silently disable a safety flag (enforce_scope /
    # block_private default True) — fall back to the default rather than flip to False.
    # This includes the EMPTY string: `MOONMCP_BLOCK_PRIVATE=` reads as "leave at
    # default", not "off" (unsetting and blanking must behave the same for a safety
    # flag, so a stray empty env value can't quietly turn the SSRF guard off).
    return default


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


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
    # Even when enabled these still honour the scope.
    allow_intrusive: bool = True
    # Hard-block private / loopback / link-local / reserved IP targets (SSRF
    # guard). No active tool can bypass this. Turn OFF for internal-network
    # engagements where you deliberately test RFC1918 space.
    block_private: bool = True

    # --- Networking -------------------------------------------------------
    # Global default request timeout in seconds.
    timeout: float = 10.0
    # Token-bucket rate limit: max outbound requests per second (0 = unlimited).
    rate_limit: float = 20.0
    # Max concurrent outbound connections.
    max_concurrency: int = 20
    # User-Agent used for HTTP probing.
    user_agent: str = (
        "MoonMCP/0.1 (+https://github.com/Moonwuk/MoonMcp; recon)"
    )
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
        allow_intrusive=_env_bool("MOONMCP_ALLOW_INTRUSIVE", True),
        block_private=_env_bool("MOONMCP_BLOCK_PRIVATE", True),
        timeout=_env_float("MOONMCP_TIMEOUT", 10.0),
        rate_limit=_env_float("MOONMCP_RATE_LIMIT", 20.0),
        max_concurrency=_env_int("MOONMCP_MAX_CONCURRENCY", 20),
        user_agent=os.environ.get(
            "MOONMCP_USER_AGENT",
            "MoonMCP/0.1 (+https://github.com/Moonwuk/MoonMcp; recon)",
        ),
        follow_redirects=_env_bool("MOONMCP_FOLLOW_REDIRECTS", True),
        max_redirects=_env_int("MOONMCP_MAX_REDIRECTS", 5),
        shodan_api_key=os.environ.get("MOONMCP_SHODAN_API_KEY") or os.environ.get("SHODAN_API_KEY"),
        nvd_api_key=os.environ.get("MOONMCP_NVD_API_KEY") or os.environ.get("NVD_API_KEY"),
        allow_external_tools=_env_bool("MOONMCP_ALLOW_EXTERNAL_TOOLS", True),
        external_timeout=_env_float("MOONMCP_EXTERNAL_TIMEOUT", 300.0),
        screenshot_dir=os.environ.get("MOONMCP_SCREENSHOT_DIR", ""),
    )
