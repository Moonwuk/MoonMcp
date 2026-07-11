"""Framework debug / console exposure detection.

Debug pages, profilers and admin consoles left reachable in production leak
source, config, queries, environment — and frequently the framework signing
secret itself (Symfony `APP_SECRET`, Laravel `APP_KEY`), which feeds the
`config_audit` forge-to-RCE classifier. A few (Werkzeug's interactive debugger,
Laravel Ignition ≤ 2.5) are direct pre-auth RCE.

Detection = a curated path → distinctive content-signature map (same idea as the
VCS-exposure detector, but for HTML/JSON panels): a panel is confirmed only when a
signature string that a soft-404 wouldn't contain is present, so generic 200 pages
don't false-positive. Non-destructive — GET only, never triggers the RCE path.
"""

from __future__ import annotations

from collections.abc import Callable
from urllib.parse import urljoin

from ..net.http import HttpClient

# path -> (label, [distinctive signatures], severity, note/next-step)
_PANELS: dict[str, tuple[str, list[str], str, str]] = {
    "/_ignition/health-check": (
        "Laravel Ignition", ["can_execute_commands", '"healthy"'], "high",
        "Ignition debug endpoint reachable — CVE-2021-3129 pre-auth RCE on vulnerable "
        "versions; a leaked APP_KEY here feeds the config_audit forge chain"),
    "/_profiler": (
        "Symfony profiler", ["Symfony Profiler", "sf-toolbar", "sf-dump"], "high",
        "Symfony profiler exposed — leaks requests/config and often APP_SECRET "
        "(→ /_fragment forge chain via config_audit)"),
    "/app_dev.php": (
        "Symfony dev front controller", ["sf-toolbar", "sf-dump", "app_dev.php"], "high",
        "dev front controller reachable in prod — debug + profiler enabled"),
    "/telescope/requests": (
        "Laravel Telescope", ["Telescope", "laravel_telescope"], "high",
        "Telescope dashboard exposed — leaks requests, queries, mail, secrets"),
    "/horizon": (
        "Laravel Horizon", ["Horizon", "window.Horizon"], "medium",
        "Horizon queue dashboard exposed"),
    "/actuator/env": (
        "Spring Boot Actuator /env", ["activeProfiles", "propertySources"], "high",
        "Actuator /env exposed — leaks environment and frequently credentials/keys"),
    "/actuator": (
        "Spring Boot Actuator", ['"_links"', '"health"', '"self"'], "medium",
        "Actuator base exposed — enumerate /env, /heapdump, /mappings, /configprops"),
    "/__debug__/": (
        "Django Debug Toolbar", ["djDebug", "djdt"], "medium",
        "Django debug toolbar exposed — DEBUG=True in production"),
    "/console": (
        "Werkzeug/Flask debugger", ["__debugger__", "Werkzeug Debugger", "The console"], "critical",
        "Werkzeug interactive debugger console — arbitrary code execution if the PIN "
        "is unset or known"),
    "/adminer.php": (
        "Adminer", ["Adminer", "adminer.org"], "medium",
        "Adminer database console exposed"),
    "/phpmyadmin/": (
        "phpMyAdmin", ["phpMyAdmin", "pmahomme"], "medium",
        "phpMyAdmin exposed"),
    "/rails/info/routes": (
        "Rails dev info", ["Routing Error", "Path / Url", "rails/info"], "medium",
        "Rails dev routes/properties exposed — running in development env"),
    # DB admin consoles left reachable in prod — a direct browse/query/delete surface.
    "/db/admin": (
        "Mongo-Express", ["Mongo Express", "mongo-express"], "high",
        "Mongo-Express DB console exposed — often no auth (ME_CONFIG_BASICAUTH unset) → "
        "full browse/query/delete of every collection"),
    "/browser/": (
        "pgAdmin", ["pgAdmin", "pgadmin4"], "medium",
        "pgAdmin console exposed — a full PostgreSQL admin UI"),
    "/play": (
        "ClickHouse /play", ["ClickHouse", "Play UI", "play-textarea"], "high",
        "ClickHouse /play SQL console exposed (the DeepSeek pattern) — arbitrary SELECT over the DB"),
    "/redisinsight": (
        "RedisInsight", ["RedisInsight"], "medium",
        "RedisInsight console exposed — a full Redis admin UI"),
}


async def probe_debug_panels(client: HttpClient, base_url: str, *,
                             scope_check: Callable[[str], bool] | None = None) -> list[dict]:
    """Probe each known debug/console path and confirm by content signature."""

    findings: list[dict] = []
    for path, (label, sigs, severity, note) in _PANELS.items():
        url = urljoin(base_url, path)
        r = await client.fetch(url, follow_redirects=False, timeout=10.0, scope_check=scope_check)
        if r.status is None or not r.body:
            continue
        text = r.text(limit=12000)
        if any(s in text for s in sigs):
            findings.append({
                "path": path, "label": label, "status": r.status, "size": len(r.body),
                "severity": severity, "verdict": "confirmed", "detail": note,
            })
    return findings
