"""Local Web Viewer for MoonMCP — a lightweight dashboard server.

A minimal HTTP server (stdlib ``http.server`` only, no Flask/Bottle) that
exposes the session's in-memory state as JSON endpoints plus a bare-bones
HTML overview page.  Bind address is always 127.0.0.1 (loopback-only); a
random port is chosen unless the caller specifies one.  Every request must
carry ``Authorization: Bearer <token>`` — the token is generated at startup
and returned to the caller.

Endpoints
---------
* ``/``          — overview: run status, severity breakdown, scope info.
* ``/findings``  — list of findings (severity, title, target, timestamp).
* ``/agents``    — agent tree (text bullet-list from ``AgentGraph.render_tree``).
* ``/history``   — recent HTTP exchanges from ``HistoryStore``.

All endpoints return JSON when the client sends ``Accept: application/json``
or when the path ends with ``.json``.  Otherwise a minimal HTML wrapper is
served for human readability in a browser.
"""

from __future__ import annotations

import json
import secrets
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

__all__ = ["ViewerServer", "get_viewer"]


# ---------------------------------------------------------------------------
# Data providers — pluggable adapters so the viewer can read from any store.
# ---------------------------------------------------------------------------

DataProvider = Callable[[], dict[str, Any]]


@dataclass
class ViewerServer:
    """Owns the HTTP server thread, token, and data providers."""

    host: str = "127.0.0.1"
    port: int = 0  # 0 → OS picks a free port
    _token: str = ""
    _server: ThreadingHTTPServer | None = None
    _thread: threading.Thread | None = None
    _providers: dict[str, DataProvider] = field(default_factory=dict)

    # -- lifecycle ----------------------------------------------------------

    def start(self) -> dict[str, Any]:
        """Start the HTTP server in a daemon thread.  Returns metadata."""
        if self._server is not None:
            return self.status()

        self._token = secrets.token_urlsafe(24)
        handler = _make_handler(self._token, self._providers)

        self._server = ThreadingHTTPServer((self.host, self.port), handler)
        self._server.daemon_threads = True
        actual_port = self._server.server_address[1]
        self.port = actual_port

        self._thread = threading.Thread(target=self._server.serve_forever,
                                        name="moonmcp-viewer", daemon=True)
        self._thread.start()

        return {
            "status": "running",
            "host": self.host,
            "port": actual_port,
            "url": f"http://{self.host}:{actual_port}",
            "token": self._token,
            "endpoints": ["/", "/findings", "/agents", "/history"],
        }

    def stop(self) -> dict[str, Any]:
        """Shut the server down and join the thread."""
        if self._server is None:
            return {"status": "stopped"}
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._server = None
        self._thread = None
        return {"status": "stopped", "port": self.port}

    def status(self) -> dict[str, Any]:
        running = self._server is not None
        return {
            "status": "running" if running else "stopped",
            "host": self.host,
            "port": self.port,
            "url": f"http://{self.host}:{self.port}" if running else None,
            "token": self._token if running else None,
        }

    # -- provider registration ----------------------------------------------

    def set_provider(self, name: str, fn: DataProvider) -> None:
        self._providers[name] = fn


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_viewer: ViewerServer | None = None


def get_viewer() -> ViewerServer:
    global _viewer
    if _viewer is None:
        _viewer = ViewerServer()
    return _viewer


# ---------------------------------------------------------------------------
# HTTP handler factory
# ---------------------------------------------------------------------------

_ROUTES = ("/", "/findings", "/agents", "/history")


# ---------------------------------------------------------------------------
# Module-level response helpers (used inside the handler closure)
# ---------------------------------------------------------------------------

def _send_json(handler: BaseHTTPRequestHandler, code: int, body: dict[str, Any]) -> None:
    payload = json.dumps(body, indent=2, default=str).encode()
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(payload)))
    handler.end_headers()
    handler.wfile.write(payload)


def _send_html(handler: BaseHTTPRequestHandler, code: int, html: str) -> None:
    payload = html.encode()
    handler.send_response(code)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(payload)))
    handler.end_headers()
    handler.wfile.write(payload)


def _make_handler(token: str, providers: dict[str, DataProvider]) -> type[BaseHTTPRequestHandler]:
    """Build a request-handler class bound to the specific token + providers."""

    def _check_auth(self: BaseHTTPRequestHandler) -> bool:
        hdr = self.headers.get("Authorization", "")
        if hdr.startswith("Bearer "):
            supplied = hdr[7:].strip()
        else:
            supplied = ""
        # Also accept ?token= query param for browser convenience.
        from urllib.parse import parse_qs, urlparse
        qs = parse_qs(urlparse(self.path).query)
        if not supplied and "token" in qs:
            supplied = qs["token"][0]
        return secrets.compare_digest(supplied, token)

    def _wants_json(self: BaseHTTPRequestHandler) -> bool:
        accept = self.headers.get("Accept", "")
        return "application/json" in accept or self.path.rstrip("/").endswith(".json")

    def _provider_data(route: str) -> dict[str, Any]:
        fn = providers.get(route)
        if fn is None:
            return {"error": "no_provider", "route": route}
        try:
            return fn()
        except Exception as exc:
            return {"error": "provider_error", "detail": f"{type(exc).__name__}: {exc}"}

    class Handler(BaseHTTPRequestHandler):
        # Quiet logging — suppress noisy stderr output.
        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            pass

        def do_GET(self) -> None:  # type: ignore[override]
            from urllib.parse import urlparse

            if not _check_auth(self):
                _send_json(self, HTTPStatus.UNAUTHORIZED,
                           {"error": "unauthorized",
                            "detail": "Bearer token required"})
                return

            path = urlparse(self.path).path.rstrip("/") or "/"
            # Allow .json suffix.
            if path.endswith(".json"):
                path = path[:-5]

            if path not in _ROUTES:
                _send_json(self, HTTPStatus.NOT_FOUND,
                           {"error": "not_found", "path": path,
                            "routes": list(_ROUTES)})
                return

            data = _provider_data(path)

            if _wants_json(self):
                _send_json(self, HTTPStatus.OK, data)
            else:
                _send_html(self, HTTPStatus.OK, _render_html(path, data))

    return Handler


# ---------------------------------------------------------------------------
# Minimal HTML rendering
# ---------------------------------------------------------------------------

_PAGE_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>MoonMCP Dashboard — {title}</title>
  <style>
    body {{ font-family: system-ui, sans-serif; max-width: 960px; margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; }}
    h1 {{ border-bottom: 2px solid #ddd; padding-bottom: .3rem; }}
    h2 {{ color: #555; margin-top: 1.5rem; }}
    table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
    th, td {{ border: 1px solid #ddd; padding: .4rem .6rem; text-align: left; font-size: .9rem; }}
    th {{ background: #f5f5f5; }}
    .badge {{ display: inline-block; padding: .15rem .5rem; border-radius: 3px; font-size: .8rem; font-weight: 600; color: #fff; }}
    .critical {{ background: #d32f2f; }}
    .high     {{ background: #f57c00; }}
    .medium   {{ background: #fbc02d; color: #333; }}
    .low      {{ background: #4caf50; }}
    .info     {{ background: #90a4ae; }}
    pre {{ background: #f8f8f8; padding: 1rem; border-radius: 4px; overflow-x: auto; font-size: .85rem; }}
    nav a {{ margin-right: 1rem; text-decoration: none; color: #1976d2; }}
    nav a:hover {{ text-decoration: underline; }}
  </style>
</head>
<body>
  <nav>
    <a href="/?token={token}">Overview</a>
    <a href="/findings?token={token}">Findings</a>
    <a href="/agents?token={token}">Agents</a>
    <a href="/history?token={token}">History</a>
  </nav>
  <h1>{title}</h1>
{body}
</body>
</html>"""


def _render_html(route: str, data: dict[str, Any]) -> str:
    """Render a minimal HTML page for the given route."""
    token = data.pop("_viewer_token", "")  # injected by the provider wrapper
    if route == "/":
        return _render_overview(data, token)
    if route == "/findings":
        return _render_findings(data, token)
    if route == "/agents":
        return _render_agents(data, token)
    if route == "/history":
        return _render_history(data, token)
    return f"<pre>{json.dumps(data, indent=2, default=str)}</pre>"


def _render_overview(data: dict[str, Any], token: str) -> str:
    severity = data.get("severity_breakdown", {})
    scope_info = data.get("scope", {})
    run_status = data.get("run_status", "idle")

    sev_rows = ""
    for sev in ("critical", "high", "medium", "low", "info"):
        count = severity.get(sev, 0)
        sev_rows += (f'<tr><td><span class="badge {sev}">{sev}</span></td>'
                     f'<td>{count}</td></tr>\n')

    scope_html = json.dumps(scope_info, indent=2, default=str)

    body = f"""\
  <h2>Run Status</h2>
  <p><strong>{run_status}</strong></p>

  <h2>Severity Breakdown</h2>
  <table>
    <tr><th>Severity</th><th>Count</th></tr>
{sev_rows}  </table>

  <h2>Scope</h2>
  <pre>{scope_html}</pre>"""

    return _PAGE_TEMPLATE.format(title="Overview", token=token, body=body)


def _render_findings(data: dict[str, Any], token: str) -> str:
    findings = data.get("findings", [])
    rows = ""
    for f in findings:
        sev = f.get("severity", "info")
        rows += (
            f'<tr><td><span class="badge {sev}">{sev}</span></td>'
            f'<td>{_esc(f.get("title", ""))}</td>'
            f'<td>{_esc(f.get("target", ""))}</td>'
            f'<td>{_esc(f.get("created_at", ""))}</td></tr>\n'
        )

    body = f"""\
  <p>Total findings: <strong>{len(findings)}</strong></p>
  <table>
    <tr><th>Severity</th><th>Title</th><th>Target</th><th>Timestamp</th></tr>
{rows}  </table>"""

    return _PAGE_TEMPLATE.format(title="Findings", token=token, body=body)


def _render_agents(data: dict[str, Any], token: str) -> str:
    tree = data.get("tree", "(no agents)")
    active = data.get("active", 0)

    body = f"""\
  <p>Active agents: <strong>{active}</strong></p>
  <pre>{_esc(tree)}</pre>"""

    return _PAGE_TEMPLATE.format(title="Agent Tree", token=token, body=body)


def _render_history(data: dict[str, Any], token: str) -> str:
    exchanges = data.get("exchanges", [])
    rows = ""
    for e in exchanges:
        rows += (
            f'<tr><td>{e.get("id", "")}</td>'
            f'<td>{_esc(e.get("source", ""))}</td>'
            f'<td>{_esc(e.get("method", ""))}</td>'
            f'<td>{_esc(e.get("url", ""))}</td>'
            f'<td>{e.get("status", "")}</td>'
            f'<td>{e.get("resp_bytes", "")}</td>'
            f'<td>{e.get("elapsed_ms", "")}</td></tr>\n'
        )

    body = f"""\
  <p>Total exchanges: <strong>{data.get("count", 0)}</strong></p>
  <table>
    <tr><th>ID</th><th>Source</th><th>Method</th><th>URL</th><th>Status</th><th>Bytes</th><th>ms</th></tr>
{rows}  </table>"""

    return _PAGE_TEMPLATE.format(title="HTTP History", token=token, body=body)


def _esc(s: str) -> str:
    """Minimal HTML escaping."""
    return (s.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;")
             .replace('"', "&quot;"))