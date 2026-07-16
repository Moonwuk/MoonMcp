"""Per-call pinned-IP context for the SSRF DNS-rebinding guard.

The scope gate (``_require_scope``) resolves each active tool's target **once** and
records the validated ``(host, ip)`` here. Raw-socket probes then connect to that IP
via :func:`connect_host` instead of re-resolving the name at connect time, closing the
rebind window between the gate's check and the connection.

Safety: :func:`connect_host` returns the pin **only** for the exact gated host. A tool
that connects to a *different* host (candidate origins during origin discovery, a
redirect target, …) transparently falls back to the hostname — so the pin can never
send a connection to the wrong address. The value is a context variable, so concurrent
tool calls (each in its own task context) don't see each other's pin, and every active
tool overwrites it at its own gate, so a stale pin is never read.
"""

from __future__ import annotations

import contextvars

_PIN: contextvars.ContextVar[tuple[str, str] | None] = contextvars.ContextVar(
    "moonmcp_pinned_ip", default=None,
)


def set_pin(host: str | None, ip: str | None) -> None:
    """Record the gate-validated ``host → ip`` pin (or clear it when either is empty)."""

    _PIN.set((host.strip().lower(), ip) if host and ip else None)


def connect_host(host: str) -> str:
    """The pinned IP to connect to for *host*, or *host* itself when it isn't the
    currently-pinned target (or pinning is off / block_private disabled)."""

    p = _PIN.get()
    if p is not None and host and p[0] == host.strip().lower():
        return p[1]
    return host


def current() -> tuple[str, str] | None:
    """The current ``(host, ip)`` pin, if any (for tests / diagnostics)."""

    return _PIN.get()
