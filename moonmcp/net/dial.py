"""Scope-aware socket dialing — resolve+vet a host ONCE, then dial the pinned IP.

The raw-socket tools (port scan, TLS, JARM, desync, datastore sweep, WebSocket)
handed the hostname straight to ``asyncio.open_connection`` /
``socket.create_connection``, which re-resolves the name independently of the SSRF
guard — a DNS-rebinding TOCTOU: the guard can vet a public IP while the connect
lands on ``127.0.0.1`` / cloud metadata.

These helpers take the SAME ``connect_pin`` the HTTP client uses
(:meth:`ScopeManager.resolve_pin`): they dial the vetted IP while keeping the
original hostname as TLS SNI, so certificate verification and vhost routing are
unchanged — only the TCP connect target is pinned. ``connect_pin=None`` (unit
tests, or ``MOONMCP_BLOCK_PRIVATE=0`` where ``resolve_pin`` returns no pin) dials
by hostname exactly as before.
"""

from __future__ import annotations

import asyncio
import socket
from collections.abc import Callable

# connect_pin(host) -> (block_reason | None, pinned_ip | None)
ConnectPin = Callable[[str], "tuple[str | None, str | None]"]


class ConnectBlocked(OSError):
    """The SSRF connect-guard refused the host at dial time.

    Subclasses ``OSError`` so the raw-socket probes' existing ``except OSError``
    treats it as a failed connection — the safe outcome: we never opened a socket
    to the private / rebinding target.
    """


def resolve_pin_sync(connect_pin: ConnectPin | None, host: str) -> str:
    """Vet *host* and return the IP to dial (or *host* unchanged when no pin
    applies). Blocking (does DNS) — call from a worker thread or the sync TLS path."""

    if connect_pin is None:
        return host
    reason, ip = connect_pin(host)
    if reason is not None:
        raise ConnectBlocked(reason)
    return ip or host


async def open_connection(
    host: str,
    port: int,
    *,
    connect_pin: ConnectPin | None = None,
    ssl_ctx: object | None = None,
    server_hostname: str | None = None,
    timeout: float | None = None,
):
    """``asyncio.open_connection`` to the vetted IP; SNI/Host stays the original host.

    Returns ``(reader, writer)``. Raises :class:`ConnectBlocked` if the guard refuses
    the host. ``ssl_ctx=None`` opens a plain connection (``server_hostname`` ignored).
    """

    dial = await asyncio.to_thread(resolve_pin_sync, connect_pin, host) if connect_pin else host
    kwargs: dict = {}
    if ssl_ctx is not None:
        kwargs["ssl"] = ssl_ctx
        kwargs["server_hostname"] = server_hostname if server_hostname is not None else host
    coro = asyncio.open_connection(dial, port, **kwargs)
    if timeout is not None:
        return await asyncio.wait_for(coro, timeout=timeout)
    return await coro


def create_connection_sync(
    host: str,
    port: int,
    *,
    connect_pin: ConnectPin | None = None,
    timeout: float | None = None,
) -> tuple[socket.socket, str]:
    """Blocking ``socket.create_connection`` to the vetted IP (for the to_thread TLS
    path). Returns ``(sock, dial_ip)`` — wrap ``sock`` in TLS with
    ``server_hostname=host`` so SNI/verification use the original name."""

    dial = resolve_pin_sync(connect_pin, host)
    return socket.create_connection((dial, port), timeout=timeout), dial
