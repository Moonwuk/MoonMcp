"""Single-packet race via HTTP/1.1 last-byte synchronization.

The naive race test — fire N requests with ``asyncio.gather`` — is jitter-bound: the
writes serialize and each request crosses the network independently, so the server may
process them milliseconds apart and a non-atomic check still holds. The single-packet
attack (Kettle) neutralizes jitter by making all N requests *complete at the server*
within the same ~1 ms window.

This is the dependency-free HTTP/1.1 variant — **last-byte synchronization**: open N
connections, send each request except its final byte, wait until every connection is
primed/in-flight, then release the final byte on all N at once. The server finishes
parsing all N almost simultaneously. (The tighter HTTP/2 single-packet variant — all N
streams in one TCP segment — needs an HTTP/2 client and is deferred; it would require
the ``h2`` dependency, against MoonMCP's stdlib-first rule.)

Detection only: N identical requests on a should-be-once action; >1 success is a race.
The socket layer is injectable (``connect``) so the orchestration is unit-testable.
"""

from __future__ import annotations

import asyncio
import functools
import ssl
from collections.abc import Awaitable, Callable

from ..net import dial
from .desync import _status_of  # reuse the status-line parser

Connect = Callable[[str, int, bool, float], Awaitable[tuple]]


def split_last_byte(raw: bytes) -> tuple[bytes, bytes]:
    """Split *raw* into (all-but-last-byte, last-byte). The withheld last byte is what
    makes the server consider the request complete, so releasing it triggers parsing."""

    if len(raw) < 2:
        return b"", raw
    return raw[:-1], raw[-1:]


_DEFAULT_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")


def build_request(host: str, path: str, *, method: str = "POST",
                  headers: dict[str, str] | None = None, body: bytes | str = b"",
                  user_agent: str = _DEFAULT_UA) -> bytes:
    """Build a complete HTTP/1.1 request whose final byte gates completion (a body byte,
    or the terminating LF for a body-less request)."""

    if isinstance(body, str):
        body = body.encode("utf-8", "replace")
    m = method.upper()
    hdrs: dict[str, str] = {"Host": host, "User-Agent": user_agent, "Accept": "*/*",
                            "Connection": "close"}
    if body or m in ("POST", "PUT", "PATCH"):
        hdrs["Content-Length"] = str(len(body))
        hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
    for k, v in (headers or {}).items():
        hdrs[str(k)] = str(v)
    head = f"{m} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items()) + "\r\n"
    return head.encode("latin-1", "replace") + body


def assess_race(statuses: list) -> dict:
    """Aggregate the parallel statuses; >1 success = race signal (verdict ``review``)."""

    hist: dict[str, int] = {}
    for s in statuses:
        hist[str(s)] = hist.get(str(s), 0) + 1
    success = sum(1 for s in statuses if isinstance(s, int) and 200 <= s < 300)
    return {
        "sent": len(statuses), "success_2xx": success, "status_histogram": hist,
        "verdict": "review" if success > 1 else "no_race_signal",
    }


async def _default_connect(host: str, port: int, tls: bool, timeout: float,
                           *, connect_pin=None) -> tuple:
    ssl_ctx = None
    if tls:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
    return await dial.open_connection(host, port, connect_pin=connect_pin, ssl_ctx=ssl_ctx,
                                      server_hostname=host if tls else None, timeout=timeout)


async def single_packet_race(host: str, port: int, tls: bool, raw: bytes, n: int, *,
                             timeout: float = 12.0, settle: float = 0.1,
                             connect: Connect | None = None, connect_pin=None) -> dict:
    """Run the last-byte-synchronized race and report how many requests succeeded."""

    n = max(2, min(n, 40))
    do_connect = connect or functools.partial(_default_connect, connect_pin=connect_pin)
    head, last = split_last_byte(raw)

    conns = await asyncio.gather(*[do_connect(host, port, tls, timeout) for _ in range(n)],
                                 return_exceptions=True)
    live = [c for c in conns if not isinstance(c, BaseException) and c]
    if len(live) < 2:
        return {**assess_race([]), "technique": "http1-last-byte-sync",
                "error": "could not open at least two connections", "connections": len(live)}

    async def _prime(rw) -> None:
        _reader, writer = rw
        writer.write(head)
        await writer.drain()

    # 1) send every request up to (but not including) its final byte, and flush.
    await asyncio.gather(*[_prime(c) for c in live], return_exceptions=True)
    # 2) let all primed bytes reach the server (parsed up to the withheld byte).
    await asyncio.sleep(max(0.0, settle))
    # 3) release the final byte on every connection as tightly as possible.
    for _reader, writer in live:
        writer.write(last)
    await asyncio.gather(*[w.drain() for _r, w in live], return_exceptions=True)

    async def _resp(rw):
        reader, writer = rw
        try:
            data = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            return _status_of(data)[0]
        except (asyncio.TimeoutError, OSError):
            return None
        finally:
            try:
                writer.close()
            except OSError:
                pass

    results = await asyncio.gather(*[_resp(c) for c in live], return_exceptions=True)
    statuses = [r if isinstance(r, int) else None for r in results]
    return {**assess_race(statuses), "technique": "http1-last-byte-sync", "connections": len(live)}
