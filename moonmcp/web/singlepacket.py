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
import ssl
from collections.abc import Awaitable, Callable

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


async def _default_connect(host: str, port: int, tls: bool, timeout: float) -> tuple:
    ssl_ctx = None
    if tls:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
    fut = asyncio.open_connection(host, port, ssl=ssl_ctx, server_hostname=host if tls else None)
    return await asyncio.wait_for(fut, timeout=timeout)


async def single_packet_race(host: str, port: int, tls: bool, raw: bytes, n: int, *,
                             timeout: float = 12.0, settle: float = 0.1,
                             connect: Connect | None = None) -> dict:
    """Run the last-byte-synchronized race, owning every opened connection.

    Cleanup also covers a partial connection batch, write failure and caller
    cancellation. Connection tasks settle before cleanup finishes, so an opening
    connection cannot arrive after its owner has returned.
    """

    n = max(2, min(n, 40))
    do_connect = connect or _default_connect
    head, last = split_last_byte(raw)

    live: list[tuple] = []
    closing = False

    def close_writer(writer):
        try:
            writer.close()
        except Exception:
            # A broken transport must not prevent closing its peers or replace
            # the original cancellation/write error.
            pass

    async def open_one():
        connection = await do_connect(host, port, tls, timeout)
        if connection:
            live.append(connection)
            if closing:
                close_writer(connection[1])
        return connection

    opening = [asyncio.create_task(open_one()) for _ in range(n)]

    async def _prime(rw) -> None:
        _reader, writer = rw
        writer.write(head)
        await writer.drain()

    async def _resp(rw):
        reader, _writer = rw
        try:
            data = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            return _status_of(data)[0]
        except (asyncio.TimeoutError, OSError):
            return None

    async def cleanup():
        await asyncio.gather(*opening, return_exceptions=True)
        for _reader, writer in live:
            close_writer(writer)

        async def wait_closed(writer):
            if not hasattr(writer, "wait_closed"):
                return
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
            except Exception:
                pass

        await asyncio.gather(*(wait_closed(w) for _r, w in live), return_exceptions=True)

    try:
        await asyncio.gather(*opening, return_exceptions=True)
        if len(live) < 2:
            return {**assess_race([]), "technique": "http1-last-byte-sync",
                    "error": "could not open at least two connections", "connections": len(live)}

        # 1) prime all requests, keeping their last byte withheld.
        await asyncio.gather(*[_prime(c) for c in live], return_exceptions=True)
        # 2) allow the primed bytes to reach the server.
        await asyncio.sleep(max(0.0, settle))
        # 3) release the final byte on every connection as tightly as possible.
        for _reader, writer in live:
            writer.write(last)
        await asyncio.gather(*[w.drain() for _r, w in live], return_exceptions=True)

        results = await asyncio.gather(*[_resp(c) for c in live], return_exceptions=True)
        statuses = [r if isinstance(r, int) else None for r in results]
        return {**assess_race(statuses), "technique": "http1-last-byte-sync", "connections": len(live)}
    finally:
        closing = True
        for task in opening:
            if not task.done():
                task.cancel()
        # Close immediately, then settle connectors and wait for transport
        # closure independently of further cancellation of the caller.
        for _reader, writer in live:
            close_writer(writer)
        cleanup_task = asyncio.create_task(cleanup())
        interrupted = False
        while not cleanup_task.done():
            try:
                await asyncio.shield(cleanup_task)
            except asyncio.CancelledError:
                interrupted = True
        cleanup_task.result()
        if interrupted:
            raise asyncio.CancelledError()
