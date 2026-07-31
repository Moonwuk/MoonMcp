"""desync._timed_request — the raw-socket smuggling-timing path (response / read_timeout /
connect_error), previously 0% covered while only the pure interpret_modern() was tested."""

import socket
import threading
import time

import pytest

from moonmcp.web import desync as d


def _raw_server(handler):
    """Start a bare TCP server; `handler(conn)` runs per connection. Returns (host, port, stop)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def loop():
        srv.settimeout(0.25)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except (OSError, TimeoutError):
                continue
            threading.Thread(target=handler, args=(conn,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()

    def _stop():
        stop.set()
        try:
            srv.close()
        except OSError:
            pass

    return "127.0.0.1", port, _stop


def _responder(conn):
    try:
        conn.recv(4096)
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi")
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def _hang(conn):
    # Accept, read the request, then NEVER respond — the client must hit its read timeout.
    try:
        conn.recv(4096)
        time.sleep(2.0)
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


@pytest.mark.asyncio
async def test_timed_request_response():
    host, port, stop = _raw_server(_responder)
    try:
        raw = b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
        pt = await d._timed_request(host, port, False, raw, timeout=2.0)
        assert pt.outcome == "response" and pt.status == 200
        assert pt.elapsed_ms >= 0
    finally:
        stop()


@pytest.mark.asyncio
async def test_timed_request_connect_error():
    # Bind then close to get a definitely-closed port → connection refused.
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    pt = await d._timed_request("127.0.0.1", port, False, b"GET / HTTP/1.1\r\n\r\n", timeout=1.0)
    assert pt.outcome == "connect_error" and pt.status is None


@pytest.mark.timing
@pytest.mark.asyncio
async def test_timed_request_read_timeout():
    host, port, stop = _raw_server(_hang)
    try:
        raw = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 200\r\n\r\nx"
        pt = await d._timed_request(host, port, False, raw, timeout=0.5)
        assert pt.outcome == "read_timeout" and pt.status is None
    finally:
        stop()
