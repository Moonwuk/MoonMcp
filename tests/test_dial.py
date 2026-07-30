"""net/dial.py — scope-aware pinning for the raw-socket tools.

Closes the DNS-rebinding TOCTOU: the vetted IP is the dialed IP, and a host the
guard refuses raises ConnectBlocked instead of opening a socket.
"""

import asyncio

import pytest

from moonmcp.net import dial


def test_resolve_pin_sync_returns_vetted_ip():
    pin = lambda h: (None, "93.184.216.34")
    assert dial.resolve_pin_sync(pin, "example.com") == "93.184.216.34"


def test_resolve_pin_sync_blocks():
    pin = lambda h: ("private/reserved", None)
    with pytest.raises(dial.ConnectBlocked):
        dial.resolve_pin_sync(pin, "rebind.example")


def test_resolve_pin_sync_none_is_passthrough():
    assert dial.resolve_pin_sync(None, "example.com") == "example.com"
    # a pin that returns no IP (block_private off) also passes the host through
    assert dial.resolve_pin_sync(lambda h: (None, None), "example.com") == "example.com"


def test_connect_blocked_is_oserror():
    # the raw-socket probes catch OSError; ConnectBlocked must be caught by that.
    assert issubclass(dial.ConnectBlocked, OSError)


@pytest.mark.asyncio
async def test_open_connection_dials_pinned_ip(monkeypatch):
    seen = {}

    async def fake_open(host, port, **kw):
        seen["host"] = host
        seen["port"] = port
        seen["server_hostname"] = kw.get("server_hostname")
        return ("reader", "writer")

    monkeypatch.setattr(asyncio, "open_connection", fake_open)
    r, w = await dial.open_connection(
        "example.com", 443, connect_pin=lambda h: (None, "203.0.113.9"),
        ssl_ctx=object(), timeout=5)
    assert seen["host"] == "203.0.113.9"        # dialed the vetted IP
    assert seen["server_hostname"] == "example.com"   # SNI kept the original name
    assert (r, w) == ("reader", "writer")


@pytest.mark.asyncio
async def test_open_connection_raises_when_blocked(monkeypatch):
    async def fake_open(host, port, **kw):
        raise AssertionError("must not connect when the guard blocks the host")

    monkeypatch.setattr(asyncio, "open_connection", fake_open)
    with pytest.raises(dial.ConnectBlocked):
        await dial.open_connection(
            "rebind.example", 6379, connect_pin=lambda h: ("blocked: private", None))


# -- the raw-socket modules must actually thread connect_pin to the dial --------
@pytest.mark.asyncio
async def test_ports_probe_dials_pinned_ip(monkeypatch):
    from moonmcp.net import ports

    seen = {}

    async def fake_open(host, port, **kw):
        seen["host"] = host
        raise ConnectionRefusedError

    monkeypatch.setattr(asyncio, "open_connection", fake_open)
    st = await ports._probe_port("example.com", 6379, 1.0, False,
                                 connect_pin=lambda h: (None, "203.0.113.5"))
    assert seen["host"] == "203.0.113.5"   # dialed the vetted IP, not the hostname
    assert st.open is False


@pytest.mark.asyncio
async def test_ports_probe_blocked_host_never_connects(monkeypatch):
    from moonmcp.net import ports

    async def fake_open(host, port, **kw):
        raise AssertionError("must not open a socket to a blocked host")

    monkeypatch.setattr(asyncio, "open_connection", fake_open)
    st = await ports._probe_port("rebind.example", 6379, 1.0, False,
                                 connect_pin=lambda h: ("blocked: private/reserved", None))
    assert st.open is False   # ConnectBlocked (OSError) → reported closed, no socket opened


@pytest.mark.asyncio
async def test_datastore_redis_dials_pinned_ip(monkeypatch):
    from moonmcp.recon import datastores

    seen = {}

    async def fake_open(host, port, **kw):
        seen["host"] = host
        raise ConnectionRefusedError

    monkeypatch.setattr(asyncio, "open_connection", fake_open)
    res = await datastores.probe_redis("db.example", 6379, 1.0,
                                       connect_pin=lambda h: (None, "198.51.100.9"))
    assert seen["host"] == "198.51.100.9"
    assert res is None


def test_create_connection_sync_dials_pinned_ip(monkeypatch):
    import socket

    seen = {}

    def fake_cc(addr, timeout=None):
        seen["addr"] = addr
        raise ConnectionRefusedError

    monkeypatch.setattr(socket, "create_connection", fake_cc)
    with pytest.raises(ConnectionRefusedError):
        dial.create_connection_sync("host.example", 443,
                                    connect_pin=lambda h: (None, "192.0.2.7"), timeout=1)
    assert seen["addr"] == ("192.0.2.7", 443)   # TLS sync path pins too
