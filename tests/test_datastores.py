"""Unauthenticated datastore exposure sweep — pure parsers + raw-socket probes."""

import asyncio
import struct

import pytest

from moonmcp import server as srv
from moonmcp.recon import datastores as ds


# -- pure parsers / interpreters ---------------------------------------------
def test_parse_redis_info_and_finding():
    info = "# Server\r\nredis_version:7.2.4\r\nos:Linux 6.1\r\nrole:master\r\n"
    kv = ds.parse_redis_info(info)
    assert kv["redis_version"] == "7.2.4" and kv["role"] == "master"
    f = ds.redis_finding(info)
    assert f["verdict"] == "confirmed" and f["severity"] == "critical"
    assert "7.2.4" in f["detail"] and "master" in f["detail"]


def test_build_op_msg_is_opmsg():
    msg = ds.build_op_msg("listDatabases")
    length, req, resp, opcode = struct.unpack_from("<iiii", msg, 0)
    assert opcode == 2013 and length == len(msg) and resp == 0
    assert b"listDatabases" in msg and b"admin" in msg


def _mongo_reply(payload: bytes) -> bytes:
    body = struct.pack("<i", 0) + b"\x00" + payload
    return struct.pack("<iiii", 16 + len(body), 1, 1, 2013) + body


def test_interpret_mongo_reply_states():
    assert ds.interpret_mongo_reply(_mongo_reply(b"databases sizeOnDisk totalSize"))["verdict"] == "confirmed"
    assert ds.interpret_mongo_reply(_mongo_reply(b"errmsg: not authorized on admin"))["verdict"] == "protected"
    assert ds.interpret_mongo_reply(_mongo_reply(b"ok"))["verdict"] == "reachable"
    # a non-OP_MSG frame (wrong opcode) is not MongoDB
    non = struct.pack("<iiii", 20, 1, 1, 1) + b"xxxx"
    assert ds.interpret_mongo_reply(non) is None
    assert ds.interpret_mongo_reply(b"tiny") is None


def test_http_interpreters():
    assert ds.interpret_es(200, {}, '{"cluster_name":"x","number_of_nodes":3}')["severity"] == "high"
    assert ds.interpret_es(401, {}, "nope") is None
    assert ds.interpret_couchdb(200, {}, '{"couchdb":"Welcome","version":"3.3.2"}')["severity"] == "high"
    assert ds.interpret_couchdb(200, {}, "<html>not couch</html>") is None
    assert ds.interpret_influxdb(204, {"x-influxdb-version": "1.6.4"}, "")["severity"] == "medium"
    assert ds.interpret_influxdb(204, {}, "") is None
    assert ds.interpret_yarn(200, {}, '{"clusterInfo":{"resourceManagerVersion":"3.3"}}')["severity"] == "critical"
    assert ds.interpret_tidb(200, {}, '{"version":"8.1.0","git_hash":"abc"}')["severity"] == "medium"


def test_ports_to_check():
    assert ds.ports_to_check(6379, "db") == [6379]           # explicit port wins
    assert ds.ports_to_check(None, "db") == sorted(ds.DB_PORTS)
    assert ds.ports_to_check(None, "6379,27017") == [6379, 27017]
    assert ds.ports_to_check(None, "6379-6381") == [6379, 6380, 6381]


# -- raw-socket probes against tiny fake servers -----------------------------
async def _serve(handler):
    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


async def _stop(*servers):
    for s in servers:
        s.close()
        await s.wait_closed()


@pytest.mark.asyncio
async def test_probe_redis_unauth():
    async def handler(reader, writer):
        await reader.read(64)                                # PING\r\n
        writer.write(b"+PONG\r\n")
        await writer.drain()
        await reader.read(64)                                # INFO server\r\n
        writer.write(b"# Server\r\nredis_version:7.2.4\r\nrole:master\r\nos:Linux\r\n")
        await writer.drain()
        writer.close()

    server, port = await _serve(handler)
    try:
        hit = await ds.probe_redis("127.0.0.1", port, 2.0)
        assert hit and hit["verdict"] == "confirmed" and "7.2.4" in hit["detail"]
    finally:
        await _stop(server)


@pytest.mark.asyncio
async def test_probe_redis_protected():
    async def handler(reader, writer):
        await reader.read(64)
        writer.write(b"-NOAUTH Authentication required.\r\n")
        await writer.drain()
        writer.close()

    server, port = await _serve(handler)
    try:
        hit = await ds.probe_redis("127.0.0.1", port, 2.0)
        assert hit and hit["verdict"] == "protected"
    finally:
        await _stop(server)


@pytest.mark.asyncio
async def test_probe_memcached_and_mongodb():
    async def memc(reader, writer):
        await reader.read(64)
        writer.write(b"VERSION 1.6.21\r\n")
        await writer.drain()
        writer.close()

    async def mongo(reader, writer):
        await reader.read(2048)                              # the OP_MSG query
        writer.write(_mongo_reply(b"databases sizeOnDisk totalSize"))
        await writer.drain()
        writer.close()

    ms, mport = await _serve(memc)
    gs, gport = await _serve(mongo)
    try:
        m = await ds.probe_memcached("127.0.0.1", mport, 2.0)
        assert m and "1.6.21" in m["detail"] and m["severity"] == "medium"
        g = await ds.probe_mongodb("127.0.0.1", gport, 2.0)
        assert g and g["verdict"] == "confirmed"
    finally:
        await _stop(ms, gs)


@pytest.mark.asyncio
async def test_probe_redis_closed_port_returns_none():
    # nothing listening → connection refused → no finding (not an error)
    assert await ds.probe_redis("127.0.0.1", 1, 0.5) is None


# -- the db_exposure tool: orchestration + gating + registration -------------
@pytest.mark.asyncio
async def test_db_exposure_tool_detects_redis(fresh_context, monkeypatch):
    async def handler(reader, writer):
        await reader.read(64)
        writer.write(b"+PONG\r\n")
        await writer.drain()
        await reader.read(64)
        writer.write(b"redis_version:7.2.4\r\nrole:master\r\nos:Linux\r\n")
        await writer.drain()
        writer.close()

    server, port = await _serve(handler)
    monkeypatch.setitem(ds.DB_PORTS, port, ("Redis", "redis"))
    try:
        res = await srv.db_exposure(target=f"127.0.0.1:{port}", timeout=2.0)
        assert res["checked"] == [port]
        assert any(f["service"] == "Redis" and f["verdict"] == "confirmed"
                   for f in res["findings"]), res
    finally:
        await _stop(server)


@pytest.mark.asyncio
async def test_db_exposure_intrusive_gated(fresh_context):
    from dataclasses import replace
    fresh_context.settings = replace(fresh_context.settings, allow_intrusive=False)
    res = await srv.db_exposure(target="127.0.0.1:6379")
    assert res["error"] == "disabled"


@pytest.mark.asyncio
async def test_db_exposure_registered():
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "db_exposure" in tools


@pytest.mark.asyncio
async def test_db_exposure_pins_raw_probe_to_resolved_ip(fresh_context, monkeypatch):
    # With the SSRF guard on, db_exposure must connect the raw-TCP handshake to the
    # ONCE-resolved IP (not re-resolve the hostname at connect time) — so a rebinding
    # swap can't land a Redis/Mongo probe on an internal store.
    object.__setattr__(fresh_context.settings, "allow_intrusive", True)
    fresh_context.scope.block_private = True
    fresh_context.scope._resolver = lambda h: ["93.184.216.34"]   # a public address
    fresh_context.scope.add("db.example")

    captured = {}

    async def _fake_redis(connect_host, port, timeout):
        captured["host"] = connect_host
        return None

    monkeypatch.setitem(ds.RAW_PROBES, "redis", _fake_redis)
    await srv.db_exposure(target="db.example:6379")
    assert captured["host"] == "93.184.216.34"    # pinned IP, not the hostname


@pytest.mark.asyncio
async def test_db_exposure_refuses_host_resolving_private(fresh_context):
    # a hostname that resolves to a private/reserved address is refused.
    object.__setattr__(fresh_context.settings, "allow_intrusive", True)
    fresh_context.scope.block_private = True
    fresh_context.scope._resolver = lambda h: ["127.0.0.1"]
    fresh_context.scope.add("rebind.example")
    res = await srv.db_exposure(target="rebind.example:6379")
    assert res.get("error")   # blocked by the SSRF guard (gate or in-tool pin check)
