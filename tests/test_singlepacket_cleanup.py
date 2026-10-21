"""Owned fake transports exercise race-probe teardown without network traffic."""

import asyncio

import pytest

from moonmcp.web import singlepacket as sp


class Writer:
    def __init__(self, *, fail_write=False, fail_close=False):
        self.fail_write = fail_write
        self.fail_close = fail_close
        self.closed = False
        self.waited = False
        self.primed = asyncio.Event()
        self.drain_gate = None
        self.close_gate = None
        self.closing = asyncio.Event()

    def write(self, data):
        if self.fail_write and len(data) == 1:
            raise OSError("last-byte write failed")

    async def drain(self):
        self.primed.set()
        if self.drain_gate is not None:
            await self.drain_gate.wait()

    def close(self):
        self.closed = True
        if self.fail_close:
            raise OSError("broken close")

    async def wait_closed(self):
        self.closing.set()
        if self.close_gate is not None:
            await self.close_gate.wait()
        self.waited = True


class Reader:
    def __init__(self, *, error=None, gate=None):
        self.error = error
        self.gate = gate
        self.reading = asyncio.Event()

    async def read(self, limit):
        self.reading.set()
        if self.error is not None:
            raise self.error
        if self.gate is not None:
            await self.gate.wait()
        return b"HTTP/1.1 200 OK\r\n\r\n"


def connector(pairs):
    connections = iter(pairs)

    async def connect(*args):
        connection = next(connections)
        if isinstance(connection, Exception):
            raise connection
        return connection

    return connect


async def test_partial_connection_batch_closes_the_lone_transport():
    writer = Writer()
    result = await sp.single_packet_race(
        "unused.invalid", 80, False, b"request", 2, settle=0,
        connect=connector([(Reader(), writer), OSError("refused")]),
    )
    assert result["connections"] == 1 and result["success_2xx"] == 0
    assert writer.closed and writer.waited


async def test_release_write_failure_closes_every_transport_without_masking_error():
    writers = [Writer(fail_write=True), Writer(fail_close=True)]
    with pytest.raises(OSError, match="last-byte write failed"):
        await sp.single_packet_race(
            "unused.invalid", 80, False, b"request", 2, settle=0,
            connect=connector([(Reader(), writer) for writer in writers]),
        )
    assert all(writer.closed and writer.waited for writer in writers)


@pytest.mark.parametrize("failure", [RuntimeError("read failed"), OSError("connection lost")])
async def test_response_failure_closes_peers_and_keeps_status_uncertain(failure):
    writers = [Writer(), Writer()]
    result = await sp.single_packet_race(
        "unused.invalid", 80, False, b"request", 2, settle=0,
        connect=connector([(Reader(error=failure), writers[0]), (Reader(), writers[1])]),
    )
    assert result["status_histogram"] == {"None": 1, "200": 1}
    assert all(writer.closed and writer.waited for writer in writers)


async def test_response_timeout_closes_all_transports():
    writers = [Writer(), Writer()]
    gate = asyncio.Event()
    result = await sp.single_packet_race(
        "unused.invalid", 80, False, b"request", 2, settle=0, timeout=0.01,
        connect=connector([(Reader(gate=gate), writer) for writer in writers]),
    )
    assert result["status_histogram"] == {"None": 2}
    assert all(writer.closed and writer.waited for writer in writers)


@pytest.mark.parametrize("phase", ["prime", "settle", "read"])
async def test_cancellation_in_each_active_phase_closes_every_transport(phase):
    writers = [Writer(), Writer()]
    readers = [Reader(), Reader()]
    gate = asyncio.Event()
    if phase == "prime":
        for writer in writers:
            writer.drain_gate = gate
    if phase == "read":
        for reader in readers:
            reader.gate = gate
    worker = asyncio.create_task(sp.single_packet_race(
        "unused.invalid", 80, False, b"request", 2,
        settle=60 if phase == "settle" else 0,
        connect=connector(list(zip(readers, writers, strict=True))),
    ))
    signal = readers[0].reading if phase == "read" else writers[-1].primed
    await asyncio.wait_for(signal.wait(), timeout=2)
    worker.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(worker, timeout=2)
    assert all(writer.closed and writer.waited for writer in writers)


async def test_cancellation_during_connect_owns_connections_returned_while_stopping():
    writers = [Writer(), Writer()]
    opened, stopped, release = asyncio.Event(), asyncio.Event(), asyncio.Event()
    calls = 0

    async def connect(*args):
        nonlocal calls
        calls += 1
        if calls == 1:
            opened.set()
            return Reader(), writers[0]
        try:
            await release.wait()
        except asyncio.CancelledError:
            stopped.set()
            await release.wait()
        return Reader(), writers[1]

    worker = asyncio.create_task(sp.single_packet_race(
        "unused.invalid", 80, False, b"request", 2, connect=connect,
    ))
    await asyncio.wait_for(opened.wait(), timeout=2)
    worker.cancel()
    await asyncio.wait_for(stopped.wait(), timeout=2)
    assert not worker.done()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(worker, timeout=2)
    assert all(writer.closed and writer.waited for writer in writers)


async def test_repeated_cancellation_waits_for_transport_closure():
    writers = [Writer(), Writer()]
    release = asyncio.Event()
    for writer in writers:
        writer.close_gate = release
    worker = asyncio.create_task(sp.single_packet_race(
        "unused.invalid", 80, False, b"request", 2, settle=0,
        connect=connector([(Reader(), writer) for writer in writers]),
    ))
    await asyncio.wait_for(writers[-1].closing.wait(), timeout=2)
    worker.cancel()
    await asyncio.sleep(0)
    worker.cancel()
    await asyncio.sleep(0)
    assert not worker.done() and all(writer.closed for writer in writers)
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(worker, timeout=2)
    assert all(writer.waited for writer in writers)
