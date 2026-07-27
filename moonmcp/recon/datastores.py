"""Unauthenticated datastore exposure sweep — read-only protocol handshakes.

`port_scan` proves a port is *open* but sends no protocol probe, and `stack_probe`
is HTTP-only. This module speaks the **minimal read-only handshake** for each data
store and returns an unauth verdict from a clean protocol differential — the flagship
gap from docs/DATABASE_RESEARCH.md Theme B.

Every handshake is non-destructive: a Redis `PING`/`INFO`, a memcached `version`, a
MongoDB `listDatabases` wire query, or an HTTP metadata read (`/_cat/indices`,
`/_all_dbs`, `/ping`, `/ws/v1/cluster/info`). Nothing is ever written — no
`CONFIG SET`/`SLAVEOF`/`MODULE LOAD`, no collection dump, no app submit. Exploitation
of an exposed store is handed to Strix.

Pure parsers/interpreters + raw-TCP probes live here (trivially testable); the HTTP
reads and scope gating live in the `db_exposure` server tool.

Sources: https://paper.seebug.org/977/ (Redis) · https://www.verylazytech.com/mongodb-port-27017-27018 ·
https://www.wiz.io/blog/wiz-research-uncovers-exposed-deepseek-database-leak (ES/ClickHouse) ·
https://github.com/Al1ex/Hadoop-Yarn-ResourceManager-RCE (YARN).
"""

from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass, field

# port -> (service name, handshake kind). Raw-TCP kinds: redis/memcached/mongodb.
# HTTP kinds are read via the shared HTTP client in the server tool.
DB_PORTS: dict[int, tuple[str, str]] = {
    6379: ("Redis", "redis"),
    6380: ("Redis (alt)", "redis"),
    11211: ("Memcached", "memcached"),
    27017: ("MongoDB", "mongodb"),
    27018: ("MongoDB (shard)", "mongodb"),
    9200: ("Elasticsearch/OpenSearch", "http-es"),
    5984: ("CouchDB", "http-couchdb"),
    8086: ("InfluxDB", "http-influxdb"),
    8088: ("Hadoop YARN", "http-yarn"),
    10080: ("TiDB status", "http-tidb"),
}

# HTTP kind -> the single read-only path to fetch.
HTTP_PATHS: dict[str, str] = {
    "http-es": "/",
    "http-couchdb": "/",
    "http-influxdb": "/ping",
    "http-yarn": "/ws/v1/cluster/info",
    "http-tidb": "/status",
}


@dataclass
class DatastoreResult:
    host: str
    findings: list[dict] = field(default_factory=list)
    checked: list[int] = field(default_factory=list)
    error: str | None = None


# ── raw-TCP handshakes ──────────────────────────────────────────────────────

def _close(writer) -> None:
    try:
        writer.close()
    except OSError:
        pass


async def _open(host: str, port: int, timeout: float):
    return await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)


def parse_redis_info(text: str) -> dict[str, str]:
    """Parse a Redis ``INFO`` reply (``key:value`` lines) into a dict."""

    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        k, _, v = line.partition(":")
        out[k.strip()] = v.strip()
    return out


def redis_finding(info: str) -> dict:
    """Build the unauth-Redis finding from a benign ``INFO`` reply."""

    kv = parse_redis_info(info)
    ver, role, os_ = kv.get("redis_version", "?"), kv.get("role", "?"), kv.get("os", "?")
    detail = (f"PING→+PONG with no auth; INFO leaked redis_version={ver} role={role} os={os_}. "
              "Writable master enables SSH-key/cron/master-slave MODULE LOAD RCE — hand to Strix.")
    return {"verdict": "confirmed", "severity": "critical",
            "issue": "unauthenticated Redis access", "detail": detail}


async def probe_redis(host: str, port: int, timeout: float) -> dict | None:
    try:
        reader, writer = await _open(host, port, timeout)
    except (OSError, asyncio.TimeoutError):
        return None
    try:
        writer.write(b"PING\r\n")
        await writer.drain()
        resp = (await asyncio.wait_for(reader.read(256), timeout=timeout)).decode("latin-1", "replace")
        if resp.startswith("+PONG"):
            writer.write(b"INFO server\r\n")
            await writer.drain()
            info = (await asyncio.wait_for(reader.read(4096), timeout=timeout)).decode("latin-1", "replace")
            return redis_finding(info)
        low = resp.lower()
        if "noauth" in low or ("-err" in low and "auth" in low) or "operation not permitted" in low:
            return {"verdict": "protected", "severity": "info", "issue": "Redis requires auth",
                    "detail": resp.strip()[:120]}
        return None
    except (OSError, asyncio.TimeoutError):
        return None
    finally:
        _close(writer)


async def probe_memcached(host: str, port: int, timeout: float) -> dict | None:
    try:
        reader, writer = await _open(host, port, timeout)
    except (OSError, asyncio.TimeoutError):
        return None
    try:
        writer.write(b"version\r\n")
        await writer.drain()
        resp = (await asyncio.wait_for(reader.read(256), timeout=timeout)).decode("latin-1", "replace")
        if resp.startswith("VERSION"):
            ver = resp.split(" ", 1)[1].strip() if " " in resp else "?"
            return {"verdict": "exposed", "severity": "medium",
                    "issue": "unauthenticated Memcached",
                    "detail": f"version→{ver}; no auth by design — info leak + amplification pivot. "
                              "Reachable via SSRF dict://host:11211/stats too."}
        return None
    except (OSError, asyncio.TimeoutError):
        return None
    finally:
        _close(writer)


# --- MongoDB OP_MSG (opcode 2013): minimal BSON encoder + reply interpreter ---

def _bson(fields: list[tuple[str, str, object]]) -> bytes:
    """Encode a flat BSON document from ``(type, key, value)`` where type is
    ``"int"`` (int32) or ``"str"`` (utf-8 string) — all ``listDatabases`` needs."""

    body = b""
    for typ, key, val in fields:
        kb = key.encode() + b"\x00"
        if typ == "int":
            body += b"\x10" + kb + struct.pack("<i", val)  # type: ignore[arg-type]
        elif typ == "str":
            vb = str(val).encode() + b"\x00"
            body += b"\x02" + kb + struct.pack("<i", len(vb)) + vb
    return struct.pack("<i", len(body) + 5) + body + b"\x00"


def build_op_msg(command: str, db: str = "admin", request_id: int = 1) -> bytes:
    """A complete OP_MSG carrying ``{command: 1, "$db": db}`` (section kind 0)."""

    doc = _bson([("int", command, 1), ("str", "$db", db)])
    body = struct.pack("<i", 0) + b"\x00" + doc     # flagBits=0, section kind 0
    header = struct.pack("<iiii", 16 + len(body), request_id, 0, 2013)
    return header + body


def interpret_mongo_reply(data: bytes) -> dict | None:
    """Classify a MongoDB OP_MSG reply to ``listDatabases``.

    Returns a finding dict, or None if the bytes aren't a MongoDB OP_MSG.
    """

    if len(data) < 16:
        return None
    if struct.unpack_from("<i", data, 12)[0] != 2013:   # opCode != OP_MSG
        return None
    low = data.decode("latin-1", "replace").lower()
    if "sizeondisk" in low or ("databases" in low and "totalsize" in low):
        return {"verdict": "confirmed", "severity": "critical",
                "issue": "unauthenticated MongoDB",
                "detail": "listDatabases returned a database list with no auth — full read/dump exposure."}
    if any(s in low for s in ("not authorized", "unauthorized", "requires authentication",
                              "authentication failed", "command listdatabases requires")):
        return {"verdict": "protected", "severity": "info", "issue": "MongoDB requires auth",
                "detail": "listDatabases rejected (authentication required)."}
    return {"verdict": "reachable", "severity": "low", "issue": "MongoDB reachable",
            "detail": "MongoDB answered the wire protocol but the auth state is ambiguous — verify manually."}


async def probe_mongodb(host: str, port: int, timeout: float) -> dict | None:
    try:
        reader, writer = await _open(host, port, timeout)
    except (OSError, asyncio.TimeoutError):
        return None
    try:
        writer.write(build_op_msg("listDatabases"))
        await writer.drain()
        # OP_MSG replies are framed by a leading int32 length; read a chunk.
        data = await asyncio.wait_for(reader.read(8192), timeout=timeout)
        return interpret_mongo_reply(data)
    except (OSError, asyncio.TimeoutError):
        return None
    finally:
        _close(writer)


RAW_PROBES = {"redis": probe_redis, "memcached": probe_memcached, "mongodb": probe_mongodb}


# ── HTTP interpreters (pure; the tool supplies status/headers/body) ──────────

def interpret_es(status: int | None, headers: dict[str, str], body: str) -> dict | None:
    low = body.lower()
    if status == 200 and ('"you know, for search"' in low or '"cluster_name"' in low
                          or '"number_of_nodes"' in low or '"lucene_version"' in low):
        return {"verdict": "exposed", "severity": "high",
                "issue": "Elasticsearch/OpenSearch cluster readable unauthenticated",
                "detail": "GET / returned the cluster banner with no auth — read /_cat/indices, "
                          "/_search for data (minimise; dump → Strix)."}
    return None


def interpret_couchdb(status: int | None, headers: dict[str, str], body: str) -> dict | None:
    low = body.lower()
    if status == 200 and '"couchdb"' in low and "welcome" in low:
        return {"verdict": "exposed", "severity": "high",
                "issue": "CouchDB reachable unauthenticated",
                "detail": "GET / returned the CouchDB welcome banner — /_all_dbs enumerates data; "
                          "map the version to CVE-2017-12635 (admin bypass) / CVE-2022-24706."}
    return None


def interpret_influxdb(status: int | None, headers: dict[str, str], body: str) -> dict | None:
    ver = headers.get("x-influxdb-version") or headers.get("X-Influxdb-Version")
    if status in (200, 204) and ver:
        return {"verdict": "exposed", "severity": "medium",
                "issue": "InfluxDB reachable",
                "detail": f"/ping answered with X-Influxdb-Version={ver} — <1.7.6 is vulnerable to the "
                          "empty-secret JWT auth bypass (CVE-2019-20933)."}
    return None


def interpret_yarn(status: int | None, headers: dict[str, str], body: str) -> dict | None:
    low = body.lower()
    if status == 200 and ("resourcemanagerversion" in low or "hadoopversion" in low):
        return {"verdict": "exposed", "severity": "critical",
                "issue": "Hadoop YARN ResourceManager exposed",
                "detail": "GET /ws/v1/cluster/info answered unauthenticated — the app-submit REST API "
                          "is pre-auth RCE (hand the submit to Strix, never in-scan)."}
    return None


def interpret_tidb(status: int | None, headers: dict[str, str], body: str) -> dict | None:
    low = body.lower()
    if status == 200 and '"version"' in low and ("git_hash" in low or "ddl_id" in low):
        return {"verdict": "exposed", "severity": "medium",
                "issue": "TiDB status endpoint exposed",
                "detail": "GET :10080/status leaked the TiDB version unauthenticated — check PD :2379 "
                          "(etcd) for unauth access too."}
    return None


HTTP_INTERPRETERS = {
    "http-es": interpret_es,
    "http-couchdb": interpret_couchdb,
    "http-influxdb": interpret_influxdb,
    "http-yarn": interpret_yarn,
    "http-tidb": interpret_tidb,
}


def ports_to_check(explicit_port: int | None, spec: str | None) -> list[int]:
    """Pick which ports to sweep: an explicit host:port wins; else the DB_PORTS
    set (spec 'db'/empty) or a parsed 'a,b,c-d' list intersected with DB_PORTS."""

    if explicit_port is not None:
        return [explicit_port]
    if not spec or spec.strip().lower() in ("db", "default", "top", "all", ""):
        return sorted(DB_PORTS)
    out: list[int] = []
    for chunk in spec.replace(" ", "").split(","):
        if chunk.isdigit():
            out.append(int(chunk))
        elif "-" in chunk:
            lo, _, hi = chunk.partition("-")
            if lo.isdigit() and hi.isdigit():
                out.extend(range(int(lo), int(hi) + 1))
    return sorted(set(out))
