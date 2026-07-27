"""SSRF → internal datastore reach — protocol-smuggling + internal-port detection.

``ssrf_metadata_probe`` turns a *full-read* SSRF into cloud-credential theft; the gap is
**protocol-level** reach into internal DBs. When an SSRF sink accepts non-HTTP schemes,
``gopher://`` sends raw bytes to a TCP port (enough to drive Redis/memcached/MySQL), and
the sink can also reach loopback/internal DB ports. Detection-only — this proves
*capability* (scheme deref, internal-port reachability); weaponization (the actual
``SET``/``CONFIG`` bytes) is handed to Strix.

Two safe lanes:

1. **scheme-deref OAST canary** — inject ``gopher://``/``dict://``/``ftp://`` (+ an
   ``http://`` positive control) pointing at a per-scheme OAST canary; a callback proves
   the sink dereferences that scheme. NOTE: gopher/dict/ftp callbacks fire on a DNS/TCP
   OAST (interactsh via ``oast_configure``); the built-in HTTP self-host catcher only
   sees the ``http`` control.
2. **internal-port reachability** — inject ``http://127.0.0.1:<db_port>/`` and diff the
   sink's response against a closed-port control; a differential = the sink reaches
   internal services (SSRF into the internal network). No payload bytes are delivered.

Pure payload/analyser helpers here; the ``ssrf_protocol_probe`` tool drives it.
Sources: https://github.com/tarunkant/Gopherus ·
https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf .
See docs/DATABASE_RESEARCH.md F.1.
"""

from __future__ import annotations

INTERNAL_HOST = "127.0.0.1"
# A port that should be closed everywhere — the reachability differential's control.
CLOSED_CONTROL_PORT = 9

# Internal datastore ports worth probing for reachability behind an SSRF.
DB_PORTS = [6379, 3306, 5432, 27017, 9200, 11211, 5984, 8123, 9000, 9092]

SCHEMES = ("gopher", "dict", "ftp", "http")


def scheme_payload(scheme: str, canary_host: str | None, http_url: str) -> str:
    """The SSRF-param value for one scheme, pointed at the OAST canary."""

    host = canary_host or http_url
    if scheme == "http":
        return http_url
    if scheme == "gopher":
        return f"gopher://{host}/_ssrf"
    if scheme == "dict":
        return f"dict://{host}/INFO"
    if scheme == "ftp":
        return f"ftp://{host}/ssrf"
    return http_url


def parse_ports(spec: str | None) -> list[int]:
    """``'db'``/empty → the internal DB port set; else a ``'6379,3306'`` list."""

    if not spec or spec.strip().lower() in ("db", "default", "all", ""):
        return list(DB_PORTS)
    out: list[int] = []
    for chunk in spec.replace(" ", "").split(","):
        if chunk.isdigit():
            out.append(int(chunk))
    return out or list(DB_PORTS)


def internal_port_targets(ports: list[int]) -> list[tuple[str, str]]:
    """``(label, url)`` loopback targets for each port."""

    return [(f"{INTERNAL_HOST}:{p}", f"http://{INTERNAL_HOST}:{p}/") for p in ports]


def closed_control_url() -> str:
    return f"http://{INTERNAL_HOST}:{CLOSED_CONTROL_PORT}/"


def assess_reachability(control: tuple, tested: tuple) -> bool:
    """An internal port is reachable when the sink's response for it differs from the
    closed-port control (different status or materially different length)."""

    cs, cl = control
    ts, tl = tested
    return ts != cs or abs((tl or 0) - (cl or 0)) > 16
