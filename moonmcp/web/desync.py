"""HTTP request-smuggling / desync **indicator** probe (detection only).

This does NOT attempt a smuggling attack.  Every request it sends is a single,
**complete, well-formed** HTTP/1.1 message on its own fresh connection, so no
partial request is ever left to poison a shared connection.  It simply observes
how the server handles ambiguous framing (both ``Content-Length`` and
``Transfer-Encoding``, and obfuscated ``Transfer-Encoding`` headers) and reports
that as a risk *indicator* — always confirm with a dedicated tool under explicit
authorisation before reporting a finding.

Intrusive: the server gates it behind ``MOONMCP_ALLOW_INTRUSIVE`` + scope.
"""

from __future__ import annotations

import asyncio
import ssl
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit


@dataclass
class DesyncResult:
    url: str
    baseline_status: int | None = None
    server: str | None = None
    probes: dict[str, int | None] = field(default_factory=dict)
    indicators: list[str] = field(default_factory=list)
    risk: str = "low"
    note: str = ("Indicators only — NOT a confirmed vulnerability. Verify manually "
                 "with a dedicated request-smuggling tool under authorisation.")
    error: str | None = None


def _status_of(data: bytes) -> tuple[int | None, str | None]:
    try:
        line, _, rest = data.partition(b"\r\n")
        parts = line.split(b" ", 2)
        status = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else None
        server = None
        for hl in rest.split(b"\r\n"):
            if hl.lower().startswith(b"server:"):
                server = hl.split(b":", 1)[1].strip().decode("latin-1", "replace")
                break
        return status, server
    except (ValueError, IndexError):
        return None, None


async def _raw_request(host: str, port: int, tls: bool, raw: bytes, timeout: float) -> bytes | None:
    ssl_ctx = None
    if tls:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
    try:
        fut = asyncio.open_connection(host, port, ssl=ssl_ctx, server_hostname=host if tls else None)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
    except (asyncio.TimeoutError, ssl.SSLError, OSError):
        return None
    try:
        writer.write(raw)
        await writer.drain()
        return await asyncio.wait_for(reader.read(4096), timeout=timeout)
    except (asyncio.TimeoutError, OSError):
        return None
    finally:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
        except (asyncio.TimeoutError, OSError):
            pass


def _raw_bytes(host: str, path: str, *, method: str = "GET",
               extra_headers: str = "", body: str = "") -> bytes:
    head = (f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: MoonMCP\r\n"
            f"Accept: */*\r\nConnection: close\r\n{extra_headers}\r\n{body}")
    return head.encode("latin-1")


def _req(host: str, path: str, extra_headers: str = "", body: str = "") -> bytes:
    return _raw_bytes(host, path, method="GET", extra_headers=extra_headers, body=body)


async def probe_desync(url: str, *, timeout: float = 12.0) -> DesyncResult:
    parts = urlsplit(url if "://" in url else f"https://{url}")
    tls = parts.scheme != "http"
    host = parts.hostname or ""
    port = parts.port or (443 if tls else 80)
    path = parts.path or "/"
    result = DesyncResult(url=url)

    base = await _raw_request(host, port, tls, _req(host, path), timeout)
    if base is None:
        result.error = "unreachable"
        return result
    result.baseline_status, result.server = _status_of(base)

    # A complete, empty chunked body advertised with BOTH CL and TE. Both parsers
    # read exactly this message, so nothing is left dangling.
    complete_chunked = "0\r\n\r\n"
    clte = _req(host, path,
                extra_headers=f"Content-Length: {len(complete_chunked)}\r\nTransfer-Encoding: chunked\r\n",
                body=complete_chunked)
    r = await _raw_request(host, port, tls, clte, timeout)
    result.probes["cl.te-dual"] = _status_of(r)[0] if r else None

    # Obfuscated Transfer-Encoding variants (each a complete message).
    variants = {
        "te-space-before-colon": "Transfer-Encoding : chunked\r\n",
        "te-tab": "Transfer-Encoding:\tchunked\r\n",
        "te-nameprefix": "X: x\r\nTransfer-Encoding: chunked\r\n",
    }
    for name, hdr in variants.items():
        rr = await _raw_request(host, port, tls, _req(host, path, extra_headers=hdr, body=complete_chunked), timeout)
        result.probes[name] = _status_of(rr)[0] if rr else None

    # Interpretation (indicators only).
    base_ok = result.baseline_status is not None and result.baseline_status < 400
    dual = result.probes.get("cl.te-dual")
    if dual is not None and dual < 400 and base_ok:
        result.indicators.append("Server accepted a request with both Content-Length and "
                                 "Transfer-Encoding (RFC says reject) — review for CL.TE/TE.CL desync")
    accepted_obf = [n for n in variants if (result.probes.get(n) is not None and result.probes[n] < 400)]
    if accepted_obf:
        result.indicators.append(f"Obfuscated Transfer-Encoding accepted: {', '.join(accepted_obf)}")
    result.risk = "review" if result.indicators else "low"
    return result


# ── Modern desync (2025 "HTTP/1.1 Must Die" class): 0.CL / TE.0 / Expect / chunk-ext ──
#
# These use the **timeout-differential technique** — the safest way to detect a
# framing disagreement. Each probe is sent on its OWN fresh ``Connection: close``
# socket that is closed immediately; because no *second* (victim) request ever shares
# the connection, nothing is smuggled — the only observable effect is our own socket
# either getting a response or timing out. From *whether the server waits for the
# body it was told to expect* we infer which length header it honours.

@dataclass
class ProbeTiming:
    status: int | None
    outcome: str          # "response" | "read_timeout" | "connect_error"
    elapsed_ms: float


@dataclass
class ModernDesyncResult:
    url: str
    baseline_status: int | None = None
    probes: dict[str, dict] = field(default_factory=dict)
    indicators: list[str] = field(default_factory=list)
    risk: str = "low"
    note: str = ("Timing indicators only — NOT a confirmed vulnerability. Each probe ran on its "
                 "own closed socket (no smuggling). Confirm with a dedicated tool under authorisation.")
    error: str | None = None


async def _timed_request(host: str, port: int, tls: bool, raw: bytes,
                         timeout: float) -> ProbeTiming:
    """Send *raw* and classify the outcome by timing: a real response, a read
    timeout (the server hung waiting for more body), or a connect error."""

    ssl_ctx = None
    if tls:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
    start = time.monotonic()
    try:
        fut = asyncio.open_connection(host, port, ssl=ssl_ctx,
                                      server_hostname=host if tls else None)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
    except (asyncio.TimeoutError, ssl.SSLError, OSError):
        return ProbeTiming(None, "connect_error", (time.monotonic() - start) * 1000)
    try:
        writer.write(raw)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(4096), timeout=timeout)
        return ProbeTiming(_status_of(data)[0], "response", (time.monotonic() - start) * 1000)
    except asyncio.TimeoutError:
        return ProbeTiming(None, "read_timeout", (time.monotonic() - start) * 1000)
    except OSError:
        return ProbeTiming(None, "connect_error", (time.monotonic() - start) * 1000)
    finally:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
        except (asyncio.TimeoutError, OSError):
            pass


def _modern_payloads(host: str, path: str) -> dict[str, bytes]:
    """The probe set. Control is complete/well-formed; the timing probes are
    deliberately incomplete/ambiguous (safe — own socket, closed immediately)."""

    return {
        # A normal, complete request — the fast-response control.
        "control": _raw_bytes(host, path),
        # Chunked body with NO terminating 0-chunk: a TE-honouring server hangs
        # waiting for the terminator; a TE-ignoring (TE.0) one answers immediately.
        "te0_incomplete": _raw_bytes(host, path, method="POST",
                                     extra_headers="Transfer-Encoding: chunked\r\n",
                                     body="5\r\nhello"),
        # Content-Length promises 200 bytes but we send 1: a CL-honouring server
        # hangs for the rest; a CL-ignoring (CL.0) one answers immediately.
        "cl_partial": _raw_bytes(host, path, method="POST",
                                 extra_headers="Content-Length: 200\r\n", body="x"),
        # Expect: 100-continue with a promised body we never send.
        "expect_100": _raw_bytes(host, path, method="POST",
                                 extra_headers="Expect: 100-continue\r\nContent-Length: 30\r\n"),
        # Malformed Expect twin (CVE-2025-32094 Akamai 0.CL) — compared to the above.
        "expect_malformed": _raw_bytes(host, path, method="POST",
                                       extra_headers="Expect: y 100-continue\r\nContent-Length: 30\r\n"),
        # Chunk-extension on the terminating chunk (CVE-2025-55315 Kestrel class) —
        # a complete message; compared against the control's status.
        "chunk_ext": _raw_bytes(host, path, method="POST",
                                extra_headers="Transfer-Encoding: chunked\r\n",
                                body="0;moonmcp=1\r\n\r\n"),
    }


def interpret_modern(probes: dict[str, dict]) -> tuple[list[str], str]:
    """Derive indicators from the probe outcomes (pure — timing/status in, verdict out).

    A probe only signals when the server *accepted* the ambiguous framing with a
    non-error status; a fast 4xx is a rejection (no signal) and a read timeout is the
    server correctly honouring the length it was given (no signal)."""

    control = probes.get("control", {})
    if control.get("outcome") != "response":
        return [], "low"  # no usable baseline

    def accepted(name: str) -> bool:
        p = probes.get(name, {})
        s = p.get("status")
        return p.get("outcome") == "response" and s is not None and s < 400

    ind: list[str] = []
    if accepted("te0_incomplete"):
        ind.append("Server accepted a chunked request with no terminating 0-chunk — it ignored "
                   "Transfer-Encoding (TE.0 candidate); a TE-honouring peer in front would desync")
    if accepted("cl_partial"):
        ind.append("Server answered without waiting for the declared Content-Length body — it "
                   "ignored Content-Length (CL.0 candidate); a CL-honouring peer in front would desync")
    e1, e2 = probes.get("expect_100", {}), probes.get("expect_malformed", {})
    if (e1.get("outcome") == "response" or e2.get("outcome") == "response") and \
            (e1.get("status"), e1.get("outcome")) != (e2.get("status"), e2.get("outcome")):
        ind.append("Expect: 100-continue handling diverges on a malformed twin "
                   "(`Expect: y 100-continue`) — 0.CL candidate (CVE-2025-32094 class)")
    cs, xs = control.get("status"), probes.get("chunk_ext", {}).get("status")
    if accepted("chunk_ext") and cs is not None and xs is not None and xs != cs:
        ind.append("A chunk-extension on the terminating chunk changed the response vs the control "
                   "— review chunk-extension parsing (CVE-2025-55315 class)")
    return ind, ("review" if ind else "low")


async def probe_modern_desync(url: str, *, timeout: float = 6.0) -> ModernDesyncResult:
    """Run the modern-desync timing probes concurrently and interpret the outcomes."""

    parts = urlsplit(url if "://" in url else f"https://{url}")
    tls = parts.scheme != "http"
    host = parts.hostname or ""
    port = parts.port or (443 if tls else 80)
    path = parts.path or "/"
    result = ModernDesyncResult(url=url)

    per = max(2.0, min(timeout, 6.0))
    payloads = _modern_payloads(host, path)
    names = list(payloads)
    timings = await asyncio.gather(
        *(_timed_request(host, port, tls, payloads[n], per) for n in names))
    by_name = dict(zip(names, timings, strict=False))

    if by_name["control"].outcome == "connect_error":
        result.error = "unreachable"
        return result
    result.probes = {n: {"status": t.status, "outcome": t.outcome,
                         "elapsed_ms": round(t.elapsed_ms, 1)} for n, t in by_name.items()}
    result.baseline_status = by_name["control"].status
    result.indicators, result.risk = interpret_modern(result.probes)
    return result
