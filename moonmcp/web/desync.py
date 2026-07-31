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

from ..net import dial


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


def _sig(data: bytes | None) -> tuple[int | None, int] | None:
    """(status, response-byte-length) for a differential compare, or None if no reply."""

    if data is None:
        return None
    return _status_of(data)[0], len(data)


def _sig_differs(a: tuple[int | None, int], b: tuple[int | None, int]) -> bool:
    """Do two response signatures differ materially — a different status, or a length
    delta beyond a small jitter tolerance (a per-request Date/nonce is length-stable,
    but leave headroom)?"""

    return a[0] != b[0] or abs(a[1] - b[1]) > 64


async def _raw_request(host: str, port: int, tls: bool, raw: bytes, timeout: float,
                       connect_pin=None) -> bytes | None:
    ssl_ctx = None
    if tls:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
    try:
        reader, writer = await dial.open_connection(
            host, port, connect_pin=connect_pin, ssl_ctx=ssl_ctx,
            server_hostname=host if tls else None, timeout=timeout)
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


_DEFAULT_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")


def _raw_bytes(host: str, path: str, *, method: str = "GET",
               extra_headers: str = "", body: str = "",
               user_agent: str = _DEFAULT_UA) -> bytes:
    head = (f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n"
            f"User-Agent: {user_agent}\r\n"
            f"Accept: */*\r\nConnection: close\r\n{extra_headers}\r\n{body}")
    return head.encode("latin-1")


def _req(host: str, path: str, extra_headers: str = "", body: str = "",
         user_agent: str = _DEFAULT_UA) -> bytes:
    return _raw_bytes(host, path, method="GET", extra_headers=extra_headers,
                      body=body, user_agent=user_agent)


async def probe_desync(url: str, *, timeout: float = 12.0,
                       user_agent: str = _DEFAULT_UA, connect_pin=None) -> DesyncResult:
    parts = urlsplit(url if "://" in url else f"https://{url}")
    tls = parts.scheme != "http"
    host = parts.hostname or ""
    port = parts.port or (443 if tls else 80)
    path = parts.path or "/"
    result = DesyncResult(url=url)

    base = await _raw_request(host, port, tls, _req(host, path, user_agent=user_agent), timeout, connect_pin)
    if base is None:
        result.error = "unreachable"
        return result
    result.baseline_status, result.server = _status_of(base)

    complete_chunked = "0\r\n\r\n"

    # Canonical chunked CONTROL: a VALID Transfer-Encoding: chunked with the same
    # complete 0-chunk body. Every probe below is judged against THIS (its de-obfuscated
    # form), not against a bare status < 400 — because each probe is itself a complete,
    # well-formed message, so a compliant server answers < 400 regardless of how it
    # treated the framing. Flagging status < 400 alone fired a "review" on essentially
    # every healthy site. A probe only earns an indicator when it is ACCEPTED (< 400)
    # AND its response DIFFERS from canonical chunked — i.e. the server parsed the
    # ambiguous/obfuscated framing into a materially different outcome.
    canon = await _raw_request(host, port, tls, _req(
        host, path, extra_headers="Transfer-Encoding: chunked\r\n",
        body=complete_chunked, user_agent=user_agent), timeout, connect_pin)
    canon_sig = _sig(canon)

    # BOTH Content-Length and Transfer-Encoding on one complete, empty chunked body.
    clte = _req(host, path,
                extra_headers=f"Content-Length: {len(complete_chunked)}\r\nTransfer-Encoding: chunked\r\n",
                body=complete_chunked, user_agent=user_agent)
    r = await _raw_request(host, port, tls, clte, timeout, connect_pin)
    result.probes["cl.te-dual"] = _status_of(r)[0] if r else None
    clte_sig = _sig(r)

    # Obfuscated Transfer-Encoding variants (each a complete message). 'te-nameprefix'
    # was removed: 'X: x\r\nTransfer-Encoding: chunked' is a benign header followed by a
    # PLAIN valid TE — not an obfuscation at all, so it fired on every server.
    variants = {
        "te-space-before-colon": "Transfer-Encoding : chunked\r\n",
        "te-tab": "Transfer-Encoding:\tchunked\r\n",
    }
    var_sigs: dict[str, tuple[int | None, int] | None] = {}
    for name, hdr in variants.items():
        rr = await _raw_request(host, port, tls, _req(host, path, extra_headers=hdr, body=complete_chunked, user_agent=user_agent), timeout, connect_pin)
        result.probes[name] = _status_of(rr)[0] if rr else None
        var_sigs[name] = _sig(rr)

    # Interpretation: a genuine differential vs canonical chunked, never raw status<400.
    base_ok = result.baseline_status is not None and result.baseline_status < 400
    if base_ok and canon_sig is not None and canon_sig[0] is not None and canon_sig[0] < 400:
        dual = result.probes.get("cl.te-dual")
        if dual is not None and dual < 400 and clte_sig is not None and _sig_differs(clte_sig, canon_sig):
            result.indicators.append(
                "A dual Content-Length + Transfer-Encoding request was accepted AND handled "
                "differently from clean chunked (status/length differ) — possible CL.TE/TE.CL "
                "desync; confirm with desync_modern_probe / a dedicated tool")
        diff_obf = [n for n, s in var_sigs.items()
                    if s is not None and s[0] is not None and s[0] < 400 and _sig_differs(s, canon_sig)]
        if diff_obf:
            result.indicators.append(
                f"Obfuscated Transfer-Encoding accepted AND processed differently from canonical "
                f"chunked ({', '.join(diff_obf)}) — possible TE.TE parser disagreement; verify")
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
                         timeout: float, connect_pin=None) -> ProbeTiming:
    """Send *raw* and classify the outcome by timing: a real response, a read
    timeout (the server hung waiting for more body), or a connect error."""

    ssl_ctx = None
    if tls:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
    start = time.monotonic()
    try:
        reader, writer = await dial.open_connection(
            host, port, connect_pin=connect_pin, ssl_ctx=ssl_ctx,
            server_hostname=host if tls else None, timeout=timeout)
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


def _modern_payloads(host: str, path: str, *,
                     user_agent: str = _DEFAULT_UA) -> dict[str, bytes]:
    """The probe set. Control is complete/well-formed; the timing probes are
    deliberately incomplete/ambiguous (safe — own socket, closed immediately)."""

    return {
        # A normal, complete request — the fast-response control.
        "control": _raw_bytes(host, path, user_agent=user_agent),
        # Chunked body with NO terminating 0-chunk: a TE-honouring server hangs
        # waiting for the terminator; a TE-ignoring (TE.0) one answers immediately.
        "te0_incomplete": _raw_bytes(host, path, method="POST",
                                     extra_headers="Transfer-Encoding: chunked\r\n",
                                     body="5\r\nhello", user_agent=user_agent),
        # Content-Length promises 200 bytes but we send 1: a CL-honouring server
        # hangs for the rest; a CL-ignoring (CL.0) one answers immediately.
        "cl_partial": _raw_bytes(host, path, method="POST",
                                 extra_headers="Content-Length: 200\r\n", body="x",
                                 user_agent=user_agent),
        # Expect: 100-continue with a promised body we never send.
        "expect_100": _raw_bytes(host, path, method="POST",
                                 extra_headers="Expect: 100-continue\r\nContent-Length: 30\r\n",
                                 user_agent=user_agent),
        # Malformed Expect twin (CVE-2025-32094 Akamai 0.CL) — compared to the above.
        "expect_malformed": _raw_bytes(host, path, method="POST",
                                       extra_headers="Expect: y 100-continue\r\nContent-Length: 30\r\n",
                                       user_agent=user_agent),
        # Chunk-extension on the terminating chunk (CVE-2025-55315 Kestrel class) —
        # a complete message; compared against a plain chunked-POST baseline below so
        # ONLY the chunk-extension differs (not the request method).
        "chunk_ext": _raw_bytes(host, path, method="POST",
                                extra_headers="Transfer-Encoding: chunked\r\n",
                                body="0;probe=1\r\n\r\n", user_agent=user_agent),
        # The same chunked POST with a plain terminating chunk (no extension).
        "chunk_control": _raw_bytes(host, path, method="POST",
                                    extra_headers="Transfer-Encoding: chunked\r\n",
                                    body="0\r\n\r\n", user_agent=user_agent),
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
    # Compare the chunk-extension POST against a plain chunked POST (same method +
    # framing, only the extension differs) — NOT the GET control, or a mere
    # method-difference (POST-redirect-GET) would masquerade as a parsing divergence.
    cc = probes.get("chunk_control", {})
    cs, xs = cc.get("status"), probes.get("chunk_ext", {}).get("status")
    if accepted("chunk_ext") and cc.get("outcome") == "response" and \
            cs is not None and xs is not None and xs != cs:
        ind.append("A chunk-extension on the terminating chunk changed the response vs a plain "
                   "chunked POST — review chunk-extension parsing (CVE-2025-55315 class)")
    return ind, ("review" if ind else "low")


async def probe_modern_desync(url: str, *, timeout: float = 6.0,
                              user_agent: str = _DEFAULT_UA, connect_pin=None) -> ModernDesyncResult:
    """Run the modern-desync timing probes concurrently and interpret the outcomes."""

    parts = urlsplit(url if "://" in url else f"https://{url}")
    tls = parts.scheme != "http"
    host = parts.hostname or ""
    port = parts.port or (443 if tls else 80)
    path = parts.path or "/"
    result = ModernDesyncResult(url=url)

    per = max(2.0, min(timeout, 6.0))
    payloads = _modern_payloads(host, path, user_agent=user_agent)
    names = list(payloads)
    timings = await asyncio.gather(
        *(_timed_request(host, port, tls, payloads[n], per, connect_pin) for n in names))
    by_name = dict(zip(names, timings, strict=False))

    if by_name["control"].outcome == "connect_error":
        result.error = "unreachable"
        return result
    result.probes = {n: {"status": t.status, "outcome": t.outcome,
                         "elapsed_ms": round(t.elapsed_ms, 1)} for n, t in by_name.items()}
    result.baseline_status = by_name["control"].status
    result.indicators, result.risk = interpret_modern(result.probes)
    return result
