"""Burp-style request primitives — the native interception layer.

Rather than a live TLS-MITM proxy a human points a browser at (awkward for an
agent, and cert generation needs a non-stdlib crypto lib), MoonMCP exposes the
Burp *workflow* as tools an agent actually drives:

* **repeater**   — send one request (raw or structured) to an in-scope target and
  get the full response back, tweak, resend.
* **intruder**   — a request template with a payload marker + a payload list,
  fired (rate-limited) with per-payload status/length/reflection diffing.
* **passive scan** — run MoonMCP's existing header/secret/fingerprint analysers
  over a captured response, all at once.
* **history**    — an in-memory request/response log (like Burp's history), so an
  agent can review or replay what it sent.

Everything rides the scope guard and shared rate limiter; nothing here bypasses
them. The live intercepting proxy and adapters to ZAP/mitmproxy/Caido are a
follow-up on top of this foundation.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .recon import fingerprint as fpmod
from .recon import headers as headersmod
from .recon import secrets as secretsmod


def parse_raw_request(raw: str, default_scheme: str = "https") -> tuple[str, str, dict[str, str], bytes]:
    """Parse a raw HTTP/1.1 request (Burp-style) into ``(method, url, headers, body)``.

    Accepts either an absolute request target (``GET https://h/p HTTP/1.1``) or the
    usual origin-form (``GET /p HTTP/1.1`` + a ``Host:`` header). Raises
    :class:`ValueError` on a malformed request line or a missing host.
    """

    text = raw.replace("\r\n", "\n").lstrip("\n")
    head, _, body = text.partition("\n\n")
    lines = head.split("\n")
    parts = lines[0].split()
    if len(parts) < 2:
        raise ValueError("malformed request line (expected 'METHOD target [HTTP/x]')")
    method, target = parts[0].upper(), parts[1]

    headers: dict[str, str] = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            if k.strip():
                headers[k.strip()] = v.strip()

    host = next((v for k, v in headers.items() if k.lower() == "host"), None)
    if "://" in target:
        url = target
    elif host:
        url = f"{default_scheme}://{host}{target if target.startswith('/') else '/' + target}"
    else:
        raise ValueError("origin-form request needs a Host header")
    # urllib derives Host from the URL; drop any explicit one to avoid a duplicate.
    headers = {k: v for k, v in headers.items() if k.lower() != "host"}
    return method, url, headers, body.encode()


def passive_findings(result) -> dict:  # result: HttpResult
    """Run the passive analysers (headers, fingerprint, secrets) over a response."""

    audit = headersmod.audit_headers(result)
    fp = fpmod.fingerprint(result)
    hits = secretsmod.scan_text(result.text(500_000), source=result.final_url or result.url)
    issues = [
        {"header": f.header, "severity": f.severity, "detail": f.detail}
        for f in (*audit.missing, *audit.info_leaks, *audit.cookie_issues)
    ]
    return {
        "header_grade": audit.grade,
        "header_issues": issues[:30],
        "title": fp.title,
        "technologies": [
            {"name": t.name, "category": t.category, "version": t.version}
            for t in fp.technologies
        ],
        "secret_count": len(hits),
        "secrets": [
            {"type": h.type, "risk": h.fp_risk, "redacted": h.redacted} for h in hits[:30]
        ],
    }


_PREVIEW = 4096


@dataclass
class Exchange:
    """One recorded request/response pair (bodies stored as bounded previews)."""

    id: int
    source: str          # "repeater" | "intruder"
    method: str
    url: str
    host: str
    status: int | None
    req_headers: dict[str, str]
    req_body_preview: str
    resp_headers: dict[str, str]
    resp_body_preview: str
    resp_len: int
    elapsed_ms: float
    label: str = ""


class HistoryStore:
    """A bounded, in-memory request/response history for the session."""

    def __init__(self, cap: int = 500) -> None:
        self._items: list[Exchange] = []
        self._cap = cap
        self._seq = 0

    def add(self, *, source: str, method: str, url: str, host: str, status: int | None,
            req_headers: dict[str, str], req_body: bytes, resp_headers: dict[str, str],
            resp_body: bytes, resp_len: int, elapsed_ms: float, label: str = "") -> Exchange:
        self._seq += 1
        ex = Exchange(
            id=self._seq, source=source, method=method, url=url, host=host, status=status,
            req_headers=dict(req_headers),
            req_body_preview=req_body[:_PREVIEW].decode("utf-8", "replace"),
            resp_headers=dict(resp_headers),
            resp_body_preview=resp_body[:_PREVIEW].decode("utf-8", "replace"),
            resp_len=resp_len, elapsed_ms=elapsed_ms, label=label,
        )
        self._items.append(ex)
        if len(self._items) > self._cap:
            self._items = self._items[-self._cap:]
        return ex

    def list(self, *, limit: int = 50, host: str | None = None) -> list[Exchange]:
        items = [e for e in self._items if host is None or e.host == host]
        return list(reversed(items[-max(1, limit):]))

    def get(self, exchange_id: int) -> Exchange | None:
        return next((e for e in self._items if e.id == exchange_id), None)

    def clear(self) -> int:
        n = len(self._items)
        self._items.clear()
        return n

    @property
    def count(self) -> int:
        return len(self._items)


@dataclass
class IntruderResult:
    payload: str
    status: int | None
    length: int
    elapsed_ms: float
    reflected: bool
    error: str | None = None
    flags: list[str] = field(default_factory=list)
