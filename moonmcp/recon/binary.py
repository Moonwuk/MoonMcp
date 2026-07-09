"""Binary / compiled-artifact triage — a headless, stdlib-first answer to the
"I found a .dll/.exe/.jar, what's in it?" moment in recon.

Inspired by reverse-engineering tools like dnSpyEx (a GUI .NET debugger/decompiler
with no automatable interface), this brings the *useful* part to MCP:

* download an in-scope binary (size-capped),
* identify its type from magic bytes (PE/.NET, ELF, Mach-O, ZIP/JAR/APK, Java
  class, WASM),
* extract printable strings (ASCII **and** UTF-16LE — crucial for Windows/.NET),
* scan those strings for secrets (reusing MoonMCP's secret patterns) and for
  URLs / endpoints / hosts,
* and, when a real decompiler (``ilspycmd``) is installed, optionally decompile
  a .NET assembly — otherwise report that it is available to install.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field

from ..net.http import HttpClient
from .secrets import scan_text

_ASCII_RE = re.compile(rb"[\x20-\x7e]{5,}")
_UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){5,}")
_URL_RE = re.compile(r"https?://[a-zA-Z0-9.\-]+(?:/[^\s\"'<>]*)?")
_HOST_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.IGNORECASE)
_CONNSTR_RE = re.compile(
    r"(?i)(?:server|data source|host|initial catalog|database|uid|pwd|password|user id|"
    r"account(?:name|key)|endpoint)=[^;\"'\s]{1,80}(?:;[^;\"'\s]{1,80}){1,}")

_MAX_BYTES = 12 * 1024 * 1024  # 12 MiB download cap


@dataclass
class BinaryAnalysis:
    url: str
    filetype: str = "unknown"
    is_dotnet: bool = False
    size_bytes: int = 0
    truncated: bool = False
    string_count: int = 0
    secrets: list[dict] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    connection_strings: list[str] = field(default_factory=list)
    interesting_strings: list[str] = field(default_factory=list)
    decompiler_available: str | None = None
    decompiler_hint: str | None = None
    decompiled_preview: str | None = None
    error: str | None = None


_INTERESTING_TOKENS = (
    "password", "secret", "apikey", "api_key", "token", "connectionstring",
    "bearer", "authorization", "private", "BEGIN ", "internal", ".local",
    "s3.amazonaws", "blob.core", "azurewebsites", "jdbc:", "mongodb://",
    "amqp://", "redis://", "/api/", "/v1/", "/v2/", "swagger", "graphql",
)


def detect_filetype(data: bytes) -> tuple[str, bool]:
    """Return ``(filetype, is_dotnet)`` from leading magic bytes + content."""

    is_dotnet = b"BSJB" in data[:4096] or b"BSJB" in data  # CLI metadata signature
    if data[:2] == b"MZ":
        # .NET assemblies are PE files; distinguish by the CLI metadata header.
        return ("PE (.NET assembly)" if is_dotnet else "PE executable (native)"), is_dotnet
    if data[:4] == b"\x7fELF":
        return "ELF executable", False
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        return "Mach-O executable", False
    if data[:4] == b"\xca\xfe\xba\xbe":
        # Ambiguous: Java class OR Mach-O fat binary. Java class if version looks sane.
        return "Java class / Mach-O fat binary", False
    if data[:4] == b"PK\x03\x04":
        return "ZIP archive (JAR/APK/DOCX/…)", is_dotnet
    if data[:4] == b"\x00asm":
        return "WebAssembly module", False
    if data[:4] == b"dex\n":
        return "Android DEX", False
    return ("data (.NET metadata present)" if is_dotnet else "unknown/data"), is_dotnet


def _extract_strings(data: bytes, cap: int = 20000) -> list[str]:
    out: list[str] = []
    for m in _ASCII_RE.finditer(data):
        out.append(m.group().decode("latin-1"))
        if len(out) >= cap:
            break
    for m in _UTF16_RE.finditer(data):
        out.append(m.group().decode("utf-16-le", errors="replace"))
        if len(out) >= cap:
            break
    return out


def analyze_bytes(data: bytes, url: str = "") -> BinaryAnalysis:
    """Pure analysis of already-downloaded bytes (no network) — easily testable."""

    result = BinaryAnalysis(url=url, size_bytes=len(data))
    result.filetype, result.is_dotnet = detect_filetype(data)

    strings = _extract_strings(data)
    result.string_count = len(strings)
    blob = "\n".join(strings)

    result.secrets = [
        {"type": h.type, "fp_risk": h.fp_risk, "redacted": h.redacted, "context": h.context}
        for h in scan_text(blob, source=url)
    ]
    result.urls = sorted(set(_URL_RE.findall(blob)))[:200]
    hosts = {h.lower() for h in _HOST_RE.findall(blob)
             if "." in h and not h.lower().endswith((".dll", ".exe", ".png", ".jpg", ".gif", ".cs", ".xml"))}
    result.hosts = sorted(hosts)[:200]
    result.connection_strings = sorted(set(_CONNSTR_RE.findall(blob)))[:50]

    interesting = [s for s in strings if any(tok.lower() in s.lower() for tok in _INTERESTING_TOKENS)]
    # De-dup while keeping order, cap length.
    seen: set[str] = set()
    for s in interesting:
        key = s.strip()[:200]
        if key and key not in seen:
            seen.add(key)
        if len(seen) >= 150:
            break
    result.interesting_strings = list(seen)
    return result


async def analyze_binary(
    client: HttpClient,
    url: str,
    *,
    scope_check: Callable[[str], bool] | None = None,
    max_bytes: int = _MAX_BYTES,
) -> BinaryAnalysis:
    r = await client.fetch(url, follow_redirects=True, timeout=30.0, max_body=max_bytes,
                           scope_check=scope_check)
    if r.status is None:
        return BinaryAnalysis(url=url, error=r.error or "unreachable")
    if not r.body:
        return BinaryAnalysis(url=url, error=f"empty body (HTTP {r.status})")
    analysis = analyze_bytes(r.body, url=r.final_url or url)
    analysis.truncated = r.truncated
    return analysis
