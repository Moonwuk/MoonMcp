"""A small async HTTP client built on urllib (standard library only).

Design goals:
* No third-party HTTP dependency — recon must work in a bare environment.
* Structured responses (status, headers, timing, redirect chain, TLS peek).
* Manual redirect handling so we can record the full chain and cap it.
* Body reads are capped to avoid memory blow-ups on large responses.
"""

from __future__ import annotations

import asyncio
import ssl
import time
import urllib.error
import urllib.request
import zlib
from collections.abc import Callable
from dataclasses import dataclass, field
from http.client import HTTPResponse

from .ratelimit import Governor

DEFAULT_MAX_BODY = 512 * 1024  # 512 KiB


@dataclass
class HttpResult:
    url: str
    final_url: str
    status: int | None
    reason: str
    # Raw header pairs, preserving order and duplicates (crucial for Set-Cookie).
    headers: list[tuple[str, str]]
    body: bytes
    elapsed_ms: float
    redirect_chain: list[str] = field(default_factory=list)
    error: str | None = None
    truncated: bool = False
    redirect_blocked: str | None = None  # set if a redirect target left the scope

    @property
    def ok(self) -> bool:
        return self.status is not None and 200 <= self.status < 400

    def text(self, limit: int | None = None) -> str:
        data = self.body if limit is None else self.body[:limit]
        return data.decode("utf-8", errors="replace")

    def header(self, name: str, default: str | None = None) -> str | None:
        lname = name.lower()
        for k, v in self.headers:
            if k.lower() == lname:
                return v
        return default

    def get_all(self, name: str) -> list[str]:
        lname = name.lower()
        return [v for k, v in self.headers if k.lower() == lname]

    def headers_map(self) -> dict[str, str]:
        """A last-wins dict view of the headers (for display/JSON)."""
        out: dict[str, str] = {}
        for k, v in self.headers:
            out[k] = v
        return out


def _insecure_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _find_header(pairs: list[tuple[str, str]], name: str) -> str | None:
    lname = name.lower()
    for k, v in pairs:
        if k.lower() == lname:
            return v
    return None


def _inflate(raw: bytes, wbits: int, limit: int) -> bytes:
    """Decompress with a hard cap on *output* size (decompression-bomb guard)."""

    dobj = zlib.decompressobj(wbits)
    return dobj.decompress(raw, limit + 1)


def _decode_body(raw: bytes, encoding: str | None, limit: int) -> tuple[bytes, bool]:
    """Return ``(decoded_body, truncated)`` with the decoded size bounded to
    *limit* so a compressed payload can never inflate past the body cap."""

    enc = (encoding or "").lower()
    if not enc:
        return raw[:limit], len(raw) > limit
    try:
        if enc == "gzip":
            out = _inflate(raw, 16 + zlib.MAX_WBITS, limit)
        elif enc == "deflate":
            try:
                out = _inflate(raw, zlib.MAX_WBITS, limit)
            except zlib.error:
                out = _inflate(raw, -zlib.MAX_WBITS, limit)
        else:
            return raw[:limit], len(raw) > limit
    except (OSError, zlib.error):
        return raw[:limit], len(raw) > limit
    return out[:limit], len(out) > limit


def _blocking_fetch(
    url: str,
    method: str,
    headers: dict[str, str],
    body: bytes | None,
    timeout: float,
    verify_tls: bool,
    max_body: int,
) -> HttpResult:
    started = time.monotonic()
    req = urllib.request.Request(url, data=body, method=method.upper(), headers=headers)
    ctx = ssl.create_default_context() if verify_tls else _insecure_context()
    https_handler = urllib.request.HTTPSHandler(context=ctx)
    opener = urllib.request.build_opener(https_handler, _NoRedirect)
    resp: HTTPResponse | None = None
    try:
        resp = opener.open(req, timeout=timeout)
        status = resp.status
        reason = resp.reason or ""
        resp_headers = list(resp.getheaders())
        raw = resp.read(max_body + 1)
        compressed_capped = len(raw) > max_body
        content, decoded_capped = _decode_body(
            raw, _find_header(resp_headers, "Content-Encoding"), max_body
        )
        truncated = decoded_capped or compressed_capped
        elapsed = (time.monotonic() - started) * 1000
        return HttpResult(
            url=url,
            final_url=resp.geturl(),
            status=status,
            reason=reason,
            headers=resp_headers,
            body=content,
            elapsed_ms=round(elapsed, 1),
            truncated=truncated,
        )
    except urllib.error.HTTPError as exc:
        # HTTPError is a valid response for our purposes (4xx/5xx).
        resp = exc  # ensure the error response socket is closed by `finally`
        resp_headers = list(exc.headers.items()) if exc.headers else []
        try:
            raw = exc.read(max_body + 1)
        except Exception:
            raw = b""
        compressed_capped = len(raw) > max_body
        content, decoded_capped = _decode_body(
            raw, _find_header(resp_headers, "Content-Encoding"), max_body
        )
        truncated = decoded_capped or compressed_capped
        elapsed = (time.monotonic() - started) * 1000
        return HttpResult(
            url=url,
            final_url=exc.geturl() or url,
            status=exc.code,
            reason=exc.reason or "",
            headers=resp_headers,
            body=content,
            elapsed_ms=round(elapsed, 1),
            truncated=truncated,
        )
    except (urllib.error.URLError, ssl.SSLError, TimeoutError, OSError) as exc:
        elapsed = (time.monotonic() - started) * 1000
        reason = getattr(exc, "reason", None)
        return HttpResult(
            url=url,
            final_url=url,
            status=None,
            reason="",
            headers=[],
            body=b"",
            elapsed_ms=round(elapsed, 1),
            error=str(reason) if reason is not None else str(exc),
        )
    finally:
        if resp is not None:
            resp.close()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Disable urllib's automatic redirects so we can record them ourselves."""

    def redirect_request(self, *args, **kwargs):  # noqa: D401,ANN001,ANN002
        return None


class HttpClient:
    """Async HTTP client with shared rate limiting and manual redirect tracing."""

    def __init__(
        self,
        governor: Governor,
        *,
        user_agent: str,
        default_timeout: float = 10.0,
        max_body: int = DEFAULT_MAX_BODY,
    ) -> None:
        self._gov = governor
        self._ua = user_agent
        self._timeout = default_timeout
        self._max_body = max_body

    async def fetch(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
        timeout: float | None = None,
        verify_tls: bool = True,
        follow_redirects: bool = False,
        max_redirects: int = 5,
        max_body: int | None = None,
        scope_check: Callable[[str], bool] | None = None,
    ) -> HttpResult:
        merged = {"User-Agent": self._ua, "Accept-Encoding": "gzip, deflate", "Accept": "*/*"}
        if headers:
            merged.update(headers)
        chain: list[str] = []
        current = url
        seen: set[str] = set()
        result: HttpResult | None = None
        hops = max_redirects if follow_redirects else 0
        for _ in range(hops + 1):
            async with self._gov:
                result = await asyncio.to_thread(
                    _blocking_fetch,
                    current,
                    method,
                    merged,
                    body,
                    timeout or self._timeout,
                    verify_tls,
                    max_body or self._max_body,
                )
            if not follow_redirects or result.status is None or not (300 <= result.status < 400):
                break
            location = result.header("Location")
            if not location:
                break
            nxt = urllib.request.urljoin(current, location)
            if nxt in seen:
                break
            # Never follow a redirect that leaves the authorised scope.
            if scope_check is not None and not scope_check(nxt):
                result.redirect_blocked = nxt
                break
            seen.add(nxt)
            chain.append(nxt)
            current = nxt
            # A redirect after a POST should typically become a GET.
            if method.upper() not in {"GET", "HEAD"} and result.status in (301, 302, 303):
                method = "GET"
                body = None
        assert result is not None
        result.redirect_chain = chain
        result.url = url
        return result
