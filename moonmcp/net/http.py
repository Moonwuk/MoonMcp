"""A small async HTTP client built on urllib (standard library only).

Design goals:
* No third-party HTTP dependency — recon must work in a bare environment.
* Structured responses (status, headers, timing, redirect chain, TLS peek).
* Manual redirect handling so we can record the full chain and cap it.
* Body reads are capped to avoid memory blow-ups on large responses.
"""

from __future__ import annotations

import asyncio
import http.client
import ssl
import time
import urllib.error
import urllib.request
import zlib
from collections.abc import Callable
from dataclasses import dataclass, field
from http.client import HTTPResponse
from urllib.parse import urlsplit

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
    blocked_reason: str | None = None  # set if the SSRF connect-guard refused the host

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
    pinned_ip: str | None = None,
) -> HttpResult:
    started = time.monotonic()
    req = urllib.request.Request(url, data=body, method=method.upper(), headers=headers)
    ctx = ssl.create_default_context() if verify_tls else _insecure_context()
    opener = _build_opener(ctx, pinned_ip=pinned_ip)
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
    except (urllib.error.URLError, ssl.SSLError, TimeoutError, OSError, ValueError) as exc:
        # ValueError: http.client raises it for an illegal header value (embedded
        # CR/LF) during opener.open — catch it here so a bad caller header yields a
        # clean HttpResult(error=...) instead of crashing fetch().
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


def _pinned_handlers(
    pinned_ip: str, ctx: ssl.SSLContext
) -> tuple[urllib.request.BaseHandler, urllib.request.BaseHandler]:
    """HTTP(S) handlers that connect the socket to *pinned_ip* while keeping the
    URL's hostname for the ``Host`` header and TLS SNI / certificate verification.

    Pinning the pre-validated IP closes the DNS-rebinding TOCTOU: the address the
    SSRF guard checked is exactly the address we connect to, so a short-TTL attacker
    can't rebind to loopback/metadata between the check and the connection."""

    class _PinnedHTTPConnection(http.client.HTTPConnection):
        def connect(self) -> None:
            self.sock = self._create_connection(
                (pinned_ip, self.port), self.timeout, self.source_address)
            if self._tunnel_host:
                self._tunnel()

    class _PinnedHTTPSConnection(http.client.HTTPSConnection):
        def connect(self) -> None:
            sock = self._create_connection(
                (pinned_ip, self.port), self.timeout, self.source_address)
            # Verify the cert against the real hostname (self.host), not the pinned IP.
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)

    class _PinnedHTTPHandler(urllib.request.HTTPHandler):
        def http_open(self, req):  # noqa: ANN001
            return self.do_open(_PinnedHTTPConnection, req)

    class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
        def https_open(self, req):  # noqa: ANN001
            return self.do_open(_PinnedHTTPSConnection, req,
                                context=self._context, check_hostname=self._check_hostname)

    return _PinnedHTTPHandler(), _PinnedHTTPSHandler(context=ctx)


def _build_opener(ctx: ssl.SSLContext, *, pinned_ip: str | None = None) -> urllib.request.OpenerDirector:
    """An opener with ONLY http(s) handlers — never urllib's default FileHandler /
    FTPHandler / DataHandler, so a redirect (or crafted URL) to ``file://`` /
    ``ftp://`` / ``data:`` cannot smuggle a local-file read or a non-HTTP fetch past
    the SSRF guard. Unknown schemes hit UnknownHandler → a clean URLError, not a crash.

    When *pinned_ip* is set, the http(s) handlers connect to that exact address
    (DNS-rebinding guard); otherwise the standard handlers are used."""

    if pinned_ip:
        http_h, https_h = _pinned_handlers(pinned_ip, ctx)
    else:
        http_h = urllib.request.HTTPHandler()
        https_h = urllib.request.HTTPSHandler(context=ctx)
    opener = urllib.request.OpenerDirector()
    for h in (
        urllib.request.ProxyHandler(),
        urllib.request.UnknownHandler(),
        http_h,
        https_h,
        urllib.request.HTTPDefaultErrorHandler(),
        _NoRedirect(),
        urllib.request.HTTPErrorProcessor(),
    ):
        opener.add_handler(h)
    return opener


def _origin(u: str) -> tuple[str, str, int | None]:
    sp = urlsplit(u)
    return (sp.scheme.lower(), (sp.hostname or "").lower(), sp.port)


def _will_use_proxy(scheme: str, host: str) -> bool:
    """True if urllib would route a *scheme*://*host* request through a proxy — in
    which case the socket connects to the proxy, not the target, so IP-pinning must
    be skipped (the proxy becomes the egress-control point)."""

    try:
        if scheme not in urllib.request.getproxies():
            return False
        return not urllib.request.proxy_bypass(host)
    except (KeyError, ValueError, OSError):
        return False


# Headers that must never be replayed to a different origin across a redirect.
_SENSITIVE_HEADERS = frozenset({"authorization", "cookie", "proxy-authorization"})


class HttpClient:
    """Async HTTP client with shared rate limiting and manual redirect tracing."""

    def __init__(
        self,
        governor: Governor,
        *,
        user_agent: str,
        default_timeout: float = 10.0,
        max_body: int = DEFAULT_MAX_BODY,
        connect_resolver: Callable[[str], tuple[str | None, str | None]] | None = None,
        auth_provider: Callable[[], dict[str, str]] | None = None,
    ) -> None:
        self._gov = governor
        self._ua = user_agent
        self._timeout = default_timeout
        self._max_body = max_body
        # connect_resolver(host) -> (pinned_ip, reason). Applied to every hop (initial
        # + each redirect): `reason` blocks a private/internal IP; `pinned_ip` is the
        # pre-validated address we connect to, closing the DNS-rebinding TOCTOU.
        self._connect_resolver = connect_resolver
        # auth_provider() -> engagement headers merged into every request unless
        # suppress_auth is set (e.g. the anonymous leg of an access-control diff).
        self._auth_provider = auth_provider

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
        suppress_auth: bool = False,
    ) -> HttpResult:
        merged = {"User-Agent": self._ua, "Accept-Encoding": "gzip, deflate", "Accept": "*/*"}
        auth_keys: set[str] = set()
        if self._auth_provider is not None and not suppress_auth:
            ap = self._auth_provider()
            auth_keys = set(ap)
            merged.update(ap)
        if headers:
            merged.update(headers)  # per-call headers win over engagement auth
        origin0 = _origin(url)
        chain: list[str] = []
        current = url
        seen: set[str] = set()
        result: HttpResult | None = None
        hops = max_redirects if follow_redirects else 0
        for _ in range(hops + 1):
            # Only ever speak HTTP(S). A redirect (or the caller) that hands us a
            # file:// / ftp:// / data: / gopher: URL is refused, not fetched.
            scheme = urlsplit(current).scheme.lower()
            if scheme not in ("http", "https"):
                reason = f"refusing non-HTTP(S) scheme {scheme or '(none)'!r}"
                if result is None:
                    return HttpResult(url=url, final_url=current, status=None, reason="",
                                      headers=[], body=b"", elapsed_ms=0.0,
                                      error=reason, blocked_reason=reason)
                result.redirect_blocked = current
                result.blocked_reason = reason
                break
            # SSRF connect-guard: resolve this hop's host ONCE, block a private/
            # reserved address, and pin the validated IP for the connection. The
            # resolve does a blocking getaddrinfo, so keep it off the event loop.
            pinned_ip: str | None = None
            if self._connect_resolver is not None:
                host = urlsplit(current).hostname or current
                pinned_ip, reason = await asyncio.to_thread(self._connect_resolver, host)
                if reason is not None:
                    if result is None:  # the very first hop is blocked
                        return HttpResult(
                            url=url, final_url=current, status=None, reason="",
                            headers=[], body=b"", elapsed_ms=0.0,
                            error=reason, blocked_reason=reason,
                        )
                    result.redirect_blocked = current
                    result.blocked_reason = reason
                    break
                # Only pin on a DIRECT connection. If a proxy will carry this request,
                # the socket goes to the proxy (not the target), so pinning the target
                # IP would be wrong — the proxy is then the egress-control point.
                if pinned_ip and _will_use_proxy(scheme, host):
                    pinned_ip = None
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
                    pinned_ip,
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
            # Drop credentials before crossing to a different origin — never replay
            # Authorization/Cookie (or engagement-auth headers) to another host.
            if _origin(nxt) != origin0:
                for k in list(merged):
                    if k.lower() in _SENSITIVE_HEADERS or k in auth_keys:
                        merged.pop(k, None)
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
