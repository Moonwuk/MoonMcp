"""A small async HTTP client built on urllib (standard library only), with an
opt-in curl_cffi transport for browser-TLS impersonation.

Design goals:
* No third-party HTTP dependency by default — recon works in a bare environment.
* Structured responses (status, headers, timing, redirect chain, TLS peek).
* Manual redirect handling so we can record the full chain and cap it.
* Body reads are capped to avoid memory blow-ups on large responses.
* Opt-in browser impersonation: set ``MOONMCP_IMPERSONATE=chrome`` (or firefox,
  safari) to route every request through curl_cffi, which forges a real
  Chrome/Firefox TLS (JA3/JA4) + HTTP/2 + header-order fingerprint. Without
  that env var, or if curl_cffi is not installed, the urllib transport runs
  unchanged (audit 2026-07-27, debt #1).
"""

from __future__ import annotations

import asyncio
import os
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

# Opt-in browser-TLS impersonation. When set to a curl_cffi profile name
# ("chrome", "chrome131", "firefox", "safari", ...) and curl_cffi is importable,
# the request transport forges that browser's TLS/HTTP2/header-order fingerprint
# instead of urllib's Python-unique one. WAFs that gate on JA3/JA4 (QRATOR,
# Cloudflare, Akamai, DataDome) then see a real browser and stop blocking recon.
_IMPERSONATE_PROFILE = os.environ.get("MOONMCP_IMPERSONATE", "").strip() or None
try:  # optional dependency
    from curl_cffi import requests as _cf_requests  # type: ignore

    _HAVE_CURL_CFFI = True
except Exception:  # pragma: no cover - import guard
    _HAVE_CURL_CFFI = False
# Whether the curl_cffi transport is actually active (env var + lib present).
_USE_CURL_CFFI = bool(_IMPERSONATE_PROFILE) and _HAVE_CURL_CFFI


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


def _trusted_context() -> ssl.SSLContext:
    """Default context, extended with a custom CA bundle if present."""
    ctx = ssl.create_default_context()
    import os as _os
    for p in (
        _os.environ.get("MOONMCP_CA_BUNDLE", ""),
        _os.path.expanduser("~/.hermes/ssl/ca-bundle.crt"),
    ):
        if p and _os.path.isfile(p):
            try:
                ctx.load_verify_locations(cafile=p)
            except Exception:
                pass
    return ctx


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
    ctx = _trusted_context() if verify_tls else _insecure_context()
    opener = _build_opener(ctx)
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


def _curl_cffi_fetch(
    url: str,
    method: str,
    headers: dict[str, str],
    body: bytes | None,
    timeout: float,
    verify_tls: bool,
    max_body: int,
    profile: str,
) -> HttpResult:
    """Browser-impersonating transport via curl_cffi.

    Forges the full Chrome/Firefox fingerprint: TLS ClientHello (JA3/JA4),
    HTTP/2 SETTINGS/HEADERS frame ordering, ALPN, header order, sec-ch-ua /
    sec-fetch-* headers, GREASE values. The caller's ``headers`` win over the
    impersonation defaults (so engagement auth + per-call headers still apply),
    and we do NOT follow redirects here — the outer fetch() loop records each
    hop so the scope guard and credential-drop rules apply per redirect.
    """
    started = time.monotonic()
    try:
        # content=False so curl_cffi does not auto-decode — we cap+decode
        # ourselves via _decode_body, matching the urllib transport's contract.
        r = _cf_requests.request(
            method=method.upper(),
            url=url,
            headers=headers,
            data=body,
            timeout=timeout,
            allow_redirects=False,
            verify=verify_tls,
            impersonate=profile,
            stream=False,
        )
        raw = r.content if r.content is not None else b""
        # curl_cffi decodes gzip/deflate/br by default; we still cap.
        content = raw[:max_body]
        truncated = len(raw) > max_body
        # Header pairs preserving order — r.headers is a multidict-like.
        try:
            resp_headers = list(r.headers.multi_items())
        except AttributeError:
            resp_headers = list(r.headers.items())
        elapsed = (time.monotonic() - started) * 1000
        return HttpResult(
            url=url,
            final_url=str(r.url) if r.url else url,
            status=r.status_code,
            reason=getattr(r, "reason", "") or "",
            headers=resp_headers,
            body=content,
            elapsed_ms=round(elapsed, 1),
            truncated=truncated,
        )
    except Exception as exc:  # curl_cffi raises a variety; normalise to error result
        elapsed = (time.monotonic() - started) * 1000
        return HttpResult(
            url=url,
            final_url=url,
            status=None,
            reason="",
            headers=[],
            body=b"",
            elapsed_ms=round(elapsed, 1),
            error=str(exc),
        )


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Disable urllib's automatic redirects so we can record them ourselves."""

    def redirect_request(self, *args, **kwargs):  # noqa: D401,ANN001,ANN002
        return None


def _build_opener(ctx: ssl.SSLContext) -> urllib.request.OpenerDirector:
    """An opener with ONLY http(s) handlers — never urllib's default FileHandler /
    FTPHandler / DataHandler, so a redirect (or crafted URL) to ``file://`` /
    ``ftp://`` / ``data:`` cannot smuggle a local-file read or a non-HTTP fetch past
    the SSRF guard. Unknown schemes hit UnknownHandler → a clean URLError, not a crash."""

    opener = urllib.request.OpenerDirector()
    for h in (
        urllib.request.ProxyHandler(),
        urllib.request.UnknownHandler(),
        urllib.request.HTTPHandler(),
        urllib.request.HTTPSHandler(context=ctx),
        urllib.request.HTTPDefaultErrorHandler(),
        _NoRedirect(),
        urllib.request.HTTPErrorProcessor(),
    ):
        opener.add_handler(h)
    return opener


def _origin(u: str) -> tuple[str, str, int | None]:
    sp = urlsplit(u)
    return (sp.scheme.lower(), (sp.hostname or "").lower(), sp.port)


# The ONLY headers safe to carry across an origin boundary on a redirect. Anything
# not on this allowlist is dropped when a redirect crosses to a different origin —
# not just Authorization/Cookie and engagement auth, but ANY caller-supplied header
# (X-Api-Key, X-Auth-Token, a custom bearer, Referer, …), since a cross-origin hop
# must never replay a credential the caller attached for the first origin. An
# allowlist fails safe: a new/unknown auth header is dropped by default.
_CROSS_ORIGIN_SAFE_HEADERS = frozenset({
    "user-agent", "accept", "accept-encoding", "accept-language", "content-type",
})


class HttpClient:
    """Async HTTP client with shared rate limiting and manual redirect tracing."""

    def __init__(
        self,
        governor: Governor,
        *,
        user_agent: str,
        default_timeout: float = 10.0,
        max_body: int = DEFAULT_MAX_BODY,
        connect_guard: Callable[[str], str | None] | None = None,
        auth_provider: Callable[[], dict[str, str]] | None = None,
    ) -> None:
        self._gov = governor
        self._ua = user_agent
        self._timeout = default_timeout
        self._max_body = max_body
        # connect_guard(host) -> reason-if-blocked | None; applied to every hop
        # (initial + each redirect) so no fetch reaches a private/internal IP.
        self._connect_guard = connect_guard
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
        merged: dict[str, str]
        if _USE_CURL_CFFI:
            # curl_cffi's impersonate= profile supplies the full browser header
            # set (User-Agent, sec-ch-ua, sec-fetch-*, Accept, Accept-Encoding,
            # Accept-Language, Priority, ...). We must NOT override those with
            # urllib's 3-header skeleton, or we lose the fingerprint. Engagement
            # auth + per-call headers still layer on top.
            merged = {}
        else:
            merged = {"User-Agent": self._ua, "Accept-Encoding": "gzip, deflate", "Accept": "*/*"}
        # Scope-check the INITIAL url before the first hop. The redirect-loop
        # below already checks each Location, but without this guard a caller-
        # supplied initial URL is fetched with engagement auth attached before
        # any scope check runs — the "net-layer scope gap" that surfaced ~8
        # recon-layer findings (CR1/RC16/RC28/RC32/RC38/RC41) and the
        # oauth_redirect_probe SSRF pattern. One fix here closes all of them.
        if scope_check is not None and not scope_check(url):
            return HttpResult(
                url=url, final_url=url, status=None, reason="",
                headers=[], body=b"", elapsed_ms=0.0,
                error="out of scope", blocked_reason="out of scope",
            )
        if self._auth_provider is not None and not suppress_auth:
            merged.update(self._auth_provider())
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
            # SSRF connect-guard: resolve+check this hop's host before we touch it.
            # The guard does a blocking getaddrinfo, so keep it off the event loop.
            if self._connect_guard is not None:
                host = urlsplit(current).hostname or current
                reason = await asyncio.to_thread(self._connect_guard, host)
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
            async with self._gov:
                if _USE_CURL_CFFI:
                    result = await asyncio.to_thread(
                        _curl_cffi_fetch,
                        current,
                        method,
                        merged,
                        body,
                        timeout or self._timeout,
                        verify_tls,
                        max_body or self._max_body,
                        _IMPERSONATE_PROFILE,
                    )
                else:
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
            # Crossing to a different origin: drop every header not on the safe
            # allowlist — Authorization/Cookie, engagement auth, AND any caller-supplied
            # custom header (X-Api-Key, X-Auth-Token, Referer, …). Never replay a
            # credential the caller attached for the first origin to another host.
            if _origin(nxt) != origin0:
                for k in list(merged):
                    if k.lower() not in _CROSS_ORIGIN_SAFE_HEADERS:
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
