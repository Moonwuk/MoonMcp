"""Shared parameter-injection helpers used by the active probes.

Two placements: the query for GET/HEAD, a form body for POST-ish methods. Two
encodings: :func:`with_param` URL-encodes the value (the normal case), while
:func:`inject_raw` appends it verbatim (for payloads like CRLF that carry their
own percent-encoding and must NOT be re-encoded).
"""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def with_param(url: str, param: str | None, value: str,
               method: str = "GET") -> tuple[str, bytes | None]:
    """Return ``(request_url, request_body)`` with *value* placed in *param* — the
    (url-encoded) query for GET/HEAD, a form body for POST-ish methods. ``param``
    may be None to leave the request unchanged (just normalised)."""

    if method.upper() in ("GET", "HEAD") or not param:
        sp = urlsplit(url)
        q = dict(parse_qsl(sp.query, keep_blank_values=True))
        if param:
            q[param] = value
        return urlunsplit(sp._replace(query=urlencode(q))), None
    return url, urlencode({param: value}).encode()


def inject_raw(url: str, param: str, payload: str) -> str:
    """Append ``param=payload`` to *url* WITHOUT re-encoding (the payload already
    carries its own percent-encoded bytes, e.g. a CRLF ``%0d%0a``)."""

    sep = "&" if urlsplit(url).query else "?"
    return f"{url}{sep}{param}={payload}"
