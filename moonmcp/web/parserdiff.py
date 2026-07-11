"""HTTP parser-differential probe — detection only.

A fronting WAF/proxy and the app behind it frequently use *different* parsers.
When a request can be encoded so the two disagree, an attacker smuggles a payload
past the WAF that the app still parses — the primitive behind most modern WAF
bypasses (WAFFLED, Bishop Fox "JSON interoperability vulnerabilities").

This module supplies benign canonical-vs-quirk twins + pure analysers; the
``parser_diff_probe`` server tool fetches and scores. Every twin carries a unique
alphanumeric canary and delivers **nothing executable** — the signal is purely
*which transform the app applied* / *which non-standard form it accepted*, never a
live bypass payload and never data extraction.

Two lane families:

* **decode** (``charset_utf7`` / ``overlong_utf8``) — the canary is sent *only* in
  an encoded form; if the plain canary comes back in the response, the app decoded
  UTF-7 / normalised overlong UTF-8. A definite parser transform → the **strong**
  signal (a real filter-bypass primitive: the WAF sees ``+AG0-``/``%C1%AD``, the
  app sees the letter).
* **tolerance** (``json_comment`` / ``json_trailing`` / ``json_bom`` /
  ``multipart_lf``) — a form a *standard* parser genuinely rejects (JSON comments,
  trailing commas, a leading UTF-8 BOM, bare-LF multipart line endings) is
  **accepted and parsed** by the app, while an echo-everything endpoint — one that
  reflects the canary even from a blatantly-invalid control — is excluded. A real
  lax-parser surface → the **medium** signal.
* **precedence** (``json_dupkey`` / ``multipart_dup``) — duplicate JSON keys and
  repeated multipart fields are RFC-permitted, so *acceptance* is not a differential
  (every standard parser takes them, last-wins). Only *which value wins* is the
  WAF-relevant lead, so it is reported **informational-only** and never raises the
  verdict on its own.

Detection-only: weaponisation (smuggling a real payload through the confirmed
differential) → Strix. Sources: WAFFLED (arXiv 2503.10846) ·
https://bishopfox.com/blog/json-interoperability-vulnerabilities ·
https://portswigger.net/research. See docs/RESEARCH_GAPS.md Theme 6.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

# Inert, alphanumeric, markup-free canaries. If either is reflected it is harmless
# (no script, no SQL) — it exists only to prove *which* form the app parsed.
CANARY = "moonpd7qz"
DECOY = "moondk0zx"

# A stable multipart boundary for the multipart lane.
_BOUNDARY = "----moonPD9174boundary"

Request = tuple[str, bytes | None, dict[str, str]]


# --------------------------------------------------------------------------- #
# encoders
# --------------------------------------------------------------------------- #
def utf7_shift(s: str) -> str:
    """Force *s* into a UTF-7 shifted block (``+<modified-base64>-``).

    Python's own ``str.encode('utf-7')`` leaves plain ASCII untouched, which would
    prove nothing — so we hand-build the shifted form the way a UTF-7 XSS payload
    does. A server that decodes UTF-7 turns this back into *s*.
    """

    enc = base64.b64encode(s.encode("utf-16-be")).decode("ascii").rstrip("=")
    return "+" + enc + "-"


def overlong(s: str) -> str:
    """Percent-encode each ASCII char of *s* as an **overlong** 2-byte UTF-8
    sequence (``A`` → ``%C1%81``). Bytes >0x7f are left as normal percent-encoding.
    A server that normalises overlong UTF-8 turns this back into *s*."""

    out: list[str] = []
    for ch in s:
        c = ord(ch)
        if c > 0x7F:
            out.append(quote(ch))
            continue
        out.append(f"%{0xC0 | (c >> 6):02X}%{0x80 | (c & 0x3F):02X}")
    return "".join(out)


# --------------------------------------------------------------------------- #
# request builders
# --------------------------------------------------------------------------- #
def _is_body(method: str) -> bool:
    return method.upper() not in ("GET", "HEAD")


def form_canonical(url: str, param: str, value: str, method: str = "POST") -> Request:
    """Plain ``param=value`` — query for GET/HEAD, urlencoded form body otherwise."""

    if not _is_body(method):
        sp = urlsplit(url)
        q = [(k, v) for k, v in parse_qsl(sp.query, keep_blank_values=True) if k != param]
        q.append((param, value))
        return urlunsplit(sp._replace(query=urlencode(q))), None, {}
    return url, urlencode({param: value}).encode(), {
        "Content-Type": "application/x-www-form-urlencoded"}


def utf7_form(url: str, param: str, canary: str) -> Request:
    """UTF-7 decode lane: ``param=<utf7 canary>`` in a form body declared
    ``charset=utf-7``. Frameworks that honour the request charset decode it. The
    UTF-7 sequence is percent-encoded so form url-decoding (``+`` → space) can't
    corrupt it before the charset layer runs."""

    body = f"{param}={quote(utf7_shift(canary), safe='')}".encode()
    return url, body, {
        "Content-Type": "application/x-www-form-urlencoded; charset=utf-7"}


def overlong_query(url: str, param: str, canary: str) -> Request:
    """Overlong-UTF-8 decode lane: raw overlong bytes appended to the query
    (verbatim — must NOT be re-encoded)."""

    sep = "&" if urlsplit(url).query else "?"
    return f"{url}{sep}{param}={overlong(canary)}", None, {}


def json_canonical(url: str, param: str, value: str) -> Request:
    return url, json.dumps({param: value}).encode(), {"Content-Type": "application/json"}


def json_dupkey(url: str, param: str, decoy: str, canary: str) -> Request:
    """Duplicate-key JSON: ``decoy`` first, ``canary`` last. Parsers split on which
    one wins (RFC 8259 leaves it undefined)."""

    body = f'{{"{param}":"{decoy}","{param}":"{canary}"}}'.encode()
    return url, body, {"Content-Type": "application/json"}


def json_comment(url: str, param: str, canary: str) -> Request:
    """JSONC-style comment appended (only JSON5/Jackson-lax parsers accept it)."""

    body = f'{{"{param}":"{canary}"}} // moonpd'.encode()
    return url, body, {"Content-Type": "application/json"}


def json_trailing(url: str, param: str, canary: str) -> Request:
    """Trailing comma (rejected by a strict RFC parser, accepted by lax ones)."""

    body = f'{{"{param}":"{canary}",}}'.encode()
    return url, body, {"Content-Type": "application/json"}


def json_bom(url: str, param: str, canary: str) -> Request:
    """Leading UTF-8 BOM: RFC 8259 forbids it (Python ``json`` raises), but Jackson /
    JS ``JSON.parse`` / .NET ``System.Text.Json`` silently skip it — so a WAF that
    strict-parses the body fails to inspect it while the app accepts it (Bishop Fox
    JSON-interoperability)."""

    body = b"\xef\xbb\xbf" + json.dumps({param: canary}).encode()
    return url, body, {"Content-Type": "application/json"}


def json_invalid(url: str, param: str, canary: str) -> Request:
    """The reject-control: blatantly-broken JSON. If the app *accepts* this too it
    isn't really JSON-parsing (echo/pass-through) → tolerance lanes are suppressed."""

    body = f'{{"{param}":"{canary}"'.encode()  # truncated, no closing brace
    return url, body, {"Content-Type": "application/json"}


def _mp(url: str, parts: list[tuple[str, str]], boundary: str = _BOUNDARY) -> Request:
    chunks = "".join(
        f'--{boundary}\r\nContent-Disposition: form-data; name="{n}"\r\n\r\n{v}\r\n'
        for n, v in parts)
    body = (chunks + f"--{boundary}--\r\n").encode()
    return url, body, {"Content-Type": f"multipart/form-data; boundary={boundary}"}


def multipart_canonical(url: str, param: str, value: str) -> Request:
    return _mp(url, [(param, value)])


def multipart_dup(url: str, param: str, decoy: str, canary: str) -> Request:
    """The same field twice — parsers split on first-wins vs last-wins."""

    return _mp(url, [(param, decoy), (param, canary)])


def multipart_lf(url: str, param: str, canary: str) -> Request:
    """Bare-LF line endings. RFC 7578 mandates CRLF between multipart tokens, so a
    strict parser only splits parts on ``\\r\\n`` and misses an LF-delimited field,
    while permissive parsers (PHP, several Node/Python libs) accept it — one of
    WAFFLED's core multipart-smuggling primitives."""

    _, crlf, headers = _mp(url, [(param, canary)])
    return url, (crlf or b"").replace(b"\r\n", b"\n"), headers


def multipart_invalid(url: str, param: str, canary: str) -> Request:
    """Reject-control: the declared boundary and the body's boundary disagree."""

    _, body, _ = _mp(url, [(param, canary)], boundary="WRONGBOUNDARY")
    return url, body, {"Content-Type": f"multipart/form-data; boundary={_BOUNDARY}"}


# --------------------------------------------------------------------------- #
# response summary + assessors
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Resp:
    """The minimal comparable summary of one response."""

    status: int | None
    length: int
    has_canary: bool = False
    has_decoy: bool = False


def _ok(status: int | None) -> bool:
    """A parse-accepted response — anything that is not a client/server error."""

    return status is not None and status < 400


def assess_decode(canonical: Resp, quirk: Resp) -> dict | None:
    """Decode lane hit: the plain canary appears in the *quirk* response although it
    was sent only encoded — so the app decoded it. Requires the canonical request to
    reflect the canary too (proves the endpoint echoes input, so absence would mean
    something). The encoded form never contains the plain canary substring, so a
    match is a genuine transform, not an echo of our bytes."""

    if not canonical.has_canary:
        return None  # endpoint is not reflective — decode lane is inconclusive
    if not quirk.has_canary:
        return None
    return {"strong": True,
            "reason": "plain canary reflected from an encoded-only payload — app applied the transform",
            "status": quirk.status, "length": quirk.length}


def assess_tolerance(canonical: Resp, quirk: Resp, invalid: Resp) -> dict | None:
    """Tolerance lane hit: a **standard** parser rejects the quirk (JSON comment /
    trailing comma / BOM / bare-LF multipart), yet the app *accepts and parses* it
    (status parity with canonical, our canary reflected). The invalid control gates
    out an **echo-everything** endpoint — one that reflects the canary even from
    blatantly-broken input; a genuinely-parsing app never reflects it there. Note we
    key on *reflection*, not the invalid status: a lenient app that returns 200-empty
    on a parse error is a real target, not an echoer."""

    if not (_ok(canonical.status) and canonical.has_canary):
        return None  # no usable baseline
    if invalid.has_canary:
        return None  # echo-everything (reflects canary from broken input) → not parsing
    if not _ok(quirk.status) or quirk.status != canonical.status:
        return None  # standard parser rejected (or changed) the quirk → secure
    if not quirk.has_canary:
        return None  # accepted but didn't parse our value → not a differential
    return {"strong": False,
            "reason": "standard-parser-rejected form accepted and parsed by the app",
            "status": quirk.status, "length": quirk.length}


def assess_precedence(canonical: Resp, quirk: Resp) -> dict | None:
    """Precedence lead (informational, never scored): duplicate JSON keys / repeated
    multipart fields are RFC-permitted, so *acceptance* is not a differential. Report
    only *which value won* — the WAF-relevant lead when a fronting parser picks the
    other one. No invalid-control gate: this is not a hit, just an observation."""

    if not (_ok(canonical.status) and canonical.has_canary):
        return None
    if not _ok(quirk.status) or not (quirk.has_canary or quirk.has_decoy):
        return None
    won = ("last-wins (app used the trailing value)" if quirk.has_canary and not quirk.has_decoy
           else "first-wins (app used the leading value)" if quirk.has_decoy and not quirk.has_canary
           else "both values reflected")
    return {"won": won, "status": quirk.status}
