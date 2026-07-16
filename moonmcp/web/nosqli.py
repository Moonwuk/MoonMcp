"""MongoDB NoSQL operator-injection differential probe — detection only.

The injection KB has a ``nosqli`` class but there was never an *active* probe for
it. This module supplies the payload data + pure analysers; the ``nosqli_probe``
server tool does the fetching and feeds the signals into :func:`moonmcp.confirm.evaluate`.

Two safe, benign lanes — no data is ever extracted:

1. **Operator injection** — send an *object* where the app expects a *string*.
   ``{"$ne": null}`` matches any value, ``{"$gt": ""}`` any non-empty string,
   ``{"$nin": [ctl]}`` everything but the control. On a login/search query that is
   an auth-bypass / all-rows differential. Confirmed when a reproducible operator
   twin *flips the outcome* vs a plain-``CONTROL`` baseline (status change, a new
   session ``Set-Cookie``, or materially more body). Both the bracket form
   (``param[$ne]=v`` — Express/qs, PHP auto-parse) and the JSON form
   (``{"param":{"$ne":null}}``) are sent.
2. **``$where`` server-side-JS boolean oracle** — ``{"$where":"return 1==1"}`` vs
   ``{"$where":"return 1==2"}`` (equal length, so a verbatim echo yields no differential):
   a reproducible true≠false differential proves
   server-side JS evaluation. Boolean **only** — never ``sleep()``/busy-loop (that
   is a DoS-adjacent side effect handed to Strix), never char-by-char ``$regex``
   extraction (that is data exfil → NoSQLMap/Strix).

Sources: https://portswigger.net/web-security/nosql-injection ·
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/NoSQL%20Injection/README.md ·
OWASP WSTG-INPV-05 (NoSQL). See docs/DATABASE_RESEARCH.md Theme A.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

# A value unlikely to match a real record — the negative baseline. If the plain
# CONTROL and an operator twin behave the same, there is no injection.
CONTROL = "moonNoSQLctl9174"

# Bracket-form operator twins placed in the query (GET/HEAD) or a urlencoded form
# body (POST-ish): (label, operator, value). Each matches MANY records where the
# plain CONTROL matches at most one → an auth-bypass / all-rows differential.
BRACKET_TWINS: list[tuple[str, str, str]] = [
    ("bracket:$ne", "$ne", CONTROL),
    ("bracket:$gt", "$gt", ""),
    ("bracket:$nin", "$nin", CONTROL),
]

# JSON-body operator twins: {param: {op: value}} sent as application/json.
JSON_TWINS: list[tuple[str, object]] = [
    ("json:$ne", {"$ne": None}),
    ("json:$gt", {"$gt": ""}),
]

# $where server-side-JS boolean pair (JSON body). Boolean oracle ONLY. The two
# expressions are EQUAL LENGTH ("return 1==1" / "return 1==2", 11 chars each) so an
# endpoint that merely ECHOES the posted JSON produces no length differential —
# without this, "return true"/"return false" differ by one byte and a pure reflection
# faked a $where oracle (assess_where has no magnitude floor). Only real server-side
# JS evaluation (true matches all rows, false none) yields a differential now.
WHERE_TRUE: dict[str, str] = {"$where": "return 1==1"}
WHERE_FALSE: dict[str, str] = {"$where": "return 1==2"}

_JSON_HEADERS = {"Content-Type": "application/json"}

# Cookie name fragments that indicate an authenticated session was issued.
_SESSION_HINTS = ("session", "sess", "token", "auth", "jwt", "sid", "connect.sid")

Request = tuple[str, bytes | None, dict[str, str]]


def _is_body_method(method: str) -> bool:
    return method.upper() not in ("GET", "HEAD")


def scalar_request(url: str, param: str, value: str, method: str = "GET") -> Request:
    """The plain-scalar request (the negative baseline uses ``value=CONTROL``)."""

    if not _is_body_method(method):
        sp = urlsplit(url)
        q = [(k, v) for k, v in parse_qsl(sp.query, keep_blank_values=True) if k != param]
        q.append((param, value))
        return urlunsplit(sp._replace(query=urlencode(q))), None, {}
    return url, urlencode({param: value}).encode(), {}


def bracket_request(url: str, param: str, operator: str, value: str,
                    method: str = "GET") -> Request:
    """Place ``param[operator]=value`` in the query (GET/HEAD) or form body,
    dropping any prior ``param`` / ``param[...]`` so the twin is clean."""

    key = f"{param}[{operator}]"
    if not _is_body_method(method):
        sp = urlsplit(url)
        q = [(k, v) for k, v in parse_qsl(sp.query, keep_blank_values=True)
             if k != param and not k.startswith(f"{param}[")]
        q.append((key, value))
        return urlunsplit(sp._replace(query=urlencode(q))), None, {}
    return url, urlencode({key: value}).encode(), {}


def json_request(url: str, param: str, obj: object) -> Request:
    """Body ``{param: obj}`` as application/json (always POST-ish upstream)."""

    return url, json.dumps({param: obj}).encode(), dict(_JSON_HEADERS)


def has_session_cookie(set_cookies: list[str]) -> bool:
    """Does any ``Set-Cookie`` look like an issued auth/session cookie?"""

    joined = " ".join(set_cookies).lower()
    return any(h in joined for h in _SESSION_HINTS)


@dataclass(frozen=True)
class Resp:
    """The minimal, comparable summary of one response."""

    status: int | None
    length: int
    session_cookie: bool = False


def _stable(a: Resp, b: Resp) -> bool:
    return a.status == b.status and a.length == b.length


def assess_operator(control: tuple[Resp, Resp], twin: tuple[Resp, Resp]) -> dict | None:
    """Is an operator twin a hit vs the plain-CONTROL baseline?

    Requires the twin to be **reproducible** (both sends agree) — this rejects
    inter-request noise. A hit *flips the outcome*: a status change or a new
    session cookie is a **strong** flip; materially more body (only trusted when
    the control is itself stable) is a **weak** "more records?" flip.
    """

    c1, c2 = control
    r1, r2 = twin
    if not _stable(r1, r2):
        return None
    if not _stable(c1, c2):
        return None  # a noisy/unreproducible baseline can't be trusted for a flip
    reasons: list[str] = []
    strong = False
    if r1.status is not None and r1.status != c1.status:
        reasons.append(f"status {c1.status}→{r1.status}")
        # A status change is "strong" (auth bypass) ONLY when it flips TOWARD success —
        # the twin reaches 2xx where the control did not. A flip to a 4xx/5xx error means
        # the operator object reached the query engine but was rejected/errored: a real
        # interpretation signal worth surfacing (weak), but NOT an auth bypass, so a
        # benign type-coercion crash isn't mis-scored as a confirmed NoSQL auth bypass.
        twin_ok = 200 <= r1.status < 300
        ctrl_ok = c1.status is not None and 200 <= c1.status < 300
        if twin_ok and not ctrl_ok:
            strong = True
    if r1.session_cookie and not c1.session_cookie:
        reasons.append("new session Set-Cookie appeared")
        strong = True
    if r1.length - c1.length >= max(64, c1.length // 2):
        reasons.append(f"response +{r1.length - c1.length} bytes vs baseline (more records?)")
    if not reasons:
        return None
    return {"strong": strong, "reasons": reasons, "status": r1.status, "length": r1.length}


def assess_where(true_pair: tuple[Resp, Resp], false_pair: tuple[Resp, Resp]) -> dict | None:
    """``$where`` boolean oracle: reproducible true≠false ⇒ server-side JS eval.

    Mirrors ``sqli_probe``'s reproducible boolean logic exactly.
    """

    t1, t2 = true_pair
    f1, f2 = false_pair
    if not (_stable(t1, t2) and _stable(f1, f2)):
        return None
    differs = t1.status != f1.status or t1.length != f1.length
    if not differs:
        return None
    return {"true_status": t1.status, "true_len": t1.length,
            "false_status": f1.status, "false_len": f1.length,
            "status_changed": t1.status != f1.status,
            "length_delta": t1.length - f1.length}
