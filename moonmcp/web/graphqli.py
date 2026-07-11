"""GraphQL → NoSQL operator-injection differential — detection only.

``graphql_check`` finds and introspects GraphQL endpoints; it does not test whether
a resolver forwards a client-controlled object straight into a Mongo/Mongoose
filter. When an arg is typed as a JSON/Object scalar, an attacker sends an
*operator object* (``{"$ne": null}``) as the GraphQL **variable** value where the
app expects a scalar — on a login/search resolver that is an auth-bypass /
all-records differential. (Distinct from the Mongoose `$where`-in-``populate().match``
RCE class, CVE-2024-53900 / CVE-2025-23061, which needs server-side JS and is
deferred to NoSQLMap/Strix — this tool never sends `$where`.)

This module supplies the payload objects + pure analysers; the ``graphql_nosqli``
server tool transports them as GraphQL variables and feeds the signals into
:func:`moonmcp.confirm.evaluate` + the ``nosqli`` error-signature KB. Detection-only
— a benign reproducible differential (a resolver returns data / more records where
the scalar did not) or a Mongoose ``CastError`` leaked in ``errors[]``; never
``$regex`` char-extraction or ``sleep()`` (those go to NoSQLMap/Strix).

Injected via **variables**, not inline: ``$ne`` is a GraphQL variable sigil, so an
operator object can only ride in the ``variables`` JSON — which is exactly how the
real Mongoose-GraphQL bugs land. Sources: appsecco "hacking apps using NoSQLi" ·
PayloadsAllTheThings GraphQL Injection · https://security.snyk.io/vuln/SNYK-JS-MONGOOSE-8172732 ·
https://portswigger.net/web-security/nosql-injection. See docs/DATABASE_RESEARCH.md Theme A.3.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

CONTROL = "moonGQLctl4821"

# Operator objects sent where the resolver expects a scalar. Each matches MANY
# records where the plain CONTROL string matches at most one → an auth-bypass /
# all-records flip on ``find({field: value})``.
OPERATOR_TWINS: list[tuple[str, object]] = [
    ("$ne", {"$ne": None}),
    ("$gt", {"$gt": ""}),
    ("$in", {"$in": ["admin", "administrator", "root"]}),
    ("$nin", {"$nin": [CONTROL]}),
]

# GraphQL validation messages that mean the variable is STRICTLY typed (e.g. String)
# so the object was rejected *before* reaching a resolver → not injectable via it.
_REJECTION = (
    "expected type", "expected value of type", "cannot represent",
    "got invalid value", "must be a string", "of non-null type",
)


def build_body(query: str, variable: str, value: object) -> bytes:
    """The GraphQL POST body: fixed ``query`` + the injected ``variables[variable]``."""

    return json.dumps({"query": query, "variables": {variable: value}}).encode()


def _nonnull(v: object) -> bool:
    if v is None:
        return False
    if isinstance(v, dict):
        return any(_nonnull(x) for x in v.values())
    if isinstance(v, list):
        return len(v) > 0
    if isinstance(v, str):
        return v != ""
    return True


def data_present(body_text: str) -> bool:
    """Did the response carry a **non-empty** ``data`` payload (a resolver actually
    returned something)? GraphQL always includes a ``data`` key, so we require it
    non-null and non-empty for an auth/record flip to be visible."""

    try:
        obj = json.loads(body_text)
    except (ValueError, TypeError):
        return False
    return isinstance(obj, dict) and _nonnull(obj.get("data"))


def is_rejected(body_text: str) -> bool:
    """A GraphQL type-validation error → the operator object was rejected, so the
    variable is strictly typed (not injectable via it). NOT a vulnerability signal."""

    low = body_text.lower()
    return '"errors"' in low and any(k in low for k in _REJECTION)


@dataclass(frozen=True)
class Resp:
    """The minimal comparable summary of one GraphQL response.

    ``rejected`` = a GraphQL type-coercion error (the variable is strictly typed, so
    the object never reached a resolver); ``session`` = an auth/session cookie was
    issued (an auth-success signal independent of the body shape)."""

    status: int | None
    length: int
    data: bool = False
    rejected: bool = False
    session: bool = False


def _stable(a: Resp, b: Resp) -> bool:
    return (a.status == b.status and a.length == b.length
            and a.data == b.data and a.session == b.session)


def assess_operator(control: tuple[Resp, Resp], twin: tuple[Resp, Resp]) -> dict | None:
    """A reproducible operator twin that flips the outcome vs the string control.

    Guards, in order: the twin must be reproducible; a **type-rejection** twin is
    never a hit (that is a strictly-typed variable, not injection); and the control
    must itself be reproducible before any differential is trusted. Strong flips:
    a resolver payload appears (``data`` false→true), an auth/session cookie is issued
    the control didn't get, or a **denied→success** status change (a change to a
    4xx/5xx rejection/crash is never scored). A materially longer body that carried
    data (or a very large increase, hinting a data body truncated past the parse cap)
    is a weak "more records" flip. Mirrors ``nosqli.assess_operator``' double-send
    noise rejection, extended for the GraphQL transport.
    """

    c1, c2 = control
    t1, t2 = twin
    if not _stable(t1, t2):
        return None                       # twin not reproducible → noise
    if t1.rejected:
        return None                       # GraphQL type rejection → NOT an injection hit
    if not _stable(c1, c2):
        return None                       # control not reproducible → can't trust a diff
    reasons: list[str] = []
    strong = False
    if t1.data and not c1.data:
        reasons.append("resolver returned data where the scalar control did not (auth/record flip)")
        strong = True
    if t1.session and not c1.session:
        reasons.append("an auth/session cookie was issued for the operator object but not the control")
        strong = True
    # Directional: only a DENIED→SUCCESS status change is an auth-bypass signal; a
    # change to a 4xx/5xx (rejection/crash) is never injection.
    if t1.status in (200, 201, 204) and c1.status in (401, 403):
        reasons.append(f"status {c1.status}→{t1.status} (denied→success)")
        strong = True
    # "More records": a materially longer body that actually carried data (or a very
    # large increase suggesting a data body truncated past the parse cap) — never an error.
    if (t1.data or t1.length - c1.length >= 8192) and t1.length - c1.length >= max(64, c1.length // 2):
        reasons.append(f"response +{t1.length - c1.length} bytes vs control (more records?)")
    if not reasons:
        return None
    return {"strong": strong, "reasons": reasons, "status": t1.status, "length": t1.length}
