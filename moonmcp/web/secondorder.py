"""Second-order (stored) SQL injection — write in request 1, fires in request N.

The sink is on a *different* endpoint from the injection: user input is stored safely
(a parameterized INSERT), then later re-read and concatenated into another query. A
stateless per-request matcher (nuclei, even sqlmap against the write endpoint) sees
nothing — this is the same cross-request state class as `workflow_probe`.

Detection (safe, differential): seed a **uniquely-tagged** value at the write endpoint,
then drive the candidate read/render endpoints and look for evidence that only appears
after the seed:

- **error lane** — seed ``<tag>'`` and match a SQL error signature at the read sink that
  is NOT present for a benign ``<tag>ctl`` control (a syntax error away from the write).
- **boolean lane** — seed ``<tag>' AND '1'='1`` vs ``<tag>' AND '1'='2`` (equal length, so
  a verbatim echo yields NO differential) and require the tag reflected at the sink *and*
  the two reads to differ — the stored value reached a second query context.
- **OOB lane** — seed a ``<tag>``-prefixed OAST payload, drive the reader, poll for a callback.

The unique tag ties the phase-2 evidence back to the phase-1 write. No data is extracted
(that weaponization → sqlmap ``--second-url`` / Strix).

Sources: https://portswigger.net/kb/issues/00100210_sql-injection-second-order ·
https://www.netspi.com/blog/technical-blog/web-application-pentesting/second-order-sql-injection-with-stored-procedures-dns-based-egress/ ·
Viblo/WhiteHat (VN). See docs/DATABASE_RESEARCH.md Theme C.6.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass

TAG_PREFIX = "moon2o"


def make_tag() -> str:
    """A unique, benign marker that ties phase-2 read evidence to the phase-1 write."""

    return f"{TAG_PREFIX}{uuid.uuid4().hex[:8]}"


def seed_payloads(tag: str) -> dict[str, str]:
    """The four tagged write values. The boolean twins are EQUAL length, so a verbatim
    echo produces no differential — only SQL evaluation at the sink does."""

    return {
        "control": f"{tag}ctl",
        "error": f"{tag}'",
        "true": f"{tag}' AND '1'='1",
        "false": f"{tag}' AND '1'='2",
    }


def oob_seed(tag: str, http_url: str, canary_host: str | None) -> str:
    """A tagged Oracle UTL_HTTP OOB payload (DNS/HTTP callback only, no exfil)."""

    return f"{tag}'||(SELECT UTL_HTTP.REQUEST('{http_url}') FROM dual)||'"


@dataclass(frozen=True)
class ReadObs:
    """The minimal observation of one read-sink response."""

    status: int | None
    text: str


def assess_read(tag: str, control: ReadObs, error: ReadObs, true: ReadObs, false: ReadObs,
                match_fn: Callable[[str], list[dict]]) -> dict | None:
    """Second-order verdict for one read sink.

    ``match_fn`` maps response text → SQL error signatures (the injection KB). A finding
    fires when the error seed produces a SQL error the control didn't, or when the tag is
    reflected AND the boolean twins diverge (the stored value reached a second query).
    """

    tag_l = tag.lower()
    reflected = any(tag_l in (o.text or "").lower() for o in (error, true, false))
    control_sigs = {h["matched"] for h in match_fn(control.text or "")}
    error_sigs = [h for h in match_fn(error.text or "") if h["matched"] not in control_sigs]
    bool_diff = (true.status != false.status) or (len(true.text or "") != len(false.text or ""))

    if not error_sigs and not (reflected and bool_diff):
        return None
    detail: list[str] = []
    if error_sigs:
        techs = ", ".join(dict.fromkeys(s["technology"] for s in error_sigs[:3]))
        detail.append(f"SQL error fired at the read sink after seeding the write, absent for the "
                      f"benign control ({techs}) — stored value reaches a second query context")
    if reflected and bool_diff:
        detail.append("tagged stored value reflected at the read sink and its equal-length boolean "
                      "twin changed the response — evaluated, not echoed")
    return {
        "reflected": reflected,
        "error_signatures": error_sigs[:5],
        "boolean_differential": bool_diff,
        "severity": "high" if error_sigs else "medium",
        "verdict": "review",
        "detail": "; ".join(detail),
    }


def normalize_reads(read) -> list[dict]:
    """Coerce a read spec (a URL string, or a list of URL strings / {url, method} dicts)
    into ``{url, method}`` dicts."""

    if isinstance(read, (str, dict)):
        read = [read]
    out: list[dict] = []
    for r in read or []:
        if isinstance(r, str):
            r = {"url": r}
        if not isinstance(r, dict) or not r.get("url"):
            continue
        out.append({"url": r["url"], "method": (r.get("method") or "GET").upper()})
    return out
