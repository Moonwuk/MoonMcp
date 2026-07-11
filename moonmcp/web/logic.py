"""Business-logic abuse probes — the automatable slice of logic-flaw testing.

Business-logic bugs need *intent*: the agent decides which flow (checkout, refund,
invite, vote, withdrawal) to attack and interprets the result. This module drives
the mechanical parts deterministically so the agent can reason over evidence:

* **parameter tampering** — negative / zero / overflow values on money/quantity
  fields that a correct server should reject;
* **mass assignment** — privileged fields (`role`, `is_admin`, `balance`, …) the
  client shouldn't be able to set, flagged when the response reflects them;
* **race window** — fire N identical requests in parallel; a non-atomic per-user
  limit lets more than one succeed (coupon reuse, double-spend, limit bypass).

Findings are **leads** (verdict ``review``) — logic flaws are confirmed by the
agent against the flow, guided by the ``business_logic_hunt`` prompt.
"""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Callable
from urllib.parse import parse_qsl, urlsplit

from ..net.http import HttpClient
from .inject import with_param

# money / quantity-ish parameter names worth tampering.
NUMERIC_PARAM_RE = re.compile(
    r"(qty|quantity|amount|price|total|count|balance|credit|points|cost|sum|"
    r"discount|fee|number|num|limit|max|min|id)", re.I)

# values a correct money/quantity field should reject.
TAMPER_VALUES = ["-1", "0", "-0.01", "999999999", "9e9", "1e10", "0x10", "'"]

# A garbage value a field that VALIDATES its input must reject. If the server accepts
# this like the baseline, the field isn't validated at all — so "accepting -1" is
# meaningless and every tamper flag would be a false positive. Used as a negative control.
_INVALID_CONTROL = "moonmcp_zzz_invalid"

# privileged fields that should never be client-settable (mass assignment / autobind).
PRIVILEGED_FIELDS: dict[str, str] = {
    "role": "admin", "is_admin": "true", "isAdmin": "true", "admin": "true",
    "is_staff": "true", "verified": "true", "is_verified": "true",
    "email_verified": "true", "status": "active", "account_type": "premium",
    "plan": "premium", "premium": "true", "balance": "999999", "credit": "999999",
    "approved": "true", "confirmed": "true", "price": "0", "discount": "100",
}


def numeric_params(keys) -> list[str]:
    """The subset of param names that look like money/quantity/id fields."""

    return [k for k in keys if NUMERIC_PARAM_RE.search(k)]


def assess_tamper(baseline_status: int | None, baseline_len: int,
                  tampered_status: int | None, tampered_len: int) -> bool:
    """A should-be-invalid value was ACCEPTED if the tampered request succeeds like
    the baseline (2xx, similar body) instead of being rejected (4xx / different)."""

    if baseline_status is None or tampered_status is None:
        return False
    baseline_ok = 200 <= baseline_status < 300
    tampered_ok = 200 <= tampered_status < 300
    similar = (tampered_status == baseline_status
               and abs(tampered_len - baseline_len) <= max(64, baseline_len // 8))
    return baseline_ok and tampered_ok and similar


async def probe_parameter_tampering(client: HttpClient, url: str, param: str, *,
                                    method: str = "GET",
                                    scope_check: Callable[[str], bool] | None = None) -> list[dict]:
    """Send a valid baseline then invalid values for *param*; flag the ones accepted."""

    m = method.upper()
    burl, bbody = with_param(url, param, "1", m)
    base = await client.fetch(burl, method=m, body=bbody, follow_redirects=False,
                              timeout=12.0, scope_check=scope_check)
    if base.status is None:
        return []
    base_len = len(base.body)
    # Negative control: if a garbage value is accepted like the baseline, the field
    # isn't validated at all → every tamper flag would be a false positive → bail.
    cu, cb = with_param(url, param, _INVALID_CONTROL, m)
    ctrl = await client.fetch(cu, method=m, body=cb, follow_redirects=False,
                              timeout=12.0, scope_check=scope_check)
    if assess_tamper(base.status, base_len, ctrl.status, len(ctrl.body)):
        return []
    findings: list[dict] = []
    for val in TAMPER_VALUES:
        tu, tb = with_param(url, param, val, m)
        r = await client.fetch(tu, method=m, body=tb, follow_redirects=False,
                               timeout=12.0, scope_check=scope_check)
        if assess_tamper(base.status, base_len, r.status, len(r.body)):
            findings.append({
                "kind": "parameter_tampering", "param": param, "value": val,
                "severity": "medium", "verdict": "review",
                "detail": f"{param}={val} was accepted like the valid baseline (HTTP {r.status}) — "
                          "possible price/quantity tampering; verify the order/total server-side",
            })
    return findings


async def probe_mass_assignment(client: HttpClient, url: str, *, method: str = "POST",
                                scope_check: Callable[[str], bool] | None = None) -> list[dict]:
    """POST the privileged fields as JSON; flag any reflected back with our value."""

    body = json.dumps(PRIVILEGED_FIELDS).encode()
    r = await client.fetch(url, method=method.upper(), body=body,
                           headers={"Content-Type": "application/json"},
                           follow_redirects=False, timeout=12.0, scope_check=scope_check)
    if r.status is None:
        return []
    text = r.text(limit=50_000)
    findings: list[dict] = []
    for field, value in PRIVILEGED_FIELDS.items():
        if f'"{field}"' in text and value.strip('"') in text:
            findings.append({
                "kind": "mass_assignment", "field": field, "value": value,
                "severity": "high", "verdict": "review",
                "detail": f"privileged field '{field}' reflected with our value — possible "
                          "mass assignment; verify it persisted (re-read the object)",
            })
    return findings


async def probe_race(client: HttpClient, url: str, *, method: str = "POST",
                     body: bytes | None = None, n: int = 20,
                     scope_check: Callable[[str], bool] | None = None) -> dict:
    """Fire *n* identical requests in parallel; report how many succeeded (a
    non-atomic per-user limit lets more than one through)."""

    n = max(2, min(n, 40))
    m = method.upper()

    async def _one() -> int | None:
        r = await client.fetch(url, method=m, body=body, follow_redirects=False,
                               timeout=12.0, scope_check=scope_check)
        return r.status

    statuses = await asyncio.gather(*[_one() for _ in range(n)])
    hist: dict[str, int] = {}
    for s in statuses:
        hist[str(s)] = hist.get(str(s), 0) + 1
    success = sum(1 for s in statuses if s is not None and 200 <= s < 300)
    return {
        "sent": n, "success_2xx": success, "status_histogram": hist,
        "verdict": "review" if success > 1 else "no_race_signal",
        "detail": (f"{success}/{n} parallel requests returned 2xx — if this action is meant to be "
                   "one-time (coupon, vote, withdrawal, invite, signup), that is a race-condition "
                   "limit bypass; confirm the side effect happened more than once"
                   if success > 1 else "at most one parallel request succeeded — no race signal"),
    }


def query_keys(url: str) -> list[str]:
    """The query-parameter names present in *url* (for auto-targeting)."""

    return [k for k, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)]
