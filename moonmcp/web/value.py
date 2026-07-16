"""Value / financial-logic manipulation — money-aware tampering the app must reject.

A focused, money-literate cousin of ``logic_probe``: it targets the fields that carry
*value* (amount, price, balance, coupon, voucher, gift-card, currency, points) and
sends the manipulations a correct server must reject — **negative** amounts (negative
top-up / refund-to-self), **zero**, integer **overflow**, sub-cent **precision**
rounding, **>100 % discount**, **currency swap/downgrade**, and single-use **coupon
reuse**. A should-be-invalid value accepted like the valid baseline is a value-logic
lead (verdict ``review`` — confirm the charged/credited amount server-side).

Reuses ``logic.assess_tamper`` (accepted-like-baseline) and ``inject.with_param`` so
there is one implementation of the request/verdict mechanics. Findings are leads.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from .inject import with_param
from .logic import assess_tamper

# Fields that carry monetary / redeemable value.
MONEY_FIELD_RE = re.compile(
    r"(amount|price|total|subtotal|sum|cost|fee|balance|credit|wallet|points|"
    r"discount|coupon|voucher|promo|gift|card|qty|quantity|value|charge|refund|"
    r"payout|withdraw|deposit|topup|top_up|cashback|reward|token_amount)", re.I)
# Fields that carry a currency code.
CURRENCY_FIELD_RE = re.compile(r"^(currency|curr|ccy|cur|money_code|fiat)$", re.I)
# Fields that carry a single-use redemption code.
COUPON_FIELD_RE = re.compile(r"(coupon|voucher|promo|gift.?card|discount_code|redeem|code)", re.I)

# Money manipulations by category; a correct server should reject each on a value field.
VALUE_PAYLOADS: dict[str, list[str]] = {
    "negative": ["-1", "-100", "-0.01"],
    "zero": ["0", "0.00"],
    "overflow": ["999999999", "9e9", "1e10", "99999999999999999999"],
    "precision": ["0.001", "0.005", "1.999999"],
    "over_100_percent": ["101", "1000"],
    "type_confusion": ["0x10", "1e2", "1,00"],
}
# Alternative / mismatched / invalid currency codes to swap in.
CURRENCY_SWAPS: list[str] = ["XXX", "IDR", "VND", "ZWL", "usd", "US", "'"]

# Categories whose acceptance is high severity (direct money loss).
_HIGH = {"negative", "over_100_percent"}


def money_fields(keys) -> list[str]:
    return [k for k in keys if MONEY_FIELD_RE.search(k)]


def currency_fields(keys) -> list[str]:
    return [k for k in keys if CURRENCY_FIELD_RE.match(k)]


def coupon_fields(keys) -> list[str]:
    return [k for k in keys if COUPON_FIELD_RE.search(k)]


async def _baseline(client, url, field, value, m, scope_check):
    bu, bb = with_param(url, field, value, m)
    r = await client.fetch(bu, method=m, body=bb, follow_redirects=False,
                           timeout=12.0, scope_check=scope_check)
    return r


async def probe_value_tampering(client, url: str, field: str, *, method: str = "GET",
                                scope_check: Callable[[str], bool] | None = None) -> list[dict]:
    """Send a valid baseline then each money manipulation; flag the accepted ones."""

    m = method.upper()
    base = await _baseline(client, url, field, "1", m, scope_check)
    if base.status is None:
        return []
    blen = len(base.body)
    # Negative control: if a garbage value is accepted like the baseline, the field
    # isn't validated → every value flag would be a false positive → bail.
    ctrl = await _baseline(client, url, field, "moonmcp_zzz_invalid", m, scope_check)
    if assess_tamper(base.status, blen, ctrl.status, len(ctrl.body)):
        return []
    findings: list[dict] = []
    for category, payloads in VALUE_PAYLOADS.items():
        for val in payloads:
            u, b = with_param(url, field, val, m)
            r = await client.fetch(u, method=m, body=b, follow_redirects=False,
                                   timeout=12.0, scope_check=scope_check)
            if assess_tamper(base.status, blen, r.status, len(r.body)):
                findings.append({
                    "kind": "value_tampering", "field": field, "category": category, "value": val,
                    "severity": "high" if category in _HIGH else "medium", "verdict": "review",
                    "detail": f"{field}={val} ({category}) was accepted like the valid baseline "
                              f"(HTTP {r.status}) — value manipulation; verify the charged/credited "
                              "amount server-side",
                })
                break  # one accepted payload per category is enough signal
    return findings


async def probe_currency_swap(client, url: str, field: str, *, base_value: str = "USD",
                              method: str = "GET",
                              scope_check: Callable[[str], bool] | None = None) -> list[dict]:
    """Swap the currency code to alternate/invalid values; flag accepted swaps."""

    m = method.upper()
    base = await _baseline(client, url, field, base_value, m, scope_check)
    if base.status is None:
        return []
    blen = len(base.body)
    # Negative control (mirrors probe_value_tampering): if a garbage currency is
    # accepted like the base, the field doesn't validate the currency at all, so every
    # swap would be a false "confusion" → bail. A real endpoint rejects the garbage.
    ctrl = await _baseline(client, url, field, "moonmcp_zzz", m, scope_check)
    if ctrl.status is not None and assess_tamper(base.status, blen, ctrl.status, len(ctrl.body)):
        return []
    findings: list[dict] = []
    for cur in CURRENCY_SWAPS:
        if cur.upper() == base_value.upper():
            continue
        u, b = with_param(url, field, cur, m)
        r = await client.fetch(u, method=m, body=b, follow_redirects=False,
                               timeout=12.0, scope_check=scope_check)
        if assess_tamper(base.status, blen, r.status, len(r.body)):
            findings.append({
                "kind": "currency_swap", "field": field, "currency": cur,
                "severity": "medium", "verdict": "review",
                "detail": f"currency '{cur}' was accepted with the same amount as '{base_value}' — "
                          "currency confusion / value manipulation; verify the amount actually charged",
            })
    return findings


async def probe_coupon_reuse(client, url: str, field: str, code: str, *, times: int = 3,
                             method: str = "POST",
                             scope_check: Callable[[str], bool] | None = None) -> dict:
    """Apply the same single-use code sequentially; >1 success = reuse/stacking."""

    m = method.upper()
    n = max(2, min(times, 5))
    statuses: list[int | None] = []
    for _ in range(n):
        u, b = with_param(url, field, code, m)
        r = await client.fetch(u, method=m, body=b, follow_redirects=False,
                               timeout=12.0, scope_check=scope_check)
        statuses.append(r.status)
    successes = sum(1 for s in statuses if s is not None and 200 <= s < 300)
    return {
        "kind": "coupon_reuse", "field": field, "code": code, "applied": n,
        "successes": successes, "statuses": statuses,
        "verdict": "review" if successes > 1 else "no_reuse_signal",
        "detail": (f"the same code '{code}' was accepted {successes}× in sequence — if it is "
                   "single-use (coupon/gift-card/voucher), that is reuse/stacking; confirm the "
                   "discount/credit applied more than once" if successes > 1
                   else "the code was accepted at most once — no reuse signal"),
    }
