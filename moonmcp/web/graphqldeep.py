"""Deeper GraphQL probing — batch abuse, field-suggestion recovery, nested BOLA.

`graphql_check` finds the endpoint and tests introspection; this goes further into
the classes that pay out even when introspection is *disabled*:

* **Batch-query abuse** — send an array of queries in one request. If the server
  returns an array of results, batching is on: a rate-limit / brute-force
  amplifier (one HTTP request = N logical operations), and the enabler for
  batched-login credential stuffing.
* **Field-suggestion schema recovery** — graphql-js and friends answer a typo'd
  field with *"Did you mean …?"*. That leaks real field/type names **without
  introspection** — a schema-recovery oracle. We fire a deliberate typo and read
  the suggestions back.
* **Aliases** — the endpoint honouring aliased fields (`a: x b: x`) is the second
  amplification/enumeration primitive (many operations per document).
* **Nested traversal (BOLA)** — surfaced as a lead: object relations reachable in
  one query (`me { orders { owner { email } } }`) are where GraphQL BOLA lives;
  confirm with authz once the schema (introspection or suggestions) is known.

All detection-only — benign queries, small batch, no mutations. Weaponisation
(credential stuffing, full schema clairvoyance, the BOLA PoC) is delegated to Strix.

Sources: https://portswigger.net/web-security/graphql · https://lab.wallarm.com/graphql-batching-attack/
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from ..net.http import HttpClient

_TYPENAME = "{__typename}"
# A deliberate typo of __typename — a GraphQL server with suggestions on answers
# "Did you mean \"__typename\"?", proving the schema-recovery oracle.
_TYPO_QUERY = json.dumps({"query": "{__typenamee}"})
_ALIAS_QUERY = json.dumps({"query": "{a:__typename b:__typename}"})

_SUGGEST_RE = re.compile(r"Did you mean (.+?)(?:\?|$)", re.IGNORECASE)
# Names are quote-wrapped; in a raw JSON error body the quotes are backslash-escaped
# (\"name\"), so tolerate an optional backslash on each side.
_NAME_RE = re.compile(r"""\\?["'`]([A-Za-z_][A-Za-z0-9_]*)\\?["'`]""")


def build_batch(query: str, n: int) -> bytes:
    """A JSON array of *n* identical GraphQL operations (pure)."""

    return json.dumps([{"query": query} for _ in range(max(2, n))]).encode()


def parse_batch_response(text: str, n: int) -> dict:
    """Did the server honour a batch? → ``{batched, count}`` (pure). A batched
    server returns a JSON *array* of per-operation results."""

    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return {"batched": False, "count": 0}
    if isinstance(data, list) and len(data) >= 2:
        results = sum(1 for d in data if isinstance(d, dict) and ("data" in d or "errors" in d))
        return {"batched": results >= 2, "count": len(data)}
    return {"batched": False, "count": 0}


def parse_suggestions(text: str) -> list[str]:
    """Field/type names leaked by *"Did you mean …"* errors (pure, de-duped)."""

    out: list[str] = []
    for m in _SUGGEST_RE.finditer(text or ""):
        for nm in _NAME_RE.finditer(m.group(1)):
            out.append(nm.group(1))
    return list(dict.fromkeys(out))


@dataclass
class GraphQLDeepResult:
    url: str
    is_graphql: bool = False
    batching: dict = field(default_factory=dict)
    aliases_enabled: bool = False
    suggestions_enabled: bool = False
    recovered_names: list[str] = field(default_factory=list)
    leads: list[dict] = field(default_factory=list)
    review: list[str] = field(default_factory=list)
    error: str | None = None


async def _post(client: HttpClient, url: str, body: bytes, scope_check, timeout: float):
    return await client.fetch(url, method="POST",
                              headers={"Content-Type": "application/json"}, body=body,
                              follow_redirects=False, timeout=timeout, scope_check=scope_check)


async def deep_probe(client: HttpClient, url: str, *, scope_check=None,
                     batch_n: int = 5, timeout: float = 12.0) -> GraphQLDeepResult:
    """Run the batch / suggestion / alias probes against a known GraphQL *url*."""

    res = GraphQLDeepResult(url=url)

    # sanity: is it a GraphQL endpoint at all?
    base = await _post(client, url, json.dumps({"query": _TYPENAME}).encode(), scope_check, timeout)
    if base.status is None:
        res.error = base.error or "no response"
        return res
    btext = base.text(limit=20_000)
    if not ('"__typename"' in btext or ('"data"' in btext or '"errors"' in btext)):
        res.review.append("Endpoint did not answer a GraphQL query — run graphql_check to locate one.")
        return res
    res.is_graphql = True

    # 1) batch abuse
    batch = await _post(client, url, build_batch(_TYPENAME, batch_n), scope_check, timeout)
    if batch.status is not None:
        res.batching = parse_batch_response(batch.text(limit=50_000), batch_n)
        if res.batching.get("batched"):
            res.leads.append({
                "kind": "graphql_batching", "severity": "medium",
                "detail": (f"Query batching is enabled ({res.batching['count']} operations honoured in "
                           "one request) — a rate-limit / brute-force amplifier (e.g. batched-login "
                           "credential stuffing, OTP/2FA brute force). Confirm against an auth mutation "
                           "via Strix.")})
            res.review.append("Batching ON → rate-limit bypass surface; test on login/OTP mutations.")

    # 2) field-suggestion schema recovery (works even with introspection OFF)
    typo = await _post(client, url, _TYPO_QUERY.encode(), scope_check, timeout)
    if typo.status is not None:
        names = parse_suggestions(typo.text(limit=20_000))
        if names:
            res.suggestions_enabled = True
            res.recovered_names = names
            res.leads.append({
                "kind": "graphql_field_suggestions", "severity": "low",
                "detail": (f"Field-suggestion errors are enabled — a typo leaked real names "
                           f"({', '.join(names[:8])}). This recovers the schema even when introspection "
                           "is disabled (clairvoyance). Disable suggestions in production.")})
            res.review.append("Field suggestions ON → schema recoverable without introspection.")

    # 3) aliases (second amplification primitive)
    alias = await _post(client, url, _ALIAS_QUERY.encode(), scope_check, timeout)
    if alias.status is not None:
        try:
            data = json.loads(alias.text(limit=20_000))
            d = (data.get("data") if isinstance(data, dict) else None) or {}
            res.aliases_enabled = "a" in d and "b" in d
        except (json.JSONDecodeError, ValueError, AttributeError):
            res.aliases_enabled = False
        if res.aliases_enabled:
            res.review.append("Aliases honoured → many operations per document (amplification/enum).")

    # 4) nested BOLA guidance (lead, not an automated check)
    res.review.append(
        "BOLA: once you know the schema (introspection or the recovered names), test nested "
        "traversal to other users' objects — e.g. `node(id:\"…\") { ... }` or "
        "`me { orders { owner { email } } }` with another tenant's id — via access_control_check / Strix.")
    return res
