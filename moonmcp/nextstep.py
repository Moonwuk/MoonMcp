"""Standardised "what to run next" hints for the detection probes.

Every detector emits a verdict, but an agent still has to *decide the next move*.
This module centralises that decision: given a probe and its verdict, it names the
concrete MoonMCP tool(s) to run next — confirm the lead, escalate to the OOB
channel, or pivot to the related class. Probes attach the result as a
``suggested_next`` field so the agent chains without re-reasoning.

Only *positive* verdicts get a suggestion — a clean/unconfirmed result returns an
empty list so it adds no noise. `interp_probe` computes its own dynamic
``suggested_next`` from which markers fired and is intentionally not routed here.
"""

from __future__ import annotations

# tool -> the tool(s) to run next when it surfaces something worth chasing.
AFTER: dict[str, list[str]] = {
    # injection classes → prove it differentially (confirm_finding), then weaponise
    # elsewhere (sqlmap/Strix) under human confirmation.
    "sqli_probe": ["confirm_finding"],
    "cmdi_probe": ["confirm_finding"],
    "ssti_probe": ["confirm_finding"],
    "lfi_probe": ["confirm_finding"],
    "nosqli_probe": ["confirm_finding"],
    "xxe_probe": ["oast_poll", "confirm_finding"],
    # SSRF → poll the callback, then reach for the deeper SSRF lanes.
    "ssrf_probe": ["oast_poll", "ssrf_metadata_probe", "ssrf_protocol_probe"],
    # GraphQL → escalate from discovery to the attack probes.
    "graphql_check": ["graphql_probe", "graphql_nosqli"],
    "graphql_probe": ["graphql_nosqli", "authz_probe"],
    # a captured JWT → the offline-forge / key-injection battery.
    "jwt_analyze": ["jwt_crack", "jwt_alg_confusion", "jwt_jku_probe"],
    # recon → orient and expand surface.
    "fingerprint": ["plan_target"],
    "crawl": ["discover_parameters", "analyze_js", "plan_target"],
}

# Verdicts that mean "there's something here" — anything else adds no suggestion.
_POSITIVE = frozenset({"confirmed", "likely", "corroborated", "review", "weak"})
_NEGATIVE = frozenset({"unconfirmed", "none", "inconclusive", "unlikely", ""})


def after(tool: str, verdict: str | None = None) -> list[str]:
    """The tool(s) to run next after *tool* given its *verdict* (pure).

    Returns the mapped chain when *verdict* is None (verdict-agnostic caller) or a
    positive signal; returns ``[]`` for a negative/clean verdict so a
    nothing-found result stays quiet. Unknown tools return ``[]``."""

    if verdict is not None and verdict.strip().lower() not in _POSITIVE:
        return []
    return list(AFTER.get(tool, []))


def referenced_tools() -> set[str]:
    """Every tool name this module can point at (keys + values) — lets a test
    assert the map never drifts to a non-existent tool."""

    out = set(AFTER)
    for nxts in AFTER.values():
        out.update(nxts)
    return out
