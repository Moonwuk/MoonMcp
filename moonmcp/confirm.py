"""Finding-confirmation logic — turn a lead into a verdict.

Pure scoring over observable signals so it is trivially testable; the server tool
gathers the signals (differential responses, reflection, injection signatures,
out-of-band callbacks, timing) and passes them in. This is MoonMCP's cheap
"prove it before you report it" gate: differential + out-of-band + signatures,
the same discipline the operator prompts demand.
"""

from __future__ import annotations


def evaluate(*, reflected: bool = False, status_changed: bool = False,
             length_delta: int = 0, injection_hits: list[str] | None = None,
             oast_count: int = 0, timing_delta_ms: float = 0.0) -> dict:
    """Weigh confirmation signals into a verdict.

    Strong confirmation = an out-of-band callback fired, or an injection signature
    matched in a response the payload provably changed. Everything else is a lead
    of varying strength, never an assertion.
    """

    hits = injection_hits or []
    signals: list[str] = []
    score = 0
    if oast_count:
        signals.append(f"out-of-band callback fired ({oast_count} interaction(s)) — blind execution")
        score += 5
    if hits:
        signals.append(f"injection signatures matched: {', '.join(hits[:5])}")
        score += 3
    if reflected:
        signals.append("payload reflected in the response (and not in the baseline)")
        score += 2
    if status_changed:
        signals.append("status code changed vs the baseline")
        score += 1
    if length_delta:
        signals.append(f"response length changed by {length_delta:+d} bytes vs baseline")
        score += 1
    if timing_delta_ms > 3000:
        signals.append(f"response ~{int(timing_delta_ms)}ms slower than baseline — possible time-based")
        score += 2

    strong = bool(oast_count) or (bool(hits) and reflected)
    if strong:
        verdict, confidence = "confirmed", "high"
    elif score >= 3:
        verdict, confidence = "likely", "medium"
    elif score >= 1:
        verdict, confidence = "inconclusive", "low"
    else:
        verdict, confidence = "unconfirmed", "low"

    return {"verdict": verdict, "confidence": confidence, "score": score,
            "signals": signals}
