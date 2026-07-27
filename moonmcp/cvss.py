"""CVSS 3.1 base-score calculator (pure, stdlib).

Turns a metric set — or a vector string like
``AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`` — into a base score + severity band, so a
confirmed finding can carry a defensible, standard severity instead of a guess.
Implements the official CVSS 3.1 base formula, including the exact ``Roundup``.
"""

from __future__ import annotations

import math

# metric -> code -> weight
_WEIGHTS: dict[str, dict[str, float]] = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
# Privileges Required depends on Scope.
_PR = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.5},
}
_DEFAULTS = {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
             "C": "N", "I": "N", "A": "N"}
_ORDER = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def parse_vector(vector: str) -> dict[str, str]:
    """Parse a ``AV:N/AC:L/...`` vector (with or without a ``CVSS:3.1/`` prefix)
    into ``{metric: code}``. Unknown metrics are ignored."""

    out: dict[str, str] = {}
    for part in (vector or "").split("/"):
        if ":" not in part:
            continue
        k, v = part.split(":", 1)
        k, v = k.strip().upper(), v.strip().upper()
        if k in _ORDER:
            out[k] = v
    return out


def _roundup(x: float) -> float:
    """The official CVSS 3.1 Roundup: round up to one decimal place."""

    i = round(x * 100000)
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def severity_band(score: float) -> str:
    if score <= 0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def base_score(metrics: dict[str, str] | None = None, *, vector: str | None = None) -> dict:
    """Compute the CVSS 3.1 base score. Provide ``metrics`` (codes) and/or a
    ``vector`` string; missing metrics default to a conservative low-impact base
    (``C/I/A = N``). Returns score, severity, the normalised vector, and metrics."""

    m = dict(_DEFAULTS)
    if vector:
        m.update(parse_vector(vector))
    if metrics:
        m.update({k.upper(): str(v).upper() for k, v in metrics.items() if k.upper() in _ORDER})

    scope = m["S"] if m["S"] in ("U", "C") else "U"
    try:
        av = _WEIGHTS["AV"][m["AV"]]
        ac = _WEIGHTS["AC"][m["AC"]]
        ui = _WEIGHTS["UI"][m["UI"]]
        pr = _PR[scope][m["PR"]]
        c = _WEIGHTS["C"][m["C"]]
        i = _WEIGHTS["I"][m["I"]]
        a = _WEIGHTS["A"][m["A"]]
    except KeyError as exc:
        raise ValueError(f"invalid CVSS metric value: {exc}") from exc

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope == "U":
        impact = 6.42 * iss
    else:
        # CVSS 3.1 modified-impact term. (CVSS 3.0 used (iss-0.02)**15 — a different
        # curve that under-scores Scope:Changed vectors and can drop a severity band.)
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss * 0.9731 - 0.02) ** 13
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        score = 0.0
    elif scope == "U":
        score = _roundup(min(impact + exploitability, 10.0))
    else:
        score = _roundup(min(1.08 * (impact + exploitability), 10.0))

    norm_vector = "CVSS:3.1/" + "/".join(f"{k}:{m[k]}" for k in _ORDER)
    return {"score": round(score, 1), "severity": severity_band(score),
            "vector": norm_vector, "metrics": {k: m[k] for k in _ORDER}}
