"""JWT decoding & weakness triage (no signature verification).

Given a JWT, decode the header and claims and flag the well-known danger signs:
``alg: none``, a symmetric alg (HS256) that may be brute-forceable, missing
expiry, and already-expired / not-yet-valid tokens.  Pure parsing — sends no
traffic, so it is not scope-gated.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field


@dataclass
class JwtAnalysis:
    valid_structure: bool
    header: dict = field(default_factory=dict)
    payload: dict = field(default_factory=dict)
    algorithm: str | None = None
    issues: list[str] = field(default_factory=list)
    error: str | None = None


def _b64url_decode(segment: str) -> bytes:
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)


def analyze_jwt(token: str, now_epoch: int | None = None) -> JwtAnalysis:
    token = token.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    parts = token.split(".")
    if len(parts) not in (2, 3):
        return JwtAnalysis(valid_structure=False, error="not a JWT (expected 2 or 3 dot-separated parts)")
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        return JwtAnalysis(valid_structure=False, error=f"undecodable segment: {exc}")

    analysis = JwtAnalysis(valid_structure=True, header=header, payload=payload)
    alg = str(header.get("alg", "")) or None
    analysis.algorithm = alg

    if alg and alg.lower() == "none":
        analysis.issues.append("CRITICAL: alg=none — signature is not verified; token forgeable")
    if alg and alg.upper().startswith("HS"):
        analysis.issues.append(f"{alg} is symmetric — vulnerable if the secret is weak/guessable (offline crack)")
    if len(parts) == 3 and parts[2] == "":
        analysis.issues.append("empty signature segment")
    if "exp" not in payload:
        analysis.issues.append("no 'exp' claim — token may never expire")
    if header.get("jku") or header.get("x5u"):
        analysis.issues.append("header references a remote key (jku/x5u) — potential key-injection (SSRF) surface")
    if header.get("kid"):
        analysis.issues.append("'kid' header present — check for path traversal / SQLi in key selection")

    if now_epoch is not None:
        exp = payload.get("exp")
        nbf = payload.get("nbf")
        if isinstance(exp, (int, float)) and exp < now_epoch:
            analysis.issues.append("token is EXPIRED")
        if isinstance(nbf, (int, float)) and nbf > now_epoch:
            analysis.issues.append("token is not yet valid (nbf in the future)")
    return analysis
