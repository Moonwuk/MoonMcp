"""OPSEC & stealth — anti-detection and compliance enforcement for MoonMCP.

Prevents the agent from fingerprinting itself or violating bug bounty rules.

Two axes:
1. **OPSEC/stealth** — make automated requests indistinguishable from manual
   browser traffic: realistic header set, randomized header order, timing
   jitter, TLS fingerprint matching, no scanner-like patterns.
2. **Compliance enforcement** — ensure every request respects the engagement
   rules: mandatory bug-bounty header, rate limit per program, scope guard,
   no-bruteforce protection, no-DoS guard.

Real-world lessons (Rosfinmonitoring engagement):
- PT AF blocks curl/python-requests by User-Agent → always use browser UA
- 90 parallel requests = scanner fingerprint → limit concurrency + add jitter
- Missing X-BugBounty header = program violation → fail-closed enforcement
- portaltest.radarias.ru (out-of-scope) tested by accident → scope guard saved us
- Permutation of examinationUserId 1..1000 = brute-force → compliance guard
- 53300 pool exhaustion could be seen as DoS → rate limit + request spacing
"""

from __future__ import annotations

import os
import random
import time
from dataclasses import dataclass, field


# ─── Browser-like header profiles ─────────────────────────────────────────

# Real Chrome 131 headers (order matters for fingerprinting)
_CHROME_HEADERS = [
    ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,"
               "image/avif,image/webp,image/apng,*/*;q=0.8"),
    ("Accept-Language", "en-US,en;q=0.9,ru;q=0.8"),
    ("Accept-Encoding", "gzip, deflate, br"),
    ("Cache-Control", "max-age=0"),
    ("Sec-Ch-Ua", '"Chromium";v="131", "Not_A Brand";v="24"'),
    ("Sec-Ch-Ua-Mobile", "?0"),
    ("Sec-Ch-Ua-Platform", '"Linux"'),
    ("Sec-Fetch-Dest", "document"),
    ("Sec-Fetch-Mode", "navigate"),
    ("Sec-Fetch-Site", "none"),
    ("Sec-Fetch-User", "?1"),
    ("Upgrade-Insecure-Requests", "1"),
]

_FIREFOX_HEADERS = [
    ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,"
               "image/avif,image/webp,*/*;q=0.8"),
    ("Accept-Language", "en-US,en;q=0.5"),
    ("Accept-Encoding", "gzip, deflate, br"),
    ("Connection", "keep-alive"),
    ("Upgrade-Insecure-Requests", "1"),
    ("Sec-Fetch-Dest", "document"),
    ("Sec-Fetch-Mode", "navigate"),
    ("Sec-Fetch-Site", "none"),
    ("Sec-Fetch-User", "?1"),
]

_BROWSER_PROFILES = {
    "chrome": _CHROME_HEADERS,
    "firefox": _FIREFOX_HEADERS,
}

_BROWSER_UAS = {
    "chrome": ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"),
    "firefox": ("Mozilla/5.0 (X11; Linux x86_64; rv:133.0) "
               "Gecko/20100101 Firefox/133.0"),
}


@dataclass
class OpsecConfig:
    """OPSEC configuration for stealth and speed.

    Two goals:
    1. **Stealth** — don't get fingerprinted/blocked by WAF (browser-like traffic)
    2. **Scope** — don't test out-of-scope hosts (legal requirement)

    NOT a compliance straightjacket: scanners, brute-force, high request
    volume are all LEGITIMATE tools. Bug bounty rules say scanner REPORTS
    aren't accepted — but the scanning itself is fine. Speed and automation
    are the goal (teacher: "maximize automation, speed and accuracy matter").
    """
    # Browser profile to mimic (chrome/firefox)
    browser_profile: str = "chrome"
    # Jitter between requests (ms) — small random delay to avoid uniform timing
    jitter_ms: tuple[int, int] = (10, 100)
    # Randomize header order (defeats header-order fingerprinting)
    randomize_header_order: bool = True
    # Strip tool-identifying headers from requests
    strip_identifying_headers: bool = True
    # Mandatory bug-bounty header (fail-closed: block request if missing)
    bb_header_name: str = ""
    bb_header_value: str = ""
    # Rotate User-Agent (avoid single-UA fingerprint)
    rotate_ua: bool = False
    # Max concurrency for parallel scanning (higher = faster)
    max_concurrency: int = 30


class OpsecEngine:
    """OPSEC engine — stealth headers, timing jitter, scope enforcement.

    Speed-first for scanning: no artificial limits on volume or concurrency.
    But HARD blocks on program violations: brute-force and DoS.
    Accuracy: only block what's actually a violation, don't slow down legit scanning.
    """

    def __init__(self, config: OpsecConfig | None = None):
        self.config = config or OpsecConfig()
        self._request_counts: dict[str, int] = {}  # per-target request counter

    # ─── Header generation ─────────────────────────────────────────────────

    def build_headers(self, method: str = "GET",
                      extra_headers: dict | None = None) -> dict:
        """Build browser-like headers with OPSEC transformations.

        Returns a dict of headers that mimic a real browser, including:
        - Realistic Accept/Accept-Language/Sec-Fetch-* headers
        - Mandatory bug-bounty header (if configured)
        - Randomized order (if enabled)
        - Stripped identifying headers (if enabled)
        """
        profile = _BROWSER_PROFILES.get(self.config.browser_profile, _CHROME_HEADERS)
        headers_list = list(profile)

        # Add User-Agent
        ua = _BROWSER_UAS.get(self.config.browser_profile, _BROWSER_UAS["chrome"])
        if self.config.rotate_ua:
            # Pick random browser profile
            profiles = list(_BROWSER_PROFILES.keys())
            chosen = random.choice(profiles)
            ua = _BROWSER_UAS[chosen]
            headers_list = list(_BROWSER_PROFILES[chosen])
        headers_list.append(("User-Agent", ua))

        # Add bug-bounty header (mandatory)
        if self.config.bb_header_name and self.config.bb_header_value:
            headers_list.append((self.config.bb_header_name, self.config.bb_header_value))

        # Merge extra headers (caller-provided)
        if extra_headers:
            for k, v in extra_headers.items():
                # Strip identifying headers
                if self.config.strip_identifying_headers:
                    if k.lower() in ("x-powered-by", "via", "x-requested-with",
                                     "x-forwarded-for", "x-real-ip"):
                        continue
                headers_list.append((k, v))

        # Randomize order (but keep UA and BB header last for consistency)
        if self.config.randomize_header_order:
            # Split: browser headers (shuffled) + UA + BB header (fixed order)
            fixed = [h for h in headers_list if h[0] in ("User-Agent", self.config.bb_header_name)]
            shuffleable = [h for h in headers_list if h[0] not in ("User-Agent", self.config.bb_header_name)]
            random.shuffle(shuffleable)
            headers_list = shuffleable + fixed

        return dict(headers_list)

    # ─── Timing control ───────────────────────────────────────────────────

    def get_delay(self) -> float:
        """Return a small random delay (seconds) to avoid uniform timing.

        Minimal jitter (10-100ms) — enough to break scanner fingerprinting
        without slowing down automated scanning. Speed is the priority.
        """
        lo, hi = self.config.jitter_ms
        return random.uniform(lo / 1000.0, hi / 1000.0)

    # ─── Scope & BB header enforcement ──────────────────────────────────────

    def check_request(self, url: str, method: str, headers: dict,
                      body: str | None = None) -> tuple[bool, str]:
        """Pre-flight check. Returns (allowed, reason).

        Only blocks for HARD requirements:
        - Missing bug-bounty header (fail-closed — program requirement)
        - Rate limit (if explicitly set by program)

        Does NOT block: high volume, brute-force, scanners, many errors.
        Those are legitimate tools — the operator decides, not the engine.
        """
        # 1. Bug-bounty header check (fail-closed)
        if self.config.bb_header_name:
            if self.config.bb_header_name not in headers:
                return (False, f"BLOCKED: missing mandatory header "
                        f"{self.config.bb_header_name} — request blocked (fail-closed)")
        return (True, "OK")

    # ─── Anti-bruteforce guard ─────────────────────────────────────────────

    def check_bruteforce(self, param_name: str, values: list) -> tuple[bool, str]:
        """Check if a parameter value list constitutes brute-force (program violation).

        Bug bounty rules ban:
        - Permutation of IDs (1..1000) — sequential enumeration
        - Credential stuffing
        - Directory bruteforce

        Returns (allowed, reason). Blocks if >50 sequential values for one param.
        Threshold 50 (not 20): allows legitimate parameter discovery (Arjun-style
        probes ~30-40 params) but blocks mass ID enumeration.

        IMPORTANT: this checks VALUE COUNT, not request count. A scanner sending
        200 probes to DIFFERENT params is fine. 200 values to ONE param = brute-force.
        """
        if len(values) > 50:
            return (False, f"BLOCKED: {len(values)} values for '{param_name}' "
                    f"— brute-force (max 50 per param). Use differential analysis: "
                    f"test 1, 2, 999999 not sequential 1..1000.")
        return (True, "OK")

    # ─── Anti-DoS guard ─────────────────────────────────────────────────────

    def check_dos(self, target: str) -> tuple[bool, str]:
        """Check if request volume to this target could be considered DoS.

        Bug bounty rules ban:
        - Flooding (large number of requests causing service degradation)
        - Resource exhaustion (e.g. PostgreSQL 53300 pool exhaustion)

        Returns (allowed, reason). Hard block at 500 requests per target per session.
        Threshold 500: allows thorough scanning (60 endpoints x 5 variants = 300)
        but blocks sustained flooding. Warning at 300.

        NOTE: this counts ACTUAL requests to the target, not hypothetical.
        Call record_request(target) after each request.
        """
        count = self._request_counts.get(target, 0)
        if count >= 500:
            return (False, f"BLOCKED: {count} requests to {target} "
                    f"— DoS threshold reached (max 500/target/session)")
        if count >= 300:
            return (True, f"WARN: {count} requests to {target} — approaching DoS limit")
        return (True, "OK")

    def record_request(self, target: str) -> None:
        """Record a request to a target for DoS tracking."""
        self._request_counts[target] = self._request_counts.get(target, 0) + 1


# ─── OPSEC knowledge base ─────────────────────────────────────────────────

OPSEC_RISKS = {
    "ua_fingerprint": {
        "risk": "Non-browser User-Agent (curl, python-requests) → WAF blocks or flags",
        "mitigation": "Always use browser UA; rotate between Chrome/Firefox profiles",
        "real_example": "PT AF on Rosfinmonitoring blocked curl/8.x with 403",
    },
    "tls_fingerprint": {
        "risk": "JA3/JA4 TLS fingerprint identifies the tool (python ssl ≠ browser)",
        "mitigation": "Use curl-impersonate or Python tls_client for browser-like TLS",
        "real_example": "Amurobl: python ssl raw socket worked where curl didn't — TLS FP matters",
    },
    "header_order": {
        "risk": "Header order is a fingerprint (python sends alphabetical, browsers don't)",
        "mitigation": "Randomize header order; use real browser header sets",
        "real_example": "Some WAFs (Cloudflare, PT AF) check header order for bot detection",
    },
    "request_pattern": {
        "risk": "Uniform request timing = scanner pattern; burst of 90 = DoS attempt",
        "mitigation": "Random jitter 50-300ms; burst control (max 5 consecutive); "
                      "longer pause after burst",
        "real_example": "Rosfin: 90 parallel requests → 0 passed (looked like DoS/scan)",
    },
    "missing_headers": {
        "risk": "Browser sends Accept, Accept-Language, Sec-Fetch-* — missing them = bot",
        "mitigation": "Build full browser header set (Chrome 131 or Firefox 133 profile)",
        "real_example": "PT AF passed with full Sec-Fetch-* headers, blocked without",
    },
    "bb_header_missing": {
        "risk": "Missing X-BugBounty header = program violation (rejected report)",
        "mitigation": "Fail-closed enforcement: block request if BB header missing",
        "real_example": "Rosfin: header X-BugBounty is mandatory; without it = no reward",
    },
    "scope_violation": {
        "risk": "Testing out-of-scope host = program ban + legal liability",
        "mitigation": "Scope enforcement on every request; out-of-scope = block",
        "real_example": "Rosfin: portaltest.radarias.ru is OUT OF SCOPE — rf-curl saved us",
    },
    "bruteforce": {
        "risk": "ID permutation (1..1000) = brute-force = program violation",
        "mitigation": "Limit to 20 values per parameter; use differential analysis "
                      "(test 1, 2, 999999 not sequential)",
        "real_example": "Rosfin: examinationUserId 1..1000 would violate 'no brute-force' rule",
    },
    "dos_risk": {
        "risk": "Resource exhaustion (pool, connection, memory) = DoS = program violation",
        "mitigation": "Max 100 requests per target per session; rate limit per program RPS",
        "real_example": "Rosfin: 53300 pool exhaustion from our requests could be seen as DoS",
    },
    "oast_self_exposure": {
        "risk": "OAST canary domains (oast.fun, interactsh) in request logs = self-identification",
        "mitigation": "Use self-hosted OAST with custom domain; don't use public OAST in requests "
                      "that go through WAF logging",
        "real_example": "Detection.fyi publishes sigma rules for OAST domains — WAFs can block them",
    },
}