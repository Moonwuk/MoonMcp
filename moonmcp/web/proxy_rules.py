"""HTTP interception proxy **rule engine** — match & replace rules applied
to requests before they are sent by ``http_repeater`` / ``intruder``.

This is NOT a live HTTP proxy server.  It is a *rule engine*: you register
:class:`ProxyRule` objects with a :class:`ProxyRuleEngine`, then call
:meth:`ProxyRuleEngine.apply_rules` on a request dict (the same shape
``http_repeater`` / ``intruder`` accept) and get back a modified copy.

Rule types (``match_type``)
----------------------------
1. **add_header**  — unconditionally inject a header (e.g. ``X-BugBounty``)
   on every in-scope request.  No pattern match required.
2. **url**         — regex match & replace inside the full URL.
3. **body**        — regex match & replace inside the request body.
4. **header**      — match a header *name* (regex) and optionally replace
   its *value*, or add it if missing.
5. **method**      — match the HTTP method (exact) and replace it.
6. **redirect**    — intercept a 3xx response: if the response carries a
   ``Location`` matching ``match_pattern``, rewrite it to
   ``replace_pattern`` so the client follows an attacker-controlled URL.
7. **token**       — rotate a credential (header / cookie / bearer) —
   replace the current value with a fresh one from a callable.
8. **ua**          — User-Agent spoofing — shortcut for ``add_header`` /
   ``replace_header`` targeting ``User-Agent``.

The engine is pure-Python, synchronous, stateless w.r.t. the network —
it never opens a socket; callers feed it request dicts and consume the
output.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

# ─── data model ──────────────────────────────────────────────────────

@dataclass
class ProxyRule:
    """A single match & replace rule.

    Attributes
    ----------
    id : str
        Unique rule identifier (auto-generated if empty).
    match_type : str
        One of: ``add_header``, ``url``, ``body``, ``header``, ``method``,
        ``redirect``, ``token``, ``ua``.
    match_pattern : str
        Regex pattern (for ``url`` / ``body`` / ``header`` / ``redirect``)
        or exact string (for ``method``).  Ignored for ``add_header``.
    replace_pattern : str
        Replacement string (supports ``\\1`` backrefs for regex rules).
        For ``add_header`` this is the *header value*.
    header_name : str
        Header name for ``add_header`` / ``ua`` rules.  Defaults derived
        from ``match_type`` when possible.
    scope_filter : str
        Optional hostname / URL-prefix filter — the rule only fires when
        the request URL starts with (or host matches) this string.
    enabled : bool
        Toggle the rule without removing it.
    priority : int
        Lower numbers fire first (default 0).
    token_provider : Callable[[], str] | None
        For ``token`` rules — a callable returning a fresh token value.
        When set, its return value overrides ``replace_pattern`` at apply
        time, enabling dynamic rotation.
    """

    id: str = ""
    match_type: str = "add_header"
    match_pattern: str = ""
    replace_pattern: str = ""
    header_name: str = ""
    scope_filter: str = ""
    enabled: bool = True
    priority: int = 0
    token_provider: Callable[[], str] | None = None

    def __post_init__(self) -> None:
        if not self.id:
            self.id = uuid.uuid4().hex[:12]
        self.match_type = self.match_type.lower().strip()
        # canonical header name for ua rules
        if self.match_type == "ua" and not self.header_name:
            self.header_name = "User-Agent"

    # ── helpers ──

    def matches_scope(self, url: str) -> bool:
        """Return True when *url* passes the scope filter (empty = match all)."""
        if not self.scope_filter:
            return True
        host = urlsplit(url).hostname or ""
        return (
            url.startswith(self.scope_filter)
            or host == self.scope_filter
            or host.endswith(self.scope_filter)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "match_type": self.match_type,
            "match_pattern": self.match_pattern,
            "replace_pattern": self.replace_pattern,
            "header_name": self.header_name,
            "scope_filter": self.scope_filter,
            "enabled": self.enabled,
            "priority": self.priority,
            "has_token_provider": self.token_provider is not None,
        }


# ─── rule engine ─────────────────────────────────────────────────────

class ProxyRuleEngine:
    """Ordered collection of :class:`ProxyRule` applied to request dicts.

    A *request dict* is the same shape used by ``http_repeater``::

        {
            "url": str,
            "method": str,
            "headers": dict[str, str],
            "body": str,
        }

    ``apply_rules`` returns a *new* dict (shallow copy with replaced
    fields) — the original is never mutated.
    """

    def __init__(self) -> None:
        self._rules: list[ProxyRule] = []

    # ── CRUD ──

    def add_rule(self, rule: ProxyRule) -> ProxyRule:
        """Register *rule* and return it (with a generated id)."""
        self._rules.append(rule)
        self._rules.sort(key=lambda r: r.priority)
        return rule

    def remove_rule(self, rule_id: str) -> bool:
        """Remove the rule with *rule_id*; return True if it existed."""
        before = len(self._rules)
        self._rules = [r for r in self._rules if r.id != rule_id]
        return len(self._rules) < before

    def list_rules(self, match_type: str | None = None) -> list[ProxyRule]:
        """Return all enabled+disabled rules, optionally filtered by type."""
        if match_type:
            mt = match_type.lower().strip()
            return [r for r in self._rules if r.match_type == mt]
        return list(self._rules)

    def get_rule(self, rule_id: str) -> ProxyRule | None:
        for r in self._rules:
            if r.id == rule_id:
                return r
        return None

    def clear(self) -> None:
        self._rules.clear()

    # ── application ──

    def apply_rules(
        self,
        request: dict[str, Any],
        *,
        response: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Apply all enabled, in-scope rules to *request*.

        If *response* is provided, ``redirect`` rules are also applied to
        its ``Location`` header.

        Returns a new request dict; the original is untouched.
        """
        req = dict(request)
        req.setdefault("headers", dict(request.get("headers", {})))
        # deep-ish copy headers so we don't mutate caller's dict
        req["headers"] = dict(req["headers"])
        req.setdefault("url", "")
        req.setdefault("method", "GET")
        req.setdefault("body", "")

        applied: list[str] = []

        for rule in self._rules:
            if not rule.enabled:
                continue
            if not rule.matches_scope(req["url"]):
                continue
            tag = self._apply_one(rule, req, response)
            if tag:
                applied.append(f"{rule.id}:{tag}")

        req["_applied_rules"] = applied  # metadata for debugging
        return req

    # ── per-rule dispatch ──

    def _apply_one(
        self,
        rule: ProxyRule,
        req: dict[str, Any],
        response: dict[str, Any] | None,
    ) -> str | None:
        """Apply a single rule to *req* (and *response* for redirect rules).

        Returns a short tag string describing what was done, or None.
        """
        mt = rule.match_type

        if mt == "add_header":
            name = rule.header_name or "X-BugBounty"
            req["headers"][name] = rule.replace_pattern
            return f"add_header:{name}"

        if mt == "ua":
            name = rule.header_name or "User-Agent"
            req["headers"][name] = rule.replace_pattern
            return f"ua:{name}"

        if mt == "url":
            if not rule.match_pattern:
                return None
            new_url, n = re.subn(
                rule.match_pattern, rule.replace_pattern, req["url"]
            )
            if n:
                req["url"] = new_url
                return f"url:{n}"

        if mt == "body":
            if not rule.match_pattern:
                return None
            new_body, n = re.subn(
                rule.match_pattern, rule.replace_pattern, req["body"]
            )
            if n:
                req["body"] = new_body
                return f"body:{n}"

        if mt == "header":
            if not rule.match_pattern:
                return None
            pat = re.compile(rule.match_pattern, re.IGNORECASE)
            changed = False
            for key in list(req["headers"]):
                if pat.search(key):
                    if rule.replace_pattern:
                        req["headers"][key] = rule.replace_pattern
                        changed = True
                    elif rule.header_name:
                        # rename header
                        req["headers"][rule.header_name] = req["headers"].pop(key)
                        changed = True
            if not changed and rule.replace_pattern and rule.header_name:
                # header not found — add it
                req["headers"][rule.header_name] = rule.replace_pattern
                return "header:added"
            return "header" if changed else None

        if mt == "method":
            if req["method"].upper() == rule.match_pattern.upper():
                req["method"] = rule.replace_pattern.upper()
                return f"method:{req['method']}"

        if mt == "redirect":
            if response is None:
                return None
            location = (
                response.get("headers", {}).get("Location")
                or response.get("headers", {}).get("location")
            )
            if not location or not rule.match_pattern:
                return None
            new_loc, n = re.subn(
                rule.match_pattern, rule.replace_pattern, location
            )
            if n:
                response["headers"]["Location"] = new_loc
                return f"redirect:{n}"

        if mt == "token":
            # Determine the current token location and rotate it
            new_val: str | None = None
            if rule.token_provider is not None:
                try:
                    new_val = rule.token_provider()
                except Exception:
                    new_val = None
            if new_val is None:
                new_val = rule.replace_pattern

            # Try Authorization: Bearer <token>
            auth = req["headers"].get("Authorization") or req["headers"].get("authorization")
            if auth:
                if auth.startswith("Bearer "):
                    req["headers"]["Authorization"] = f"Bearer {new_val}"
                    return "token:bearer"
                req["headers"]["Authorization"] = new_val
                return "token:auth"

            # Try cookie
            cookie = req["headers"].get("Cookie") or req["headers"].get("cookie")
            if cookie:
                req["headers"]["Cookie"] = new_val
                return "token:cookie"

            # Try a custom header name
            if rule.header_name:
                req["headers"][rule.header_name] = new_val
                return f"token:{rule.header_name}"

            # Fallback — set Authorization
            req["headers"]["Authorization"] = f"Bearer {new_val}"
            return "token:fallback"

        return None


# ─── convenience builders ────────────────────────────────────────────

def bugbounty_header_rule(value: str = "X-BugBounty-Research: authorized") -> ProxyRule:
    """Create the standard auto-add ``X-BugBounty`` header rule."""
    name, _, val = value.partition(":")
    return ProxyRule(
        match_type="add_header",
        header_name=name.strip(),
        replace_pattern=val.strip(),
        priority=-100,  # fire before everything else
    )


def ua_spoof_rule(ua: str) -> ProxyRule:
    """Create a User-Agent spoofing rule."""
    return ProxyRule(
        match_type="ua",
        replace_pattern=ua,
        priority=-50,
    )


def token_rotation_rule(
    provider: Callable[[], str],
    header_name: str = "",
) -> ProxyRule:
    """Create a token-rotation rule that calls *provider* on each apply."""
    return ProxyRule(
        match_type="token",
        token_provider=provider,
        replace_pattern="",  # provider takes precedence
        header_name=header_name,
        priority=-10,
    )


def url_rewrite_rule(pattern: str, replacement: str, scope: str = "") -> ProxyRule:
    """Create a URL match & replace rule."""
    return ProxyRule(
        match_type="url",
        match_pattern=pattern,
        replace_pattern=replacement,
        scope_filter=scope,
    )


def body_rewrite_rule(pattern: str, replacement: str, scope: str = "") -> ProxyRule:
    """Create a body match & replace rule."""
    return ProxyRule(
        match_type="body",
        match_pattern=pattern,
        replace_pattern=replacement,
        scope_filter=scope,
    )


def header_rewrite_rule(
    header_pattern: str,
    replacement: str = "",
    new_name: str = "",
    scope: str = "",
) -> ProxyRule:
    """Create a header match & replace rule."""
    return ProxyRule(
        match_type="header",
        match_pattern=header_pattern,
        replace_pattern=replacement,
        header_name=new_name,
        scope_filter=scope,
    )


def redirect_intercept_rule(pattern: str, replacement: str, scope: str = "") -> ProxyRule:
    """Create a redirect-interception rule (rewrites ``Location``)."""
    return ProxyRule(
        match_type="redirect",
        match_pattern=pattern,
        replace_pattern=replacement,
        scope_filter=scope,
    )


# ─── module-level singleton (used by server.py MCP tool) ─────────────

_default_engine: ProxyRuleEngine | None = None


def get_engine() -> ProxyRuleEngine:
    global _default_engine
    if _default_engine is None:
        _default_engine = ProxyRuleEngine()
    return _default_engine