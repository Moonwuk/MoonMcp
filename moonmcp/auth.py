"""Per-engagement authentication context.

Modern bug-bounty value concentrates *behind* a login — IDOR/BOLA, broken access
control, privilege escalation.  A single :class:`AuthContext` holds the custom
headers / cookies / bearer token for the current engagement; the HTTP client
merges it into every in-scope request so the web tools can test authenticated
surface.  Credentials only ever travel to in-scope hosts (the scope guard) and
are stripped on the anonymous leg of an access-control diff.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field


# Control characters that must never travel into an HTTP header value.
# Stripping CR/LF (and other C0 controls) on entry closes the header-injection
# vector at the single source of truth, instead of relying on urllib's late
# ValueError as the only defence (audit 2026-07-18, bug #7).
_CTRL = "".join(chr(i) for i in range(32)) + "\x7f"


def _sanitize_header_value(value: str) -> str:
    """Strip CR/LF and other C0 control chars from a header value."""
    return value.translate(str.maketrans("", "", _CTRL)).strip()


def _sanitize_header_name(name: str) -> str:
    """Header names are tokens — no controls, no whitespace, no separators."""
    return name.translate(str.maketrans("", "", _CTRL)).strip()


def _redact(value: str) -> str:
    v = value.strip()
    if len(v) <= 8:
        return "set"
    return f"{v[:4]}…{v[-2:]} ({len(v)} chars)"


@dataclass
class AuthContext:
    """Custom headers + cookies applied to every authenticated request."""

    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)

    def set_bearer(self, token: str) -> None:
        self.headers["Authorization"] = f"Bearer {_sanitize_header_value(token)}"

    def set_basic(self, username: str, password: str) -> None:
        u = _sanitize_header_value(username)
        p = _sanitize_header_value(password)
        raw = base64.b64encode(f"{u}:{p}".encode()).decode()
        self.headers["Authorization"] = f"Basic {raw}"

    def set_cookie_string(self, cookie: str) -> None:
        """Parse a raw ``k=v; k2=v2`` Cookie header into the cookie jar.

        CR/LF (and other C0 controls) are stripped from both keys and values on
        entry — a poisoned cookie value is a header-injection vector otherwise.
        """

        for part in cookie.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                k = _sanitize_header_name(k)
                v = _sanitize_header_value(v)
                if k:
                    self.cookies[k] = v

    def update_headers(self, headers: dict[str, str]) -> None:
        self.headers.update({
            _sanitize_header_name(str(k)): _sanitize_header_value(str(v))
            for k, v in headers.items()
        })

    def merged_headers(self) -> dict[str, str]:
        """The header dict to inject into a request (headers + a Cookie header)."""

        out = dict(self.headers)
        if self.cookies:
            jar = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            existing = out.get("Cookie")
            out["Cookie"] = f"{existing}; {jar}" if existing else jar
        return out

    def clear(self) -> None:
        self.headers.clear()
        self.cookies.clear()

    def is_set(self) -> bool:
        return bool(self.headers or self.cookies)

    def redacted(self) -> dict:
        """A safe-to-display view — credential values are masked."""

        return {
            "set": self.is_set(),
            "headers": {
                k: (_redact(v) if k.lower() in ("authorization", "x-api-key", "cookie") else v)
                for k, v in self.headers.items()
            },
            "cookies": {k: _redact(v) for k, v in self.cookies.items()},
        }
