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
        self.headers["Authorization"] = f"Bearer {token.strip()}"

    def set_basic(self, username: str, password: str) -> None:
        raw = base64.b64encode(f"{username}:{password}".encode()).decode()
        self.headers["Authorization"] = f"Basic {raw}"

    def set_cookie_string(self, cookie: str) -> None:
        """Parse a raw ``k=v; k2=v2`` Cookie header into the cookie jar."""

        for part in cookie.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                if k.strip():
                    self.cookies[k.strip()] = v.strip()

    def update_headers(self, headers: dict[str, str]) -> None:
        self.headers.update({str(k): str(v) for k, v in headers.items()})

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
