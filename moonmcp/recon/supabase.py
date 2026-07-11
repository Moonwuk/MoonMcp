"""Supabase RLS-off / anon-key full-table read — safe read-only.

Supabase tables have Row-Level Security **off by default**, and the ``anon`` key is
public-by-design (it ships in the frontend). With RLS off, that public key grants full
SELECT on every PostgREST-exposed table. CVE-2025-48757; ~10% of analyzed "vibe-coded"
apps shipped anon-readable tables.

Detection (safe): harvest the project URL (``https://<ref>.supabase.co``) + the ``anon``
key from the app JS, fetch the auto-generated schema at ``/rest/v1/?apikey=<anon>`` to
enumerate tables, then ``GET /rest/v1/<table>?select=*&limit=1&apikey=<anon>`` — a ``200``
returning a row = RLS off. ``limit=1`` avoids a bulk pull; we use the app's own public
key against its own API (non-destructive read).

Pure parsers + assessors here; the ``supabase_exposure`` tool does the fetching (rows are
redacted). Sources:
https://supabase.com/docs/guides/database/database-advisors?lint=0013_rls_disabled_in_public ·
https://modernpentest.com/blog/supabase-security-misconfigurations . See docs/DATABASE_RESEARCH.md E.2.
"""

from __future__ import annotations

import base64
import binascii
import json
import re

_SUPABASE_URL_RE = re.compile(r"https?://([a-z0-9]{16,40})\.supabase\.(?:co|in)", re.I)
_ANON_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]{6,}\.eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}")
_PUBLISHABLE_RE = re.compile(r"\bsb_publishable_[A-Za-z0-9_\-]{16,}")


def _jwt_role(token: str) -> str | None:
    """Decode a JWT's payload and return its ``role`` claim (no signature check)."""

    parts = token.split(".")
    if len(parts) < 2:
        return None
    seg = parts[1]
    seg += "=" * (-len(seg) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(seg))
    except (binascii.Error, ValueError, json.JSONDecodeError):
        return None
    role = payload.get("role")
    return str(role) if role is not None else None


def parse_supabase_config(text: str) -> dict:
    """Extract ``{url, anon_key, key_type}`` from page/JS source (best-effort)."""

    out: dict = {}
    m = _SUPABASE_URL_RE.search(text or "")
    if m:
        out["url"] = f"https://{m.group(1)}.supabase.co"
    # Prefer a JWT whose role is anon (the classic anon key); else a publishable key.
    for jm in _ANON_JWT_RE.finditer(text or ""):
        if _jwt_role(jm.group(0)) == "anon":
            out["anon_key"] = jm.group(0)
            out["key_type"] = "anon-jwt"
            break
    if "anon_key" not in out and (pm := _PUBLISHABLE_RE.search(text or "")):
        out["anon_key"] = pm.group(0)
        out["key_type"] = "publishable"
    return out


def schema_url(url: str, anon_key: str) -> str:
    return f"{url.rstrip('/')}/rest/v1/?apikey={anon_key}"


def table_url(url: str, table: str, anon_key: str) -> str:
    return f"{url.rstrip('/')}/rest/v1/{table}?select=*&limit=1&apikey={anon_key}"


def parse_tables(schema_body: str) -> list[str]:
    """Table names from the PostgREST OpenAPI/Swagger root (``definitions`` or ``paths``)."""

    try:
        doc = json.loads(schema_body or "")
    except (ValueError, json.JSONDecodeError):
        return []
    tables: list[str] = []
    for name in (doc.get("definitions") or {}):
        if name and not name.startswith(("(", "rpc")):
            tables.append(name)
    if not tables:
        for path in (doc.get("paths") or {}):
            t = path.strip("/")
            if t and "/" not in t and not t.startswith("rpc"):
                tables.append(t)
    return list(dict.fromkeys(tables))


def assess_table(status: int | None, body: str) -> bool:
    """A ``200`` returning a JSON array with at least one row ⇒ RLS off (readable)."""

    if status != 200:
        return False
    try:
        rows = json.loads(body or "")
    except (ValueError, json.JSONDecodeError):
        return False
    return isinstance(rows, list) and len(rows) >= 1
