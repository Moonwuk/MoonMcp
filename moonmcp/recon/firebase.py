"""Firebase Realtime Database / Firestore open-rules exposure — safe read-only.

A Firebase project whose Security Rules allow ``.read: true`` (or ``if true``) lets
anyone who learns the project id — it ships in the app's `firebaseConfig` — read the
whole dataset over one unauthenticated HTTPS request. Comparitech attributes 100M+
leaked records/year to this; it is epidemic in "vibe-coded" apps.

Detection (safe): harvest ``databaseURL``/``projectId`` from the crawled page + JS, then
one unauthenticated ``GET <databaseURL>/.json?shallow=true`` — ``shallow=true`` returns
only the top-level keys (no bulk data pull). A ``200`` with JSON (not
``{"error":"Permission denied"}``) = open read. Firestore uses a different endpoint/rule
set, so a discovered ``projectId`` is reported as a follow-up lead.

Pure parsers + assessors here; the ``firebase_exposure`` tool does the fetching.
Weaponization (bulk dump / write) → Strix. Sources:
https://firebase.google.com/docs/rules/insecure-rules ·
https://www.legba.app/adversary/exposures/exposed-firebase-database . See
docs/DATABASE_RESEARCH.md E.1.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

# firebaseConfig fields (JS object or JSON). databaseURL is a full RTDB URL; the RTDB
# host is *.firebaseio.com (classic) or *.firebasedatabase.app (newer, regional).
_DATABASE_URL_RE = re.compile(
    r"""["']?databaseURL["']?\s*[:=]\s*["'](https?://[^"'\s]+)["']""", re.I)
_PROJECT_ID_RE = re.compile(
    r"""["']?projectId["']?\s*[:=]\s*["']([a-z0-9][a-z0-9\-]{2,})["']""", re.I)
# A bare RTDB URL anywhere in the source (fallback when there's no full config object).
_RTDB_URL_RE = re.compile(
    r"https?://[a-z0-9][a-z0-9\-]*(?:\.[a-z0-9\-]+)*\.(?:firebaseio\.com|firebasedatabase\.app)", re.I)


def parse_firebase_config(text: str) -> dict:
    """Extract ``{databaseURL, projectId}`` from page/JS source (best-effort)."""

    out: dict = {}
    m = _DATABASE_URL_RE.search(text or "")
    if m:
        out["databaseURL"] = m.group(1).rstrip("/")
    elif (b := _RTDB_URL_RE.search(text or "")):
        out["databaseURL"] = b.group(0).rstrip("/")
    p = _PROJECT_ID_RE.search(text or "")
    if p:
        out["projectId"] = p.group(1)
    return out


def rtdb_probe_url(database_url: str) -> str:
    """The shallow, read-only RTDB probe URL for a databaseURL."""

    sp = urlsplit(database_url)
    base = f"{sp.scheme or 'https'}://{sp.netloc}"
    return f"{base}/.json?shallow=true"


def assess_rtdb(status: int | None, body: str) -> dict | None:
    """Classify a ``/.json?shallow=true`` response. Returns a finding or None."""

    if status is None:
        return None
    low = (body or "").lower()
    # A real Firebase deny is 401/403 or a body containing "Permission denied". The bare
    # `"error"` key was too broad — an OPEN RTDB whose data has a top-level node named
    # "error" (e.g. an app storing error logs at /error) was misread as protected (FN).
    if status in (401, 403) or "permission denied" in low:
        return {"verdict": "protected", "severity": "info",
                "detail": "RTDB rules deny anonymous read (Permission denied)."}
    if status == 200:
        stripped = (body or "").strip()
        # NB: `"" in "{["` is True in Python, so an empty 200 body must be excluded —
        # require actual JSON content (`null`, or a leading `{`/`[`).
        if stripped == "null" or stripped[:1] in ("{", "["):
            return {"verdict": "confirmed", "severity": "high",
                    "detail": "RTDB is readable with NO auth (/.json?shallow=true returned data) — "
                              "open Security Rules; the whole dataset is exposed. Bulk dump → Strix."}
    return None
