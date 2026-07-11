"""Multi-step authorization / BOLA (IDOR) chains — the nuclei-can't edge.

nuclei matches one template against one request, so it cannot express the thing that
actually finds broken object-level authorization: *carry state across requests and
across identities*. This module does exactly that, GET-only (read, never mutate —
weaponization/state change is handed to the human or Strix):

* **direct BOLA** — the owner (auth_A) and a second/anon identity get the *same* object
  back from the *same* URL → the object isn't scoped to its owner;
* **sibling sweep** — walk the object-id space (id±1, low ids) as the other identity;
  a 2xx object body for an id they have no relation to = horizontal IDOR / enumeration;
* **multi-step chain** — read the owner's response, extract the object ids *A* exposes
  (``"order_id": 205``, ``/invoices/77``), then try to fetch each of those as the other
  identity. The response of step 1 feeds step 2 — the part a stateless scanner can't do.

Findings are ``review`` leads (the agent confirms the body is the real private object).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from difflib import SequenceMatcher
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
# object ids in a response body: "id"/"*_id"/"uuid" JSON fields, and /segment/<id> hrefs.
# NB: the UUID alternative comes BEFORE \d{1,12} so a UUID's leading digits aren't
# captured as a short numeric id.
_BODY_ID_RE = re.compile(
    r'"(?:id|[a-z0-9_]{0,24}_id|uuid|guid|ref|number)"\s*:\s*"?('
    r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
    r'|\d{1,12})"?', re.I)
_HREF_ID_RE = re.compile(
    r'/[a-zA-Z][\w-]{1,40}/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-'
    r'[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|\d{1,12})')


@dataclass
class ObjectRef:
    kind: str      # "numeric" | "uuid"
    value: str
    where: str     # "path:<index>" | "query:<key>"


def object_refs(url: str) -> list[ObjectRef]:
    """Object identifiers in *url*'s path segments and query values."""

    parts = urlsplit(url)
    refs: list[ObjectRef] = []
    for i, seg in enumerate(parts.path.split("/")):
        if _UUID_RE.fullmatch(seg):
            refs.append(ObjectRef("uuid", seg, f"path:{i}"))
        elif seg.isdigit():
            refs.append(ObjectRef("numeric", seg, f"path:{i}"))
    for k, v in parse_qsl(parts.query, keep_blank_values=True):
        if _UUID_RE.fullmatch(v):
            refs.append(ObjectRef("uuid", v, f"query:{k}"))
        elif v.isdigit():
            refs.append(ObjectRef("numeric", v, f"query:{k}"))
    return refs


def sibling_values(ref: ObjectRef, limit: int = 3) -> list[str]:
    """Neighbouring ids to walk the object space (numeric only; UUIDs aren't guessable)."""

    if ref.kind != "numeric":
        return []
    n = int(ref.value)
    out: list[str] = []
    for c in (n - 1, n + 1, 1, 2, 0):
        s = str(c)
        if c >= 0 and s != ref.value and s not in out:
            out.append(s)
        if len(out) >= limit:
            break
    return out


def with_ref(url: str, ref: ObjectRef, new_value: str) -> str:
    """Return *url* with *ref* replaced by *new_value* (path segment or query value)."""

    parts = urlsplit(url)
    kind, _, loc = ref.where.partition(":")
    if kind == "path":
        segs = parts.path.split("/")
        idx = int(loc)
        if 0 <= idx < len(segs):
            segs[idx] = new_value
        return urlunsplit((parts.scheme, parts.netloc, "/".join(segs), parts.query, ""))
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    newq = [(k, new_value if (k == loc and v == ref.value) else v) for k, v in pairs]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(newq), ""))


def extract_body_refs(text: str, max_n: int = 20) -> list[str]:
    """Object ids the owner's response exposes (to try as another identity)."""

    out: list[str] = []
    for rx in (_BODY_ID_RE, _HREF_ID_RE):
        for m in rx.finditer(text or ""):
            v = m.group(1)
            if v not in out:
                out.append(v)
                if len(out) >= max_n:
                    return out
    return out


def similar(a: bytes, b: bytes) -> float:
    """Body similarity of the first 4 KiB (0..1)."""

    if not a or not b:
        return 0.0
    return round(SequenceMatcher(None, a[:4096], b[:4096]).ratio(), 3)


def looks_like_object(status: int | None, body: bytes) -> bool:
    """A 2xx, non-trivial body — i.e. a real object was returned, not an error stub."""

    return status is not None and 200 <= status < 300 and len(body) >= 16


async def probe_bola(client, url: str, *, b_headers: dict | None = None,
                     max_refs: int = 8, scope_check=None) -> dict:
    """Run the three BOLA signals (direct / sibling sweep / multi-step chain), GET-only."""

    async def fetch_as(u: str, *, headers=None, suppress_auth=False):
        return await client.fetch(u, method="GET", headers=headers, suppress_auth=suppress_auth,
                                  follow_redirects=False, timeout=12.0, scope_check=scope_check)

    others: list[tuple[str, dict | None]] = []
    if b_headers:
        others.append(("user_B", b_headers))
    others.append(("anonymous", None))

    findings: list[dict] = []
    a = await fetch_as(url)  # owner = current engagement auth
    a_ok = looks_like_object(a.status, a.body)
    refs = object_refs(url)[:max_refs]

    # Signal 1 — direct BOLA: another identity gets the SAME object from the SAME URL.
    if a_ok:
        for name, hdr in others:
            r = await fetch_as(url, headers=hdr, suppress_auth=True)
            if looks_like_object(r.status, r.body) and similar(a.body, r.body) >= 0.95:
                findings.append({
                    "kind": "direct_bola", "identity": name, "url": url,
                    "severity": "high", "verdict": "review",
                    "detail": f"{name} receives the same object as the owner from {url} "
                              "(similarity ≥0.95) — the object is not scoped to its owner",
                })

    # Signal 2 — sibling sweep: walk the id space as the other identity.
    sweeper_name, sweeper_hdr = others[0]
    for ref in refs:
        for sib in sibling_values(ref):
            swapped = with_ref(url, ref, sib)
            r = await fetch_as(swapped, headers=sweeper_hdr, suppress_auth=True)
            if looks_like_object(r.status, r.body):
                findings.append({
                    "kind": "sibling_idor", "identity": sweeper_name, "url": swapped,
                    "ref": ref.value, "reached": sib, "severity": "high", "verdict": "review",
                    "detail": f"{sweeper_name} read object id={sib} (neighbour of {ref.value}) — "
                              "horizontal IDOR / object enumeration; confirm it is another user's data",
                })
                break  # one neighbour hit per ref is enough signal

    # Signal 3 — multi-step chain: extract ids the OWNER exposes, access them as another identity.
    if a_ok and refs:
        url_vals = {r.value for r in refs}
        owned = [v for v in extract_body_refs(a.text(limit=50_000)) if v not in url_vals][:max_refs]
        ref0 = refs[0]
        for name, hdr in others:
            for v in owned:
                swapped = with_ref(url, ref0, v)
                r = await fetch_as(swapped, headers=hdr, suppress_auth=True)
                if looks_like_object(r.status, r.body):
                    findings.append({
                        "kind": "multistep_bola", "identity": name, "url": swapped,
                        "owner_ref": v, "severity": "high", "verdict": "review",
                        "detail": f"{name} accessed object id={v} that the owner's response exposed "
                                  "— chained IDOR (owner response → cross-identity access)",
                    })
                    break

    return {
        "target": url, "refs_found": [{"value": r.value, "where": r.where} for r in refs],
        "findings": findings, "verdict": "review" if findings else "no_obvious_bola",
    }
