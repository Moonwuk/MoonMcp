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
    r'"(id|[a-z0-9_]{0,24}_id|uuid|guid|ref|number)"\s*:\s*"?('
    r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
    r'|\d{1,12})"?', re.I)
_HREF_ID_RE = re.compile(
    r'/([a-zA-Z][\w-]{1,40})/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-'
    r'[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|\d{1,12})')

# A multi-step chain may only inject an owner-exposed id into the URL's object slot
# when the id belongs to the SAME collection as that slot, or is a generic relationship
# pointer (next/prev/parent/… or a bare id). A `product_id` pulled from an /orders/<id>
# response and pushed back into /orders/<product_id> addresses a same-NUMBERED but
# unrelated object — a false chained IDOR the sibling sweep would already cover if real.
_GENERIC_COLLECTIONS = frozenset({
    "", "next", "prev", "previous", "parent", "child", "sibling", "related", "self", "root",
})


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


def _field_collection(field: str) -> str:
    """Collection a JSON id field names: ``order_id`` → ``order``; a bare ``id`` /
    ``uuid`` / ``guid`` / ``ref`` / ``number`` names no specific collection (generic)."""

    f = field.lower()
    return f[:-3] if f.endswith("_id") else ""


def _canon_collection(c: str) -> str:
    """Canonical collection key for comparison: strip an ``_id`` suffix (or a bare
    ``id``/``uuid``/… type name → generic ``""``), then singular/plural-fold
    (``orders`` → ``order``, ``companies`` → ``compan``, ``statuses`` → ``statu``).
    Reconciles the three namespaces we compare — a path segment (``orders``), a query
    key (``order_id``) and a JSON field's collection (``order``) — into one comparable
    key. The fold is crude, but both sides of every comparison run through it, so a
    collection and its own plural collapse alike even for ``-ies``/``-ses`` forms — the
    naive single-``s`` strip silently dropped a real chained IDOR whenever the URL slot
    was e.g. ``/companies/`` (``companies`` ≠ ``company``)."""

    c = c.lower()
    if c.endswith("_id"):
        c = c[:-3]
    elif c in ("id", "uuid", "guid", "ref", "number"):
        c = ""
    if c.endswith("ies") and len(c) > 3:
        c = c[:-3] + "y"                       # companies -> company, categories -> category
    elif c.endswith(("ses", "xes", "zes", "ches", "shes")) and len(c) > 3:
        c = c[:-2]                             # statuses -> status, boxes -> box, matches -> match
    if c.endswith("s") and not c.endswith("ss") and len(c) > 1:
        c = c[:-1]                             # orders -> order (but address stays address)
    return c


def _ref_collection(url: str, ref: ObjectRef) -> str:
    """The collection the URL slot *ref* addresses: the path segment before a path id,
    or the query key for a query id."""

    parts = urlsplit(url)
    kind, _, loc = ref.where.partition(":")
    if kind == "path":
        segs = parts.path.split("/")
        idx = int(loc)
        return segs[idx - 1] if 0 < idx < len(segs) else ""
    return loc


def _collection_compatible(body_coll: str, ref_coll: str) -> bool:
    """May an id exposed under *body_coll* be tried in a URL slot of *ref_coll*? Yes when
    *body_coll* is a generic relationship pointer (next/prev/parent/…), when EITHER side
    is a generic id sink (a bare ``id``/``uuid`` field or a ``?id=`` query — the
    collection is unknowable, so don't suppress), or when both name the SAME collection
    (singular/plural- and ``_id``-insensitive). A ``product_id`` injected into
    ``/orders/<id>`` is a collection mismatch and is rejected."""

    if body_coll in _GENERIC_COLLECTIONS:
        return True
    b, r = _canon_collection(body_coll), _canon_collection(ref_coll)
    return b == "" or r == "" or b == r


def extract_body_refs(text: str, max_n: int = 20) -> list[tuple[str, str]]:
    """Object ids the owner's response exposes, each paired with the COLLECTION it was
    named under — the JSON field's ``_id`` prefix (``order_id`` → ``order``) or the
    href's path segment (``/invoices/77`` → ``invoices``). The collection lets the
    multi-step chain avoid injecting a same-numbered but unrelated id into the wrong slot."""

    out: list[tuple[str, str]] = []
    for rx, is_href in ((_BODY_ID_RE, False), (_HREF_ID_RE, True)):
        for m in rx.finditer(text or ""):
            name, value = m.group(1), m.group(2)
            pair = (value, name.lower() if is_href else _field_collection(name))
            if pair not in out:
                out.append(pair)
                if len(out) >= max_n:
                    return out
    return out


def similar(a: bytes, b: bytes) -> float:
    """Body similarity (0..1). Compares the HEAD and the TAIL so a large shared static
    shell (SPA skeleton / nav) in the leading bytes can't mask two objects that differ
    only in the data below it — comparing head-4KiB alone collapsed such pairs to 1.0."""

    if not a or not b:
        return 0.0

    def _sample(x: bytes) -> bytes:
        return x[:4096] + x[-4096:] if len(x) > 8192 else x

    return round(SequenceMatcher(None, _sample(a), _sample(b)).ratio(), 3)


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
    # Negative control: read a clearly-NONEXISTENT id as the sweeper. If the endpoint
    # returns an object-like body even for an id that can't exist, it serves a catch-all
    # / soft-200 for every id — so a neighbour body that is ~identical to that control is
    # NOT per-object data. Suppressing those kills the soft-200 false IDOR while a real
    # endpoint (distinct data per id, 404 for a bogus id) is unaffected.
    soft_body: bytes | None = None
    num_ref = next((r for r in refs if r.kind == "numeric" and r.value.isdigit()), None)
    if num_ref is not None:
        bogus = str(int(num_ref.value) + 9_000_017)
        rc = await fetch_as(with_ref(url, num_ref, bogus), headers=sweeper_hdr, suppress_auth=True)
        if looks_like_object(rc.status, rc.body):
            soft_body = rc.body
    for ref in refs:
        for sib in sibling_values(ref):
            swapped = with_ref(url, ref, sib)
            r = await fetch_as(swapped, headers=sweeper_hdr, suppress_auth=True)
            if not looks_like_object(r.status, r.body):
                continue
            if soft_body is not None and similar(soft_body, r.body) >= 0.99:
                continue  # same body as a nonexistent id → soft-200 catch-all, not real data
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
        ref0 = refs[0]
        ref0_coll = _ref_collection(url, ref0)
        # Only chain ids that belong to ref0's collection (or a generic pointer); a
        # same-numbered id from a DIFFERENT collection is an unrelated object, not a chain.
        owned: list[str] = []
        for v, coll in extract_body_refs(a.text(limit=50_000)):
            if v in url_vals or v in owned or not _collection_compatible(coll, ref0_coll):
                continue
            owned.append(v)
            if len(owned) >= max_refs:
                break
        for name, hdr in others:
            for v in owned:
                swapped = with_ref(url, ref0, v)
                r = await fetch_as(swapped, headers=hdr, suppress_auth=True)
                if not looks_like_object(r.status, r.body):
                    continue
                if soft_body is not None and similar(soft_body, r.body) >= 0.99:
                    continue  # catch-all / soft-200 body, not a real chained object
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
