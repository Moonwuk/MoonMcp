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


def absent_id(ref: ObjectRef) -> str:
    """A syntactically-valid id of *ref*'s kind that is overwhelmingly unlikely to name
    a real object — the negative control for whether the endpoint is object-scoped."""

    if ref.kind == "uuid":
        return "ffffffff-ffff-4fff-bfff-ffffffffffff"
    return "999999999"


def _classify(r, ctrl, len_jitter: int, content_stable: bool) -> str:
    """Is *r* a DISTINCT object, the same SHELL, or AMBIGUOUS versus the "this id is absent"
    *ctrl*?  Telling a real per-id object from a soft-404 shell at the byte level is, in
    general, UNDECIDABLE — a same-length object plus any per-request token (trace id / CSRF
    nonce / timestamp) defeats every length- or content-comparison. So we only ever return:

    * ``distinct`` — provably different (status change, or length past the measured jitter, or
      a content change against a byte-stable control);
    * ``shell``    — provably the SAME (a byte-stable control the response matches exactly);
    * ``ambiguous``— can't tell (a jittery control we can't reliably compare against).

    The caller SURFACES distinct + ambiguous (never suppressing a possible object → no false
    negative) and suppresses only the provable ``shell``; ``ambiguous`` is marked low-confidence."""

    if r.status != ctrl.status:
        return "distinct"
    if abs(len(r.body) - len(ctrl.body)) > len_jitter:
        return "distinct"
    if content_stable:
        return "distinct" if r.body != ctrl.body else "shell"
    return "ambiguous"


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

    sweeper_name, sweeper_hdr = others[0]
    findings: list[dict] = []
    a = await fetch_as(url)  # owner = current engagement auth
    a_ok = looks_like_object(a.status, a.body)
    refs = object_refs(url)[:max_refs]

    # Per-ref negative controls. For each id-bearing ref, fetch a guaranteed-absent id TWICE
    # as the sweeper (to measure THIS endpoint's per-request jitter) and once as the owner.
    # _classify() then tells a DISTINCT object from a provable SHELL from an AMBIGUOUS case.
    # Keyed by ref, so a decorative leading numeric segment (year / API version / page) can't
    # suppress the sweep of the actual object ref.
    _SOFT_NOTE = (" — NOTE: this endpoint returns a variable / soft-404-like body for nonexistent "
                  "ids, so an object shape can't be proven; confirm the body is real per-user data")
    ctl: dict[str, tuple] = {}  # ref.where -> (sweeper_ctrl, len_jitter, content_stable, owner_class)
    for ref in refs:
        au = with_ref(url, ref, absent_id(ref))
        s1 = await fetch_as(au, headers=sweeper_hdr, suppress_auth=True)
        s2 = await fetch_as(au, headers=sweeper_hdr, suppress_auth=True)
        len_jitter = abs(len(s1.body) - len(s2.body))
        stable = s1.body == s2.body
        ao = await fetch_as(au)  # owner: is the owner's REAL object distinct from an absent id?
        owner_class = _classify(a, ao, len_jitter, stable) if a_ok else "shell"
        ctl[ref.where] = (s1, len_jitter, stable, owner_class)

    # The endpoint is object-scoped UNLESS every ref PROVES a shell (a byte-stable control the
    # owner body matches exactly). A jittery/ambiguous control does NOT prove a shell, so the
    # direct + chained signals still run (surfaced low if the sibling lane can't confirm).
    endpoint_scoped = (not refs) or any(v[3] != "shell" for v in ctl.values())
    control_note: str | None = None
    if refs and not endpoint_scoped:
        control_note = ("nonexistent ids return the SAME (byte-stable) body as real ones — endpoint "
                        "is not object-scoped (soft-404 / SPA / public); direct/chained BOLA suppressed")

    # Signal 1 — direct BOLA: another identity gets the SAME object from the SAME URL.
    if a_ok and endpoint_scoped:
        for name, hdr in others:
            r = await fetch_as(url, headers=hdr, suppress_auth=True)
            if looks_like_object(r.status, r.body) and similar(a.body, r.body) >= 0.95:
                findings.append({
                    "kind": "direct_bola", "identity": name, "url": url,
                    "severity": "high", "verdict": "review",
                    "detail": f"{name} receives the same object as the owner from {url} "
                              "(similarity ≥0.95) — the object is not scoped to its owner",
                })

    # Signal 2 — per-ref sibling sweep. Classify each object-like neighbour against the ref's
    # absent-id control: suppress only a PROVABLE shell; surface distinct (high) and ambiguous
    # (low, soft-404-suspected) so a jittery / same-length endpoint never hides a real IDOR.
    for ref in refs:
        s1, len_jitter, stable, _ = ctl[ref.where]
        ctrl_obj = looks_like_object(s1.status, s1.body)
        for sib in sibling_values(ref):
            swapped = with_ref(url, ref, sib)
            r = await fetch_as(swapped, headers=sweeper_hdr, suppress_auth=True)
            if not looks_like_object(r.status, r.body):
                continue
            cls = "distinct" if not ctrl_obj else _classify(r, s1, len_jitter, stable)
            if cls == "shell":
                continue  # provably the same shell → not an object
            soft = cls == "ambiguous"
            findings.append({
                "kind": "sibling_idor", "identity": sweeper_name, "url": swapped,
                "ref": ref.value, "reached": sib, "severity": "low" if soft else "high",
                "verdict": "review", "soft_404_suspected": soft,
                "detail": f"{sweeper_name} read object id={sib} (neighbour of {ref.value}) — "
                          "horizontal IDOR / object enumeration; confirm it is another user's data"
                          + (_SOFT_NOTE if soft else ""),
            })
            break  # one neighbour hit per ref is enough signal

    # Signal 3 — multi-step chain: ids the OWNER exposes, accessed as another identity. Try
    # substituting into EACH ref (a decorative leading year/version must not misroute the probe).
    if a_ok and refs and endpoint_scoped:
        url_vals = {r.value for r in refs}
        owned = [v for v in extract_body_refs(a.text(limit=50_000)) if v not in url_vals][:max_refs]
        for name, hdr in others:
            for v in owned:
                for ref in refs:
                    swapped = with_ref(url, ref, v)
                    r = await fetch_as(swapped, headers=hdr, suppress_auth=True)
                    if looks_like_object(r.status, r.body):
                        findings.append({
                            "kind": "multistep_bola", "identity": name, "url": swapped,
                            "ref": ref.value, "owner_ref": v, "severity": "high", "verdict": "review",
                            "detail": f"{name} accessed object id={v} that the owner's response exposed "
                                      "— chained IDOR (owner response → cross-identity access)",
                        })
                        break  # found via this ref; next exposed id

    return {
        "target": url, "refs_found": [{"value": r.value, "where": r.where} for r in refs],
        "findings": findings, "verdict": "review" if findings else "no_obvious_bola",
        **({"note": control_note} if control_note else {}),
    }
