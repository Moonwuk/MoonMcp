"""Path-normalization ACL bypass (a.k.a. 403/401 bypass).

A front proxy enforces the access rule on the *literal* request path, then forwards
to a backend that *normalizes* the path differently — so a protected route reached
via a normalization twin (`/admin/..;/`, `/%2e/admin`, matrix `;`, double slash,
encoded chars) skips the ACL but still resolves the resource. CVE-2024-0204 (Fortra
GoAnywhere `/..;/` → admin account creation) is the canonical case.

Also carries the ingress / service-mesh twins that pay out against k8s stacks —
double-slash (`//admin`, Istio CVE-2021-31920), encoded slash (`%2f`, Envoy
CVE-2021-29492), fragment (`%23`, Istio CVE-2021-39156), first-segment case toggle
(Istio CVE-2021-39155) — plus an **external-auth lane**: a benign prefix + `..`
(`/x/..%2fadmin`) that an nginx `auth_request` / ingress-nginx `auth-url` (or APISIX
`uri-blocker`, CVE-2021-43557) authorizes on the un-normalized `$request_uri` as
public while the proxy forwards the normalized protected path.

Safe detection = differential: only fire when the plain path is actually protected
(401/403), then flag any twin that flips to 2xx. Non-destructive — GET only, no
payloads. Findings are ``review`` (the agent confirms the 2xx body is the real
protected content, not a generic page/redirect).
"""

from __future__ import annotations

from collections.abc import Callable
from urllib.parse import urlsplit, urlunsplit

from ..net.http import HttpClient

# Appended to the protected path — proxy vs backend may normalize these apart.
# `%23` is the URI fragment (Istio authz-vs-router fragment bypass, CVE-2021-39156).
_SUFFIX_TWINS = ["/", "/.", "/..;/", "..;/", "%2f", "%2e", ";", ";/", ";x", "%20", "%09", "%23"]
# Prepended to the path (root-level matrix / dot segments).
_PREFIX_TWINS = ["/%2e", "/.", "/;", "/.;", "/%2f"]
# A benign leading segment for the external-auth ($request_uri) traversal lane.
_AUTH_PREFIX = "moonmcp"


def bypass_variants(url: str) -> list[tuple[str, str]]:
    """Generate ``(technique, url)`` normalization twins of *url*'s path."""

    parts = urlsplit(url)
    path = parts.path or "/"
    out: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(label: str, newpath: str) -> None:
        u = urlunsplit((parts.scheme, parts.netloc, newpath, parts.query, ""))
        if u != url and u not in seen:
            seen.add(u)
            out.append((label, u))

    for suf in _SUFFIX_TWINS:
        add(f"suffix {suf!r}", path + suf)
    for pre in _PREFIX_TWINS:
        add(f"prefix {pre!r}", pre + path)

    segs = [s for s in path.split("/") if s]
    if segs:
        first, rest = segs[0], segs[1:]
        tail = "/" + "/".join(rest) if rest else ""
        add("matrix on first segment", f"/{first};x{tail}")
        add("dot-dot reinjection", f"/{first}/..;{tail or '/'}")
        enc = "%" + format(ord(first[0]), "02x")
        add("percent-encoded first char", f"/{enc}{first[1:]}{tail}")
        if rest:
            add("double internal slash", f"/{first}//" + "/".join(rest))
        # ingress / service-mesh normalization twins.
        add("double-slash prefix", "/" + path)                       # //admin (Istio //)
        add("encoded-slash before segment", f"/%2f{first}{tail}")    # /%2fadmin (Envoy %2f)
        add("first-segment case toggle", f"/{first.swapcase()}{tail}")  # /ADMIN (Istio host/path case)
        # External-auth ($request_uri) traversal: a benign public-looking prefix +
        # `..` the auth subrequest allows while the proxy forwards the normalized
        # protected path (ingress-nginx auth-url / APISIX uri-blocker class).
        add("external-auth traversal %2f", f"/{_AUTH_PREFIX}/..%2f{first}{tail}")
        add("external-auth traversal raw", f"/{_AUTH_PREFIX}/../{first}{tail}")
    return out


def assess_bypass(baseline_status: int | None, twin_status: int | None) -> bool:
    """A twin bypassed the ACL if the plain path was protected (401/403) and the
    twin resolved with a 2xx."""

    return baseline_status in (401, 403) and twin_status is not None and 200 <= twin_status < 300


async def probe_path_bypass(client: HttpClient, url: str, *,
                            scope_check: Callable[[str], bool] | None = None) -> dict:
    """Confirm the path is protected (401/403), then replay each normalization twin;
    flag the ones that flip to 2xx (an ACL-bypass candidate to verify)."""

    base = await client.fetch(url, method="GET", follow_redirects=False,
                              timeout=12.0, scope_check=scope_check)
    baseline = base.status
    if baseline not in (401, 403):
        return {
            "protected": False, "baseline_status": baseline, "findings": [],
            "note": "baseline is not 401/403 — point at a route that is actually access-controlled",
        }
    findings: list[dict] = []
    for label, twin in bypass_variants(url):
        r = await client.fetch(twin, method="GET", follow_redirects=False,
                               timeout=12.0, scope_check=scope_check)
        if assess_bypass(baseline, r.status):
            findings.append({
                "technique": label, "url": twin, "baseline_status": baseline,
                "twin_status": r.status, "twin_len": len(r.body),
                "severity": "high", "verdict": "review",
                "detail": f"{label} flipped {baseline} → {r.status} — proxy/backend path-"
                          "normalization disagreement reaching a protected route; verify the 2xx "
                          "body is the real protected content (not a generic page/redirect)",
            })
    return {"protected": True, "baseline_status": baseline, "findings": findings}
