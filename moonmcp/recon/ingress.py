"""Ingress-controller / service-mesh fingerprinting and version→CVE mapping.

Identifies which Kubernetes ingress controller or mesh data-plane fronts a host —
ingress-nginx, Traefik, Kong, Istio/Envoy, HAProxy Ingress, Ambassador/Emissary,
and the managed cloud LBs (Google Frontend/GKE, AWS ALB, Azure Application
Gateway) — from black-box, *detection-only* signals:

* response headers (``Via: kong/x``, ``server: istio-envoy``, ``x-envoy-*``,
  ``X-Kong-*-Latency``, ``Server: Google Frontend`` / ``Microsoft-Azure-…``),
* the controller-specific **default-backend 404 body** elicited by an unmatched
  path (``default backend - 404`` = ingress-nginx, ``404 page not found`` = Go/
  Traefik, ``response 404 (backend NotFound)`` = GFE, Kong's no-Route JSON),
* TLS certificate tells — the ingress-nginx self-signed *"Kubernetes Ingress
  Controller Fake Certificate"* served for an unmapped host, and the exposed
  **admission-webhook** SAN ``ingress-nginx-controller-admission`` (the
  IngressNightmare precondition).

A detected controller + version is mapped against a curated, **offline** table of
high-severity controller CVEs (IngressNightmare and friends). Because most data
planes run with ``server_tokens off``, the version is frequently unknown from the
response — in that case the CVEs are returned as *candidates* (``version_status:
"unknown"``) with a pointer at the ``:10254/metrics`` build-info oracle. This is
the missing keystone that lets the existing ``cve_lookup(triage=True)`` fire on the ingress
layer; it sends nothing beyond the fingerprint fetch and never injects.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..net.http import HttpResult
from ..net.tls import TlsResult

# A fixed, obviously-unmatched path used to elicit the default-backend 404 body.
PROBE_PATH = "moonmcp-ingress-404-probe-a1b2c3"

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


# -- controller signatures ---------------------------------------------------
# (controller, where, pattern, confidence) — where ∈ {header:<name>, cookie,
# body404}. A capture group, if present, yields the version. ``body404`` is only
# matched against the unmatched-path response (never the real app body).
_SIGNATURES: list[tuple[str, str, str, str]] = [
    # ingress-nginx — the data plane runs `server_tokens off`, so identity comes
    # from the default backend body and the TLS cert, not the Server header.
    ("ingress-nginx", "body404", r"default backend - 404", "strong"),
    # Traefik / Go net/http default 404 (medium: shared with other Go proxies).
    ("Traefik", "header:x-traefik-router", r".+", "strong"),
    ("Traefik", "body404", r"\A404 page not found\s*\Z", "medium"),
    # Kong — Via/Server carry the version; latency headers and no-Route JSON tell.
    ("Kong", "header:via", r"kong/([\d.]+)", "strong"),
    ("Kong", "header:server", r"kong/([\d.]+)", "strong"),
    ("Kong", "header:x-kong-proxy-latency", r".+", "strong"),
    ("Kong", "header:x-kong-upstream-latency", r".+", "strong"),
    ("Kong", "body404", r"no Route matched with those values", "strong"),
    # Istio / Envoy.
    ("Istio", "header:server", r"istio-envoy", "strong"),
    ("Envoy", "header:server", r"\Aenvoy", "medium"),
    ("Envoy", "header:x-envoy-upstream-service-time", r".+", "strong"),
    ("Envoy", "header:x-envoy-decorator-operation", r".+", "strong"),
    # HAProxy Ingress (data-plane tell is weak; stats live on :1024).
    ("HAProxy", "header:server", r"haproxy", "weak"),
    # Managed cloud load balancers.
    ("Google Frontend (GKE/GFE)", "header:server", r"Google Frontend", "medium"),
    ("Google Frontend (GKE/GFE)", "body404", r"response 404 \(backend NotFound\)", "strong"),
    ("Azure Application Gateway", "header:server",
     r"Microsoft-Azure-Application-Gateway(?:/v?([\w.]+))?", "strong"),
    ("AWS ALB", "cookie", r"awsalb(?:cors)?=", "medium"),
    ("AWS ALB", "header:x-amzn-trace-id", r".+", "weak"),
]

_CONFIDENCE_RANK = {"strong": 3, "medium": 2, "weak": 1}


# -- offline CVE knowledge base ---------------------------------------------
@dataclass(frozen=True)
class IngressCVE:
    id: str
    severity: str
    cvss: float
    fixed: tuple[str, ...]  # first-patched version per affected branch
    unauth: bool            # reachable without Ingress-create RBAC?
    summary: str
    detection: str


# Keyed by canonical controller. Istio implies Envoy (Istio ships Envoy), so an
# Istio primary surfaces both sets.
_CONTROLLER_CVES: dict[str, list[IngressCVE]] = {
    "ingress-nginx": [
        IngressCVE("CVE-2025-1974", "critical", 9.8, ("1.11.5", "1.12.1"), True,
                   "IngressNightmare: unauthenticated admission-webhook config injection → RCE in "
                   "the controller pod, cluster-wide Secret theft when chained.",
                   "Confirm the admission webhook (TLS, :8443) is reachable unauthenticated and "
                   "map the version to <1.11.5 / ==1.12.0. Do NOT inject load_module — delegate."),
        IngressCVE("CVE-2025-24514", "high", 8.8, ("1.11.5", "1.12.1"), False,
                   "auth-url annotation rendered into nginx.conf unsanitized → directive injection.",
                   "Version <1.11.5 / ==1.12.0 with the admission webhook present."),
        IngressCVE("CVE-2025-1097", "high", 8.8, ("1.11.5", "1.12.1"), False,
                   "auth-tls-match-cn annotation injected into nginx config → RCE/Secret disclosure.",
                   "Version <1.11.5 / ==1.12.0."),
        IngressCVE("CVE-2025-1098", "high", 8.8, ("1.11.5", "1.12.1"), False,
                   "mirror-target/mirror-host annotations inject nginx config (also blind SSRF).",
                   "Version <1.11.5 / ==1.12.0; blind SSRF only observable via OAST."),
        IngressCVE("CVE-2025-24513", "medium", 4.8, ("1.11.5", "1.12.1"), False,
                   "Admission-controller directory traversal via attacker-influenced filename (DoS).",
                   "Version-inference only; no safe standalone data-plane observable."),
        IngressCVE("CVE-2024-7646", "high", 8.8, ("1.11.2",), False,
                   "Annotation-validation bypass via a carriage return, re-opening config injection.",
                   "Version <1.11.2."),
        IngressCVE("CVE-2023-5043", "high", 7.6, ("1.9.0",), False,
                   "configuration-snippet annotation injection → ServiceAccount-token/Secret theft.",
                   "Version <1.9.0 (or annotation-validation disabled). Needs Ingress-create RBAC."),
        IngressCVE("CVE-2023-5044", "high", 7.6, ("1.9.0",), False,
                   "permanent-redirect annotation injection → code execution in the controller.",
                   "Version <1.9.0 with annotation validation off. Needs Ingress-create RBAC."),
        IngressCVE("CVE-2022-4886", "high", 8.8, ("1.8.0",), False,
                   "path sanitization bypass via the log_format directive → read the SA token.",
                   "Version <1.8.0; ImplementationSpecific paths with directive-like chars."),
        IngressCVE("CVE-2021-25742", "high", 7.6, ("0.49.1", "1.0.1"), False,
                   "custom snippet annotations read the SA token and list all cluster Secrets.",
                   "Version <=0.49.0 unconditionally; later builds if allow-snippet-annotations left on."),
    ],
    "traefik": [
        IngressCVE("CVE-2025-32431", "high", 8.8, ("2.11.24", "3.3.6"), True,
                   "Router path matchers evaluate the raw path but forward the decoded one, so /../ "
                   "sequences bypass the middleware chain guarding another router's backend.",
                   "Confirm Traefik (404 page / dashboard), then run the path/normalization differential."),
        IngressCVE("CVE-2025-66490", "high", 7.5, ("2.11.32", "3.6.3"), True,
                   "Encoded restricted chars (/ \\ NUL ; ? #) slip past the router match and reach a "
                   "different router's backend, bypassing its middleware.",
                   "Encoded-char path differential vs the plain form."),
        IngressCVE("CVE-2024-45410", "high", 8.7, ("2.11.9", "3.1.3"), True,
                   "A client can mark Traefik's own X-Forwarded-* headers hop-by-hop via Connection, "
                   "so Traefik strips them → IP/host spoofing in backends that trust them (NOT RCE).",
                   "Reflect X-Forwarded-Host; resend with `Connection: X-Forwarded-Host` and watch it flip."),
    ],
    "kong": [
        IngressCVE("CVE-2021-27306", "high", 7.5, ("2.3.2",), True,
                   "JWT-plugin path traversal: /public/../protected applies an unauthenticated "
                   "route's rules to a JWT-protected route → auth bypass.",
                   "Confirm Kong (Via/X-Kong headers), then a path-traversal auth differential."),
        IngressCVE("CVE-2020-11710", "high", 9.8, ("2.0.4",), True,
                   "docker-compose template binds the Admin API to 0.0.0.0:8001 unauthenticated "
                   "(vendor-disputed as dev-template scope).",
                   "GET :8001/ returning node/config JSON = exposed unauthenticated Admin API."),
    ],
    "istio": [
        IngressCVE("CVE-2021-39155", "high", 8.3, ("1.9.8", "1.10.4", "1.11.1"), True,
                   "Istio compares Host case-sensitively while Envoy routes case-insensitively → "
                   "a different-cased Host bypasses AuthorizationPolicy.",
                   "Toggle the Host header case and diff routing/authz vs the lowercase baseline."),
        IngressCVE("CVE-2021-39156", "high", 8.1, ("1.9.8", "1.10.4", "1.11.1"), True,
                   "A URI fragment (#) bypasses Istio URI-path AuthorizationPolicy rules.",
                   "Append %23/#x to a protected path and diff status."),
        IngressCVE("CVE-2021-31920", "high", 8.1, ("1.8.6", "1.9.5"), True,
                   "Multiple/escaped slashes (//, %2f) bypass Istio path-based AuthorizationPolicy.",
                   "Slash-variant path differential (//P, /%2f/P, P%2f)."),
    ],
    "envoy": [
        IngressCVE("CVE-2023-27487", "high", 8.2, ("1.22.9", "1.23.6", "1.24.4", "1.25.3", "1.26.0"),
                   True,
                   "Envoy fails to strip the internal x-envoy-original-path header from untrusted "
                   "clients → spoof the path used by jwt_authn / access logs.",
                   "Send x-envoy-original-path toward a JWT/authz-gated route and watch for a change."),
        IngressCVE("CVE-2021-29492", "high", 8.3, ("1.15.5", "1.16.4", "1.17.3", "1.18.3"), True,
                   "Envoy does not decode %2F/%5C before path routing → escaped-slash access-control "
                   "bypass a decoding backend then resolves.",
                   "Compare a segment slash written literally vs %2F/%5C for a routing flip."),
        IngressCVE("CVE-2024-45806", "medium", 6.5, ("1.28.7", "1.29.9", "1.30.6", "1.31.2"), True,
                   "All RFC1918 ranges treated as internal by default → an external client behind a "
                   "private-IP hop can spoof x-envoy-* / x-forwarded-* headers.",
                   "Inject x-envoy-*/x-forwarded-* from outside and observe whether they take effect."),
    ],
}

# Controllers that imply another controller's CVE set as well.
_IMPLIES: dict[str, tuple[str, ...]] = {"istio": ("envoy",)}

# Display-name → canonical CVE key.
_CANON: dict[str, str] = {
    "ingress-nginx": "ingress-nginx",
    "Traefik": "traefik",
    "Kong": "kong",
    "Istio": "istio",
    "Envoy": "envoy",
}

# Admin / metrics / dashboard surface worth a scope-gated exposure sweep (item:
# ingress_admin_exposure). Detection-only follow-up hints — never call mutating
# endpoints (e.g. Envoy /quitquitquit).
_ADMIN_SURFACE: dict[str, list[dict[str, object]]] = {
    "ingress-nginx": [
        {"port": 10254, "path": "/metrics", "what": "Prometheus build_info — the version oracle"},
        {"port": 10254, "path": "/healthz", "what": "controller health"},
        {"port": 8443, "path": "/", "what": "admission webhook (IngressNightmare) — TLS reachability only"},
    ],
    "Traefik": [
        {"port": 8080, "path": "/dashboard/", "what": "dashboard SPA (api.insecure=true)"},
        {"port": 8080, "path": "/api/rawdata", "what": "full router/service/middleware/TLS map"},
    ],
    "Kong": [
        {"port": 8001, "path": "/", "what": "Admin API (read/write routes + plugin secrets)"},
        {"port": 8444, "path": "/", "what": "Admin API over HTTPS"},
        {"port": 8002, "path": "/", "what": "Kong Manager GUI"},
    ],
    "Istio": [
        {"port": 15000, "path": "/config_dump", "what": "Envoy admin — SecretsConfigDump"},
        {"port": 15021, "path": "/healthz/ready", "what": "pilot-agent health"},
    ],
    "Envoy": [
        {"port": 9901, "path": "/server_info", "what": "Envoy admin — exact version"},
        {"port": 9901, "path": "/config_dump", "what": "Envoy admin — full xDS config"},
    ],
    "HAProxy": [
        {"port": 1024, "path": "/", "what": "HAProxy stats — frontend/backend map"},
        {"port": 1024, "path": "/metrics", "what": "Prometheus haproxy_* series"},
    ],
}


# -- admin / metrics exposure sweep -----------------------------------------
# Read-only GET targets for the ingress_admin_exposure sweep. Each is a
# well-known control-plane endpoint that leaks topology/secrets when exposed.
# GET-only, and never a mutating endpoint (no /quitquitquit, no admin POST).
# (controller, scheme, port, path, signatures, what, severity)
ADMIN_ENDPOINTS: list[dict] = [
    {"controller": "Traefik", "scheme": "http", "port": 8080, "path": "/api/rawdata",
     "signatures": ['"routers"', '"middlewares"', '"entryPoints"'],
     "what": "full router/service/middleware/TLS map", "severity": "high"},
    {"controller": "Traefik", "scheme": "http", "port": 8080, "path": "/dashboard/",
     "signatures": ["<title>Traefik", "ng-app", "traefik"],
     "what": "dashboard SPA (api.insecure=true)", "severity": "high"},
    {"controller": "Kong", "scheme": "http", "port": 8001, "path": "/",
     "signatures": ['"plugins"', '"configuration"', "lua_version"],
     "what": "Admin API (read/write routes + plugin secrets)", "severity": "high"},
    {"controller": "Kong", "scheme": "https", "port": 8444, "path": "/",
     "signatures": ['"plugins"', '"configuration"', "lua_version"],
     "what": "Admin API over HTTPS", "severity": "high"},
    {"controller": "Envoy/Istio", "scheme": "http", "port": 9901, "path": "/server_info",
     "signatures": ['"version"', "command_line_options", '"state"'],
     "what": "Envoy admin — build/version", "severity": "high"},
    {"controller": "Envoy/Istio", "scheme": "http", "port": 15000, "path": "/server_info",
     "signatures": ['"version"', "command_line_options", '"state"'],
     "what": "Istio sidecar Envoy admin", "severity": "high"},
    {"controller": "ingress-nginx", "scheme": "http", "port": 10254, "path": "/metrics",
     "signatures": ["nginx_ingress_controller_", "nginx_ingress_controller_build_info"],
     "what": "Prometheus metrics — the version oracle", "severity": "medium"},
    {"controller": "HAProxy", "scheme": "http", "port": 1024, "path": "/",
     "signatures": ["Statistics Report for HAProxy", "pxname"],
     "what": "HAProxy stats — frontend/backend map", "severity": "medium"},
    {"controller": "Ambassador/Emissary", "scheme": "http", "port": 8877, "path": "/ambassador/v0/diag/",
     "signatures": ["Ambassador", "Emissary", "diag"],
     "what": "diagnostics UI — route table", "severity": "medium"},
]


def assess_admin_hit(status: int | None, body: str, signatures: list[str]) -> bool:
    """An admin endpoint is exposed if it answers 200 and its body carries one of
    the expected control-plane signatures (pure)."""

    if status != 200 or not body:
        return False
    low = body.lower()
    return any(s.lower() in low for s in signatures)


# -- version comparison ------------------------------------------------------
def _parse_ver(value: str | None) -> tuple[int, ...] | None:
    """Parse ``1.11.4`` → ``(1, 11, 4)`` taking the leading integer of each dotted
    part. Returns ``None`` if nothing numeric is found (pure)."""

    if not value:
        return None
    parts: list[int] = []
    for chunk in str(value).split("."):
        m = re.match(r"\d+", chunk)
        if not m:
            break
        parts.append(int(m.group()))
    return tuple(parts) if parts else None


def version_status(version: str | None, fixed: tuple[str, ...]) -> str:
    """``"vulnerable"`` / ``"patched"`` / ``"unknown"`` for *version* against the
    per-branch *fixed* set (pure).

    ``fixed`` lists the first patched version in each affected branch, e.g.
    ``("1.11.5", "1.12.1")``. A version in a listed (major, minor) branch is
    vulnerable iff its patch precedes that branch's fix — so ``1.12.0`` is
    correctly flagged vulnerable while ``1.12.1`` is patched. A branch older than
    every listed one is vulnerable; a branch newer than all of them is patched.
    """

    v = _parse_ver(version)
    if v is None:
        return "unknown"
    branches: dict[tuple[int, int], tuple[int, ...]] = {}
    for f in fixed:
        fv = _parse_ver(f)
        if fv and len(fv) >= 2:
            branches[(fv[0], fv[1])] = fv
    if not branches:
        return "unknown"
    key = (v[0], v[1]) if len(v) >= 2 else (v[0], 0)
    if key in branches:
        return "vulnerable" if v < branches[key] else "patched"
    if key < min(branches):
        return "vulnerable"
    if key > max(branches):
        return "patched"
    return "unknown"


def known_cves(controller: str, version: str | None) -> list[dict]:
    """The curated CVEs applicable to *controller* (display name), each annotated
    with a ``version_status`` for *version* (pure/offline).

    Sorted most-severe first, unauth ahead of privileged at equal severity, and
    confirmed-vulnerable ahead of unknown ahead of patched.
    """

    key = _CANON.get(controller)
    if key is None:
        return []
    keys = [key, *(_IMPLIES.get(key, ()))]
    status_rank = {"vulnerable": 2, "unknown": 1, "patched": 0}
    out: list[dict] = []
    for k in keys:
        for cve in _CONTROLLER_CVES.get(k, []):
            status = version_status(version, cve.fixed)
            out.append({
                "id": cve.id,
                "severity": cve.severity,
                "cvss": cve.cvss,
                "version_status": status,
                "unauth": cve.unauth,
                "fixed_in": list(cve.fixed),
                "summary": cve.summary,
                "detection": cve.detection,
            })
    out.sort(key=lambda c: (
        status_rank.get(c["version_status"], 0),
        _SEVERITY_RANK.get(c["severity"], 0),
        c["unauth"],
        c["cvss"],
    ), reverse=True)
    return out


# -- classification ----------------------------------------------------------
def _cert_tells(cert: TlsResult | None) -> list[dict]:
    """Detection-only TLS certificate tells for ingress-nginx (pure)."""

    if cert is None or not cert.connected:
        return []
    tells: list[dict] = []
    cn = (cert.subject or {}).get("commonName", "")
    org = (cert.subject or {}).get("organizationName", "")
    names = [cn, org, *(cert.subject_alt_names or [])]
    blob = " ".join(n for n in names if n).lower()
    if "kubernetes ingress controller fake certificate" in (cn or "").lower():
        tells.append({
            "tell": "fake_certificate",
            "controller": "ingress-nginx",
            "detail": "self-signed 'Kubernetes Ingress Controller Fake Certificate' served for an "
                      "unmapped host — ingress-nginx front door with imperfect TLS/host mapping.",
        })
    if "ingress-nginx-controller-admission" in blob:
        tells.append({
            "tell": "admission_webhook_san",
            "controller": "ingress-nginx",
            "detail": "certificate names the admission webhook (ingress-nginx-controller-admission) "
                      "— if this TLS endpoint answers unauthenticated it is the IngressNightmare "
                      "(CVE-2025-1974) precondition. Confirm reachability only; do NOT inject.",
        })
    return tells


def classify(
    main: HttpResult,
    unmatched: HttpResult | None = None,
    cert: TlsResult | None = None,
) -> dict:
    """Classify the ingress controller in front of a host from a main response, an
    optional unmatched-path response (for the default-backend 404 body), and an
    optional TLS certificate. Returns a detection-only report dict.
    """

    headers_lc = {k.lower(): v for k, v in main.headers}
    cookies = " ".join(main.get_all("set-cookie")).lower()
    body404 = unmatched.text(limit=4096) if unmatched is not None else ""

    matches: dict[str, dict] = {}
    for name, where, pattern, confidence in _SIGNATURES:
        if where.startswith("header:"):
            haystack = headers_lc.get(where.split(":", 1)[1], "")
        elif where == "cookie":
            haystack = cookies
        elif where == "body404":
            haystack = body404
        else:
            haystack = ""
        if not haystack:
            continue
        m = re.search(pattern, haystack, re.IGNORECASE)
        if not m:
            continue
        version = next((g for g in m.groups() if g), None) if m.groups() else None
        prev = matches.get(name)
        if prev is None:
            matches[name] = {
                "controller": name, "version": version,
                "evidence": where, "confidence": confidence,
            }
        else:
            # Keep the strongest evidence; fold in a version if we now have one.
            if _CONFIDENCE_RANK[confidence] > _CONFIDENCE_RANK[prev["confidence"]]:
                prev["confidence"] = confidence
                prev["evidence"] = where
            if version and not prev["version"]:
                prev["version"] = version

    cert_tells = _cert_tells(cert)
    # A fake-certificate / admission-SAN tell is strong evidence of ingress-nginx.
    if cert_tells and "ingress-nginx" not in matches:
        matches["ingress-nginx"] = {
            "controller": "ingress-nginx", "version": None,
            "evidence": "tls-cert", "confidence": "strong",
        }

    ranked = sorted(
        matches.values(),
        key=lambda mm: (_CONFIDENCE_RANK[mm["confidence"]], bool(mm["version"])),
        reverse=True,
    )
    primary = ranked[0] if ranked else None
    primary_name = primary["controller"] if primary else None
    version = primary["version"] if primary else None

    notes: list[str] = []
    if primary_name and version is None:
        notes.append(
            f"{primary_name} version not disclosed on the data plane (server_tokens off is the "
            "default) — read nginx_ingress_controller_build_info from :10254/metrics, Envoy "
            "/server_info, or the image tag to narrow the CVE set."
        )
    if any(t["tell"] == "admission_webhook_san" for t in cert_tells):
        notes.append(
            "Admission-webhook SAN present: the highest-signal, safest IngressNightmare check is "
            "confirming that TLS endpoint answers unauthenticated — reachability alone is the finding."
        )

    cves = known_cves(primary_name, version) if primary_name else []
    admin = _ADMIN_SURFACE.get(primary_name, []) if primary_name else []

    return {
        "controller": primary_name,
        "version": version,
        "confidence": primary["confidence"] if primary else None,
        "matches": ranked,
        "cert_tells": cert_tells,
        "applicable_cves": cves,
        "admin_surface": admin,
        "notes": notes,
    }
