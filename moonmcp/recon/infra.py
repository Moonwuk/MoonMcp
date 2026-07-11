"""Behavioural infrastructure detectors — infer the *shape* of the infra from how
it responds, not from a single reply.

Static recon reads one response; these read the **variance across many**: multiple
backends behind a load balancer (and whether they are patched consistently), clock
drift between nodes, how the edge routes an unexpected Host header, and how the
rate limiter actually behaves. Pure analysers here; the async probing lives in the
server tools.
"""

from __future__ import annotations

from email.utils import parsedate_to_datetime


def parse_http_date(value: str | None) -> float | None:
    """A ``Date:`` header → POSIX timestamp (the server's clock), or None."""

    if not value:
        return None
    try:
        return parsedate_to_datetime(value).timestamp()
    except (TypeError, ValueError, IndexError):
        return None


def _sig(sample: dict) -> tuple:
    """A stable-ish backend discriminator from one response."""

    return (
        (sample.get("server") or "").strip().lower(),
        (sample.get("powered_by") or "").strip().lower(),
        (sample.get("via") or "").strip().lower(),
        (sample.get("backend") or "").strip().lower(),
        tuple(sorted(sample.get("cookies") or [])),
        # Response header-NAME ordering is a covert per-backend fingerprint: distinct
        # server software/config emits headers in a distinct order even when the values
        # match. A stateless per-response scanner never compares ordering across samples.
        tuple(sample.get("header_order") or ()),
    )


def cluster_backends(samples: list[dict]) -> dict:
    """Cluster response samples into distinct backends and flag inconsistencies.

    Each sample: ``{server, powered_by, via, backend, cookies[], date_epoch,
    elapsed_ms}``. Reports how many distinct backends answered, whether their
    server versions differ (**patch drift** — one node may lag on fixes), and the
    clock skew between nodes.
    """

    groups: dict[tuple, list[dict]] = {}
    for s in samples:
        groups.setdefault(_sig(s), []).append(s)

    backends: list[dict] = []
    for _sigkey, members in groups.items():
        m0 = members[0]
        elapsed = [x.get("elapsed_ms", 0.0) for x in members]
        backends.append({
            "server": m0.get("server"),
            "powered_by": m0.get("powered_by"),
            "via": m0.get("via"),
            "backend_id": m0.get("backend"),
            "cookies": m0.get("cookies") or [],
            "hits": len(members),
            "avg_ms": round(sum(elapsed) / len(elapsed), 1) if elapsed else 0.0,
        })
    backends.sort(key=lambda b: -b["hits"])
    load_balanced = len(groups) > 1

    # Patch drift and clock skew are only meaningful across a genuine multi-backend
    # fleet — a single slow backend must never be reported as several out-of-sync
    # nodes. Also drop bare Server names that are a prefix of a more specific one
    # ("nginx" vs "nginx/1.25.1" is the same product, not two versions).
    raw_versions = sorted({b["server"] for b in backends if b["server"]})
    # Drop only a BARE product name ("nginx") that is a prefix of a versioned form
    # ("nginx/1.25.1"). A token that already carries a version is never collapsed —
    # otherwise "nginx/1.2" would be swallowed by "nginx/1.25.1" and real drift lost.
    server_versions = [
        s for s in raw_versions
        if any(ch.isdigit() for ch in s)
        or not any(o != s and o.startswith(s + "/") for o in raw_versions)
    ]
    patch_drift = load_balanced and len(server_versions) > 1

    skew = 0.0
    if load_balanced:
        reps = []
        for members in groups.values():
            ds = [m["date_epoch"] for m in members if m.get("date_epoch")]
            if ds:
                reps.append(min(ds))  # each backend's earliest observed Date
        skew = round(max(reps) - min(reps), 1) if len(reps) >= 2 else 0.0

    # Content drift: different backends returning a different ETag / Last-Modified for
    # the SAME URL means they serve different builds — a stale node may expose old code
    # or a since-patched vulnerability. Gated on a real fleet (like patch drift).
    content_versions: set[tuple[str, str]] = set()
    for members in groups.values():
        for m in members:
            tag = ((m.get("etag") or "").strip(), (m.get("last_modified") or "").strip())
            if tag != ("", ""):
                content_versions.add(tag)
    content_drift = load_balanced and len(content_versions) > 1

    concerns: list[str] = []
    if patch_drift:
        concerns.append(f"backends report different Server versions {server_versions} — "
                        "possible patch drift; the lagging node may be individually vulnerable")
    if content_drift:
        concerns.append("backends return different ETag/Last-Modified for the same URL — "
                        "content/build drift across the fleet; a stale node may serve old code")
    if skew > 2:
        concerns.append(f"~{skew:.0f}s clock skew between backends — nodes are not time-synced")
    return {
        "distinct_backends": len(groups),
        "load_balanced": load_balanced,
        "backends": backends,
        "patch_drift": patch_drift,
        "server_versions": server_versions if patch_drift else [],
        "content_drift": content_drift,
        "content_versions": (
            [f"etag={e or '-'} last-modified={lm or '-'}" for e, lm in sorted(content_versions)]
            if content_drift else []),
        "clock_skew_seconds": skew,
        "concerns": concerns,
    }


# Vendor detection is anchored to where the signal actually proves fronting — an
# exact header KEY, a substring of the Server value, or a substring of the Via
# value — never a bare substring of the whole header blob (which false-positived
# e.g. any "Via:" as CloudFront and CDN names appearing in CSP/Link values).
_EDGE_KEY: dict[str, str] = {
    "cf-ray": "Cloudflare", "cf-cache-status": "Cloudflare",
    "x-amz-cf-id": "CloudFront", "x-amz-cf-pop": "CloudFront",
    "x-fastly-request-id": "Fastly",
    "x-akamai-transformed": "Akamai", "akamai-grn": "Akamai", "x-akamai-request-id": "Akamai",
    "x-varnish": "Varnish",
    "x-sucuri-id": "Sucuri", "x-sucuri-cache": "Sucuri",
    "x-iinfo": "Imperva/Incapsula",
    "x-nf-request-id": "Netlify",
    "x-vercel-id": "Vercel", "x-vercel-cache": "Vercel",
}
_SERVER_SIGNS: dict[str, str] = {
    "cloudflare": "Cloudflare", "cloudfront": "CloudFront", "akamaighost": "Akamai",
    "sucuri": "Sucuri", "awselb": "AWS ELB/ALB", "vercel": "Vercel", "netlify": "Netlify",
    "gws": "Google Frontend", "google frontend": "Google Frontend", "varnish": "Varnish",
}
_VIA_SIGNS: dict[str, str] = {
    "cloudfront": "CloudFront", "varnish": "Varnish", "google": "Google Frontend",
    "vegur": "Heroku", "squid": "Squid", "haproxy": "HAProxy",
}
_CACHE_HDRS = ("age", "x-cache", "cf-cache-status", "x-cache-hits")
_CDN_VENDORS = {"Cloudflare", "CloudFront", "Fastly", "Akamai", "Sucuri",
                "Imperva/Incapsula", "Google Frontend"}


def edge_layers(headers: dict[str, str]) -> dict:
    """Detect CDN/WAF/cache/proxy layers in front of the origin from headers."""

    low = {k.lower(): (v or "") for k, v in headers.items()}
    vendors: set[str] = set()
    for key, vendor in _EDGE_KEY.items():
        if key in low:
            vendors.add(vendor)
    server = low.get("server", "").lower()
    for sub, vendor in _SERVER_SIGNS.items():
        if sub in server:
            vendors.add(vendor)
    via = low.get("via", "").lower()
    for sub, vendor in _VIA_SIGNS.items():
        if sub in via:
            vendors.add(vendor)
    if "cache" in low.get("x-served-by", "").lower():
        vendors.add("Fastly")  # Fastly/Varnish CDN cache node

    proxy_hops = [h.strip() for h in low.get("via", "").split(",") if h.strip()]
    cache_headers = [h for h in _CACHE_HDRS if h in low]
    behind_cdn = any(v in _CDN_VENDORS for v in vendors)
    concerns: list[str] = []
    if behind_cdn:
        concerns.append("a CDN/WAF fronts the origin — find the real origin (origin_discovery) "
                        "to test it directly and bypass the edge protection")
    elif not vendors:
        concerns.append("no CDN/WAF fronting detected — requests likely reach the origin directly")
    return {"vendors": sorted(vendors), "behind_cdn": behind_cdn,
            "proxy_hops": proxy_hops, "cache_layer": bool(cache_headers),
            "cache_headers": cache_headers, "concerns": concerns}


def summarize_http_behavior(*, baseline_status: int | None, connection: str | None,
                            http10_status: int | None, invalid_method_status: int | None,
                            oversized_status: int | None, bare_lf_status: int | None,
                            bare_cr_status: int | None = None, obs_fold_status: int | None = None,
                            dup_cl_status: int | None = None) -> dict:
    """Turn raw HTTP/1.x edge-case reactions into a behaviour profile + concerns.

    ``bare_cr``/``obs_fold``/``dup_cl`` are optional additional framing probes; each
    accepted (non-error) reaction is a lenient-parsing / proxy-origin-mismatch signal.
    """

    def _accepted(s: int | None) -> bool:
        return s is not None and 200 <= s < 400

    bare_lf_accepted = _accepted(bare_lf_status)
    bare_cr_accepted = _accepted(bare_cr_status)
    obs_fold_accepted = _accepted(obs_fold_status)
    dup_cl_accepted = _accepted(dup_cl_status)
    concerns: list[str] = []
    if bare_lf_accepted:
        concerns.append("server accepted bare-LF (no CR) line endings — lenient HTTP parsing, a "
                        "request-smuggling / desync risk factor; confirm with desync_probe")
    if bare_cr_accepted:
        concerns.append("server accepted bare-CR line endings — lenient HTTP parsing / desync risk "
                        "factor; a CR-strict peer in front would disagree on framing")
    if obs_fold_accepted:
        concerns.append("server accepted obsolete line folding (obs-fold) — RFC 7230-deprecated; a "
                        "proxy-origin header-parsing mismatch (smuggling factor)")
    if dup_cl_accepted:
        concerns.append("server accepted duplicate Content-Length headers — CL.CL framing ambiguity; "
                        "confirm with desync_modern_probe")
    if oversized_status is None:
        concerns.append("connection dropped on an oversized header (no HTTP response) — an "
                        "intermediary enforced a header-size limit before the origin")
    return {
        "baseline_status": baseline_status,
        # keep-alive can't be asserted from a Connection: close probe; report the
        # server's Connection header verbatim rather than a misleading boolean.
        "connection_header": connection,
        "http_1_0_status": http10_status,
        "invalid_method_status": invalid_method_status,
        "oversized_header_status": oversized_status,
        "bare_lf_status": bare_lf_status,
        "bare_lf_accepted": bare_lf_accepted,
        "bare_cr_status": bare_cr_status,
        "bare_cr_accepted": bare_cr_accepted,
        "obs_fold_status": obs_fold_status,
        "obs_fold_accepted": obs_fold_accepted,
        "dup_cl_status": dup_cl_status,
        "dup_cl_accepted": dup_cl_accepted,
        "concerns": concerns,
    }


def ratelimit_summary(statuses: list[int | None], *, first_block: int | None,
                      retry_after: str | None, bypass_reset: bool | None) -> dict:
    """Summarise a burst's status codes into a rate-limit behaviour profile."""

    blocked = [s for s in statuses if s in (429, 403, 503)]
    first_ok = bool(statuses) and statuses[0] not in (429, 403, 503)
    # Rate limiting means early requests SUCCEED and a later one is blocked. A block
    # on request #1 (or a status that's constant across the burst) is a baseline
    # error / blanket block, not throttling.
    if first_block is not None and first_block > 1 and first_ok:
        verdict = "rate_limited"
    elif first_block is not None:
        verdict = "endpoint_blocked"  # blocked from the start — not throttling
    else:
        verdict = "no_rate_limit"
    concerns: list[str] = []
    if verdict == "endpoint_blocked":
        concerns.append("the endpoint returns a block status from the first request — a blanket "
                        "block / auth requirement, not rate limiting")
    if bypass_reset and verdict == "rate_limited":
        concerns.append("changing X-Forwarded-For reset the limit — the limiter keys on a "
                        "spoofable client-IP header (per-IP bypass)")
    if first_block is None and len(statuses) >= 10:
        concerns.append("no throttling observed across the burst — endpoint may lack rate "
                        "limiting (brute-force / enumeration / resource-exhaustion surface)")
    return {
        "verdict": verdict,
        "requests_sent": len(statuses),
        "blocked_count": len(blocked),
        "first_block_at_request": first_block,
        "retry_after": retry_after,
        "ip_header_bypass": bool(bypass_reset),
        "concerns": concerns,
    }
