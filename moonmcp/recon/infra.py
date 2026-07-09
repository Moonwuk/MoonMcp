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

    server_versions = sorted({b["server"] for b in backends if b["server"]})
    patch_drift = len(server_versions) > 1
    dates = [s["date_epoch"] for s in samples if s.get("date_epoch")]
    skew = round(max(dates) - min(dates), 1) if len(dates) >= 2 else 0.0

    concerns: list[str] = []
    if patch_drift:
        concerns.append(f"backends report different Server versions {server_versions} — "
                        "possible patch drift; the lagging node may be individually vulnerable")
    if skew > 2:
        concerns.append(f"~{skew:.0f}s clock skew between backends — nodes are not time-synced")
    return {
        "distinct_backends": len(groups),
        "load_balanced": len(groups) > 1,
        "backends": backends,
        "patch_drift": patch_drift,
        "server_versions": server_versions if patch_drift else [],
        "clock_skew_seconds": skew,
        "concerns": concerns,
    }


# CDN / WAF / cache / proxy vendors, by header signatures ("key:value" lowercased).
_EDGE_SIGNS: list[tuple[str, list[str]]] = [
    ("Cloudflare", ["cf-ray:", "cf-cache-status:", "server:cloudflare"]),
    ("CloudFront", ["x-amz-cf-id:", "x-amz-cf-pop:", "via:", "server:cloudfront"]),
    ("Fastly", ["x-served-by:cache", "x-fastly", "fastly"]),
    ("Akamai", ["x-akamai", "akamai", "server:akamaighost"]),
    ("Varnish", ["x-varnish:", "via:varnish", "via: varnish"]),
    ("Sucuri", ["x-sucuri-id:", "x-sucuri-cache:", "server:sucuri"]),
    ("Imperva/Incapsula", ["x-iinfo:", "incap_ses", "visid_incap"]),
    ("AWS ELB/ALB", ["server:awselb", "awsalb="]),
    ("Vercel", ["server:vercel", "x-vercel-"]),
    ("Netlify", ["server:netlify", "x-nf-request-id:"]),
    ("Google Frontend", ["server:gws", "server:google frontend", "via:1.1 google"]),
]
_CACHE_HDRS = ("age", "x-cache", "cf-cache-status", "x-cache-hits", "x-served-by")
_CDN_VENDORS = {"Cloudflare", "CloudFront", "Fastly", "Akamai", "Sucuri",
                "Imperva/Incapsula", "Google Frontend"}


def edge_layers(headers: dict[str, str]) -> dict:
    """Detect CDN/WAF/cache/proxy layers in front of the origin from headers."""

    low = {k.lower(): (v or "") for k, v in headers.items()}
    text = " ".join(f"{k}:{v}" for k, v in low.items()).lower()
    vendors = sorted({name for name, signs in _EDGE_SIGNS if any(s in text for s in signs)})
    via = low.get("via", "")
    proxy_hops = [h.strip() for h in via.split(",") if h.strip()]
    cache_headers = [h for h in _CACHE_HDRS if h in low]
    behind_cdn = any(v in _CDN_VENDORS for v in vendors)
    concerns: list[str] = []
    if behind_cdn:
        concerns.append("a CDN/WAF fronts the origin — find the real origin (origin_discovery) "
                        "to test it directly and bypass the edge protection")
    elif not vendors:
        concerns.append("no CDN/WAF fronting detected — requests likely reach the origin directly")
    return {"vendors": vendors, "behind_cdn": behind_cdn,
            "proxy_hops": proxy_hops, "cache_layer": bool(cache_headers),
            "cache_headers": cache_headers, "concerns": concerns}


def summarize_http_behavior(*, baseline_status: int | None, connection: str | None,
                            http10_status: int | None, invalid_method_status: int | None,
                            oversized_status: int | None, bare_lf_status: int | None) -> dict:
    """Turn raw HTTP/1.x edge-case reactions into a behaviour profile + concerns."""

    bare_lf_accepted = bare_lf_status is not None and 200 <= bare_lf_status < 400
    concerns: list[str] = []
    if bare_lf_accepted:
        concerns.append("server accepted bare-LF (no CR) line endings — lenient HTTP parsing, a "
                        "request-smuggling / desync risk factor; confirm with desync_probe")
    if oversized_status is None:
        concerns.append("connection dropped on an oversized header (no HTTP response) — an "
                        "intermediary enforced a header-size limit before the origin")
    return {
        "baseline_status": baseline_status,
        "keep_alive": (connection or "").lower() != "close",
        "connection_header": connection,
        "http_1_0_status": http10_status,
        "invalid_method_status": invalid_method_status,
        "oversized_header_status": oversized_status,
        "bare_lf_status": bare_lf_status,
        "bare_lf_accepted": bare_lf_accepted,
        "concerns": concerns,
    }


def ratelimit_summary(statuses: list[int | None], *, first_block: int | None,
                      retry_after: str | None, bypass_reset: bool | None) -> dict:
    """Summarise a burst's status codes into a rate-limit behaviour profile."""

    blocked = [s for s in statuses if s in (429, 403, 503)]
    verdict = "no_rate_limit"
    if first_block is not None:
        verdict = "rate_limited"
    concerns: list[str] = []
    if bypass_reset:
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
