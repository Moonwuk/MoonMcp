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
