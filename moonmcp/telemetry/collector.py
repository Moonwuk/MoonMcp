"""Telemetry collector — real-time scan-progress monitoring.

Inspired by Strix's ``telemetry/`` module, this provides a lightweight,
stdlib-only collector that tracks:

* HTTP request volume and error rate (from :meth:`record_request`),
* Finding counts by severity (from :meth:`record_finding`),
* Agent status changes (from :meth:`record_agent_status`),
* Coverage estimate (endpoints tested vs discovered),
* A unified timeline of all event types.

All data is kept in a bounded ring buffer (default 1000 entries) so the
collector uses a predictable amount of memory regardless of session length.
Pure in-memory, session-scoped — nothing is persisted to disk.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_RING_SIZE = 1000
_SEVERITIES = ("critical", "high", "medium", "low", "info")
_SEV_ORDER = {s: i for i, s in enumerate(_SEVERITIES)}


# ---------------------------------------------------------------------------
# Event dataclass
# ---------------------------------------------------------------------------

@dataclass
class TelemetryEvent:
    """One entry in the telemetry ring buffer."""

    kind: str          # "request" | "finding" | "agent_status_change"
    timestamp: float   # Unix epoch (time.time())
    detail: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------

class TelemetryCollector:
    """Bounded, in-memory telemetry collector for a MoonMCP session.

    Thread-safety: MoonMCP is single-threaded async, so no locks are used.
    If the collector is ever shared across threads, wrap calls in a lock.
    """

    def __init__(self, ring_size: int = _RING_SIZE) -> None:
        self._ring: deque[TelemetryEvent] = deque(maxlen=ring_size)

        # Cumulative counters (not affected by ring-buffer eviction)
        self._requests_total: int = 0
        self._errors_total: int = 0          # 4xx + 5xx
        self._durations_total: float = 0.0   # sum of request durations in seconds
        self._endpoints_tested: set[str] = set()
        self._endpoints_discovered: int = 0
        self._findings_by_severity: dict[str, int] = {s: 0 for s in _SEVERITIES}

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def record_request(self, method: str, url: str, status: int,
                        duration: float) -> None:
        """Record an HTTP request into the ring buffer and update counters.

        Parameters
        ----------
        method : str
            HTTP method (GET, POST, ...).
        url : str
            The full request URL.
        status : int
            HTTP status code returned by the server.
        duration : float
            Request duration in **seconds**.
        """

        ts = time.time()
        self._requests_total += 1
        self._durations_total += duration
        if status >= 400:
            self._errors_total += 1
        self._endpoints_tested.add(f"{method} {url}")

        self._ring.append(TelemetryEvent(
            kind="request",
            timestamp=ts,
            detail={
                "method": method,
                "url": url,
                "status": status,
                "duration": round(duration, 4),
            },
        ))

    def record_finding(self, severity: str, type: str) -> None:
        """Record a finding event and bump the severity counter.

        Parameters
        ----------
        severity : str
            One of ``critical``, ``high``, ``medium``, ``low``, ``info``
            (case-insensitive; unknown values are normalised to ``info``).
        type : str
            Finding type label (e.g. ``sqli``, ``xss``, ``idor``).
        """

        sev = severity.lower().strip()
        if sev not in self._findings_by_severity:
            sev = "info"
        self._findings_by_severity[sev] += 1

        self._ring.append(TelemetryEvent(
            kind="finding",
            timestamp=time.time(),
            detail={"severity": sev, "type": type},
        ))

    def record_agent_status(self, agent_id: str, name: str,
                             status: str) -> None:
        """Record an agent status-change event in the timeline."""

        self._ring.append(TelemetryEvent(
            kind="agent_status_change",
            timestamp=time.time(),
            detail={"agent_id": agent_id, "name": name, "status": status},
        ))

    def set_endpoints_discovered(self, count: int) -> None:
        """Set the total number of discovered endpoints (for coverage %)."""
        self._endpoints_discovered = max(count, 0)

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_stats(self) -> dict:
        """Return a snapshot of aggregate session statistics.

        Returns
        -------
        dict
            Keys:
            - ``requests_total`` — total HTTP requests recorded.
            - ``requests_per_min`` — requests in the last 60 s.
            - ``findings_by_severity`` — ``{severity: count}``.
            - ``error_rate`` — fraction of requests with status >= 400.
            - ``avg_response_time`` — mean request duration in seconds.
            - ``endpoints_tested`` — number of unique endpoints tested.
            - ``coverage_pct`` — ``endpoints_tested / discovered * 100``
              (0 if discovered is unset/zero).
        """

        now = time.time()
        # Requests per minute: count request events in the last 60 s
        rpm = sum(
            1
            for e in self._ring
            if e.kind == "request" and (now - e.timestamp) <= 60.0
        )

        avg_resp = (
            round(self._durations_total / self._requests_total, 4)
            if self._requests_total
            else 0.0
        )
        error_rate = (
            round(self._errors_total / self._requests_total, 4)
            if self._requests_total
            else 0.0
        )
        coverage = (
            round(len(self._endpoints_tested) / self._endpoints_discovered * 100, 1)
            if self._endpoints_discovered > 0
            else 0.0
        )

        return {
            "requests_total": self._requests_total,
            "requests_per_min": rpm,
            "findings_by_severity": dict(self._findings_by_severity),
            "error_rate": error_rate,
            "avg_response_time": avg_resp,
            "endpoints_tested": len(self._endpoints_tested),
            "coverage_pct": coverage,
        }

    def get_timeline(self, minutes: int = 10) -> list[dict]:
        """Return timeline events from the last *minutes* minutes.

        Parameters
        ----------
        minutes : int
            How many minutes of history to return (default 10).

        Returns
        -------
        list[dict]
            Chronological list of events, each with ``kind``, ``timestamp``
            (ISO-ish epoch float), and ``detail``.
        """

        cutoff = time.time() - minutes * 60
        events = [
            {
                "kind": e.kind,
                "timestamp": round(e.timestamp, 3),
                "detail": e.detail,
            }
            for e in self._ring
            if e.timestamp >= cutoff
        ]
        return events

    # ------------------------------------------------------------------
    # Introspection helpers
    # ------------------------------------------------------------------

    @property
    def ring_capacity(self) -> int:
        return self._ring.maxlen or _RING_SIZE

    @property
    def ring_size(self) -> int:
        return len(self._ring)