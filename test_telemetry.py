"""Test TelemetryCollector — record 5 requests + 2 findings, verify get_stats."""

import os
import sys

# Ensure the moonmcp package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "MoonMcp"))

from moonmcp.telemetry.collector import TelemetryCollector


def test_telemetry_basic():
    tc = TelemetryCollector()

    # Record 5 requests
    tc.record_request("GET", "https://target.example.com/api/v1/users", 200, 0.15)
    tc.record_request("GET", "https://target.example.com/api/v1/users/1", 200, 0.08)
    tc.record_request("POST", "https://target.example.com/api/v1/login", 401, 0.30)
    tc.record_request("GET", "https://target.example.com/api/v1/admin", 403, 0.05)
    tc.record_request("GET", "https://target.example.com/api/v1/health", 500, 0.02)

    # Record 2 findings
    tc.record_finding("high", "sqli")
    tc.record_finding("critical", "rce")

    stats = tc.get_stats()

    # --- Assert requests_total ---
    assert stats["requests_total"] == 5, f"Expected 5, got {stats['requests_total']}"

    # --- Assert findings_by_severity ---
    assert stats["findings_by_severity"]["high"] == 1, f"Expected 1 high, got {stats['findings_by_severity']}"
    assert stats["findings_by_severity"]["critical"] == 1, f"Expected 1 critical, got {stats['findings_by_severity']}"
    assert stats["findings_by_severity"]["medium"] == 0
    assert stats["findings_by_severity"]["low"] == 0
    assert stats["findings_by_severity"]["info"] == 0

    # --- Assert error_rate ---
    # 3 errors out of 5 requests (401, 403, 500)
    assert stats["error_rate"] == 0.6, f"Expected 0.6, got {stats['error_rate']}"

    # --- Assert avg_response_time ---
    # (0.15 + 0.08 + 0.30 + 0.05 + 0.02) / 5 = 0.12
    assert stats["avg_response_time"] == 0.12, f"Expected 0.12, got {stats['avg_response_time']}"

    # --- Assert endpoints_tested ---
    # 5 unique method+url combinations
    assert stats["endpoints_tested"] == 5, f"Expected 5, got {stats['endpoints_tested']}"

    # --- Assert requests_per_min ---
    # All 5 requests were recorded within the last minute
    assert stats["requests_per_min"] == 5, f"Expected 5, got {stats['requests_per_min']}"

    # --- Assert coverage_pct ---
    # No endpoints_discovered set → 0.0
    assert stats["coverage_pct"] == 0.0

    # --- Test coverage when discovered is set ---
    tc.set_endpoints_discovered(10)
    stats2 = tc.get_stats()
    assert stats2["coverage_pct"] == 50.0, f"Expected 50.0, got {stats2['coverage_pct']}"

    # --- Test timeline ---
    timeline = tc.get_timeline(minutes=1)
    assert len(timeline) == 7, f"Expected 7 events, got {len(timeline)}"
    kinds = [e["kind"] for e in timeline]
    assert kinds.count("request") == 5
    assert kinds.count("finding") == 2

    # --- Test agent status change ---
    tc.record_agent_status("agent-1", "recon-agent", "running")
    tc.record_agent_status("agent-1", "recon-agent", "completed")
    timeline2 = tc.get_timeline(minutes=1)
    assert len(timeline2) == 9, f"Expected 9 events, got {len(timeline2)}"
    assert timeline2[-1]["kind"] == "agent_status_change"
    assert timeline2[-1]["detail"]["status"] == "completed"

    # --- Test ring buffer eviction ---
    tc_small = TelemetryCollector(ring_size=3)
    for i in range(5):
        tc_small.record_request("GET", f"https://example.com/{i}", 200, 0.01)
    assert tc_small.ring_size == 3, f"Expected 3, got {tc_small.ring_size}"
    assert tc_small.get_stats()["requests_total"] == 5, "Cumulative counter should survive ring eviction"

    print("✅ All telemetry tests passed!")


if __name__ == "__main__":
    test_telemetry_basic()