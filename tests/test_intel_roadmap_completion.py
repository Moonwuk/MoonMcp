"""Offline regressions for provider retries, version uncertainty and YAML data."""

import asyncio
import json
from datetime import datetime, timezone
from email.utils import format_datetime
from unittest.mock import AsyncMock

import pytest

from moonmcp import obsidian
from moonmcp.intel import cve, zeroday
from moonmcp.net.http import HttpResult


def response(status, retry_after=None, body=None, **kwargs):
    payload = {"totalResults": 1, "vulnerabilities": [{"cve": {"id": "CVE-2024-0001"}}]}
    return HttpResult("https://nvd.test/", "https://nvd.test/", status, "fixture",
                      [("Retry-After", retry_after)] if retry_after is not None else [],
                      json.dumps(payload if body is None else body).encode(), 1.0, **kwargs)


@pytest.fixture
def delays(monkeypatch):
    observed = []

    async def sleep(delay):
        observed.append(delay)

    monkeypatch.setattr(cve.asyncio, "sleep", sleep)
    return observed


async def call_provider(kind, client):
    if kind == "lookup":
        return await cve.lookup_cve(client, "CVE-2024-0001", api_key="provider-only")
    return await cve.search_cves(client, "fixture", api_key="provider-only")


@pytest.mark.parametrize("kind", ["lookup", "search"])
async def test_nvd_retries_transient_statuses_and_keeps_provider_auth(kind, delays):
    client = AsyncMock()
    client.fetch.side_effect = [response(429, "2"), response(503), response(200)]
    result = await call_provider(kind, client)
    assert (result.id if kind == "lookup" else result.results[0].id) == "CVE-2024-0001"
    assert client.fetch.await_count == 3 and delays == [2.0, 2.0]
    for call in client.fetch.await_args_list:
        assert call.kwargs["suppress_auth"] is True
        assert call.kwargs["headers"] == {"apiKey": "provider-only"}
        assert call.kwargs["timeout"] == 25.0


@pytest.mark.parametrize("kind", ["lookup", "search"])
async def test_nvd_retry_exhaustion_is_bounded_without_changing_legacy_contract(kind, delays):
    client = AsyncMock()
    client.fetch.return_value = response(429, "9999999999999999999")
    result = await call_provider(kind, client)
    assert client.fetch.await_count == 4 and delays == [30.0, 30.0, 30.0]
    if kind == "lookup":
        assert result is None  # historical optional-record boundary, not evidence of absence
    else:
        assert result.error == "HTTP 429" and not result.results


@pytest.mark.parametrize("status", [200, 400, 404])
@pytest.mark.parametrize("kind", ["lookup", "search"])
async def test_nvd_does_not_retry_absence_or_permanent_response(kind, status, delays):
    client = AsyncMock()
    client.fetch.return_value = response(status, body={"totalResults": 0, "vulnerabilities": []})
    result = await call_provider(kind, client)
    assert client.fetch.await_count == 1 and not delays
    if kind == "lookup":
        assert result is None
    else:
        assert result.error == (None if status == 200 else f"HTTP {status}")


@pytest.mark.parametrize("kind", ["lookup", "search"])
async def test_nvd_transient_transport_error_retries(kind, delays):
    client = AsyncMock()
    client.fetch.side_effect = [TimeoutError("fixture timeout"), response(200)]
    result = await call_provider(kind, client)
    assert result is not None and delays == [1.0]
    assert client.fetch.await_count == 2


@pytest.mark.parametrize("kind", ["lookup", "search"])
async def test_nvd_cancellation_during_backoff_never_resends(kind, monkeypatch):
    client = AsyncMock()
    client.fetch.return_value = response(429)
    monkeypatch.setattr(cve.asyncio, "sleep", AsyncMock(side_effect=asyncio.CancelledError))
    with pytest.raises(asyncio.CancelledError):
        await call_provider(kind, client)
    assert client.fetch.await_count == 1


@pytest.mark.parametrize("kind", ["lookup", "search"])
async def test_nvd_guard_failure_is_not_retried(kind, delays):
    client = AsyncMock()
    client.fetch.return_value = response(429, blocked_reason="scope blocked")
    await call_provider(kind, client)
    assert client.fetch.await_count == 1 and not delays


@pytest.mark.parametrize("hint", ["invalid", "NaN", "inf", "-1", "Wed, 99 Oct 2026 00:00:00 GMT"])
def test_invalid_retry_after_falls_back_to_bounded_backoff(hint):
    assert cve._retry_delay(response(429, hint), 1) == 2.0


def test_retry_after_http_date_is_bounded(monkeypatch):
    now = datetime(2026, 10, 21, tzinfo=timezone.utc)
    monkeypatch.setattr(cve.time, "time", lambda: now.timestamp())
    future = datetime(2026, 10, 21, 0, 0, 45, tzinfo=timezone.utc)
    assert cve._retry_delay(response(429, format_datetime(future, usegmt=True)), 0) == 30.0


@pytest.mark.parametrize("value", [
    'Found "admin": panel', "line\ninjected: true", "C:\\private\\file",
    "---\nadmin: true", "# comment", "text\u2028next\u2029line", "\x00control\r\nline",
    "text\x85next", "control\x7f\x8ftext",
])
def test_frontmatter_unsafe_scalars_cannot_inject_yaml(value):
    rendered = obsidian.frontmatter({"title": value, "tags": [value, "sev/high"]})
    lines = rendered.splitlines()
    assert len(lines) == 6
    assert lines[0] == lines[-1] == "---"
    # JSON quoted scalars are a YAML subset: independently decode their value
    # and verify that neither scalar nor list item added a structural line.
    assert json.loads(lines[1].removeprefix("title: ")) == value
    assert lines[2] == "tags:" and lines[4] == "  - sev/high"
    assert json.loads(lines[3].removeprefix("  - ")) == value


@pytest.mark.parametrize("value", ["true", "False", "yes", "ON", "null", "00123", "2026-10-21", "y", "N"])
def test_frontmatter_string_types_do_not_become_yaml_booleans_or_numbers(value):
    line = obsidian.frontmatter({"value": value}).splitlines()[1]
    assert json.loads(line.removeprefix("value: ")) == value


def test_frontmatter_keys_cannot_inject_mapping():
    key = "untrusted:\ninjected"
    rendered = obsidian.frontmatter({key: "finding"})
    assert len(rendered.splitlines()) == 3
    encoded = rendered.splitlines()[1].removesuffix(": finding")
    assert json.loads(encoded) == key


@pytest.mark.parametrize("target,lower,upper,expected", [
    ("1.2.3-alpha", "1.0.0", "1.2.3", "vulnerable"),
    ("1.2.3-rc.2", "1.0.0", "1.2.3-rc.10", "vulnerable"),
    ("1.2.3-rc.10", "1.0.0", "1.2.3-rc.2", "patched"),
    ("1.2.3", "1.0.0", "1.2.3-rc.10", "patched"),
    ("v1.2.3+build.42", "1.0.0", "1.2.3", "patched"),
    ("1.2", "1.0.0", "1.2.0.0", "patched"),
    ("0.9.9", "1.0.0", "1.2.3", "unknown"),
    ("1.2.3", "1.3.0", "1.2.3", "unknown"),
    ("1.2.3", "1.0.0", "", "unknown"),
    ("1.2.3", "unsupported", "1.2.3", "unknown"),
    ("1.2.3", "1.0.0", "unsupported", "unknown"),
])
def test_release_and_prerelease_range_comparison(target, lower, upper, expected):
    assert zeroday._version_in_range(target, lower, upper) == expected


@pytest.mark.parametrize("version", [
    "latest", "release 1.2.3", "1.2.3rc1", "1!1.2.3", "1.2.3-01",
    "1.2.3.post1", "1.2.3.4.5", "1.2.3/unsupported", "9" * 500 + ".0",
])
def test_unsupported_version_syntax_never_claims_patched(version):
    assert zeroday._version_in_range(version, "1.0.0", "1.2.3") == "unknown"


def test_semver_prerelease_precedence():
    ordered = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta",
               "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0"]
    parsed = [zeroday._parse_version(v) for v in ordered]
    assert all(a < b for a, b in zip(parsed, parsed[1:], strict=False))


def test_advisory_extractors_keep_prerelease_and_reject_unknown_suffix():
    description = "Affected from versions 1.0.0 to before 1.2.3-rc.2. Fixed in 1.2.3-rc.2."
    assert zeroday._extract_version_range(description) == ("1.0.0", "1.2.3-rc.2")
    assert zeroday._extract_fix_version(description) == "1.2.3-rc.2"
    assert not zeroday._extract_fix_version("Fixed in 1.2.3rc1")
    assert not zeroday._extract_fix_version("Fixed in 1.2.3.post1")


@pytest.mark.parametrize("version,collection", [("1.2.3-alpha", "unpatched"), ("latest", "unknown")])
async def test_public_version_check_preserves_uncertainty(version, collection, monkeypatch):
    record = cve.CveRecord("CVE-2024-0001", description="Affected before 1.2.3. Fixed in 1.2.3.")
    monkeypatch.setattr(cve, "search_cves", AsyncMock(return_value=cve.CveSearchResult(
        "fixture", total=1, results=[record])))
    result = await zeroday.version_vuln_check(None, "fixture", version)
    assert len(getattr(result, collection)) == 1
    assert not result.patched
