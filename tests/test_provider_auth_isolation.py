"""Provider-only OSINT requests must not carry engagement credentials."""

import json

import pytest

from moonmcp.intel import cve, reader, search
from moonmcp.net import http
from moonmcp.net.http import HttpClient, HttpResult
from moonmcp.net.ratelimit import Governor
from moonmcp.recon import subdomains, wayback


@pytest.mark.parametrize("provider", [
    "crtsh", "hackertarget", "anubis", "otx", "wayback", "cve_lookup", "cve_search",
    "web_search", "web_read",
])
async def test_provider_requests_suppress_engagement_headers_but_keep_provider_key(
        provider, monkeypatch):
    captured = []
    engagement_headers = {
        "Authorization": "Bearer engagement-only", "Cookie": "session=engagement-only",
        "X-Api-Key": "engagement-only", "X-Bug-Bounty": "private-program-id",
    }
    client = HttpClient(Governor(0, 4), user_agent="test",
                        auth_provider=lambda: dict(engagement_headers))
    bodies = {
        "crtsh": b'[{"name_value":"api.example.com"}]',
        "hackertarget": b"api.example.com,192.0.2.1",
        "anubis": b'["api.example.com"]',
        "otx": b'{"passive_dns":[{"hostname":"api.example.com"}]}',
        "wayback": b'[["original"],["https://example.com/archived"]]',
        "web_search": b'{"results":[{"title":"Public reference", "url":"https://reference.test/"}]}',
        "web_read": b"Public reference text.",
    }
    nvd_body = json.dumps({
        "totalResults": 1, "vulnerabilities": [{"cve": {"id": "CVE-2024-0001"}}],
    }).encode()

    def transport(url, method, headers, *args):
        captured.append((url, dict(headers)))
        return HttpResult(url, url, 200, "OK", [("Content-Type", "application/json")],
                          bodies.get(provider, nvd_body), 1.0)

    monkeypatch.setattr(http, "_USE_CURL_CFFI", False)
    monkeypatch.setattr(http, "_blocking_fetch", transport)
    if provider in subdomains._SOURCES:
        result = await subdomains.enumerate_subdomains(client, "example.com", sources=[provider])
        assert result.subdomains == ["api.example.com"]
    elif provider == "wayback":
        assert (await wayback.fetch_wayback_urls(client, "example.com")).urls == [
            "https://example.com/archived"]
    elif provider == "cve_lookup":
        result = await cve.lookup_cve(client, "CVE-2024-0001", api_key="nvd-only")
        assert result is not None and result.id == "CVE-2024-0001"
    elif provider == "cve_search":
        result = await cve.search_cves(client, "reference", api_key="nvd-only")
        assert result.results[0].id == "CVE-2024-0001"
    elif provider == "web_search":
        monkeypatch.setattr(search, "_CACHE", {})
        monkeypatch.setattr(search, "_ENGINES", (
            ("searxng", "https://search-provider.test/search?q=", search.parse_searxng),))
        result = await search.web_search(client, "public reference")
        assert result["results"][0]["url"] == "https://reference.test/"
    else:
        result = await reader.web_read(client, "https://reference.test/")
        assert result["text"] == "Public reference text."
    assert len(captured) == 1
    headers = {key.lower(): value for key, value in captured[0][1].items()}
    assert not ({key.lower() for key in engagement_headers} & headers.keys())
    if provider.startswith("cve_"):
        assert headers["apikey"] == "nvd-only"
    else:
        assert "apikey" not in headers


async def test_provider_key_is_not_forwarded_to_cross_origin_redirect(monkeypatch):
    captured = []
    client = HttpClient(Governor(0, 4), user_agent="test", auth_provider=lambda: {
        "Authorization": "Bearer engagement-only", "Cookie": "session=engagement-only",
    })

    def transport(url, method, headers, *args):
        captured.append((url, dict(headers)))
        if len(captured) == 1:
            return HttpResult(url, url, 302, "Found", [("Location", "https://mirror.test/data")],
                              b"", 1.0)
        return HttpResult(url, url, 200, "OK", [], b'{"totalResults":0,"vulnerabilities":[]}', 1.0)

    monkeypatch.setattr(http, "_USE_CURL_CFFI", False)
    monkeypatch.setattr(http, "_blocking_fetch", transport)
    result = await cve.search_cves(client, "reference", api_key="nvd-only")
    assert not result.error and len(captured) == 2
    first = {key.lower(): value for key, value in captured[0][1].items()}
    second = {key.lower(): value for key, value in captured[1][1].items()}
    assert first["apikey"] == "nvd-only"
    assert "apikey" not in second
    assert not ({"authorization", "cookie"} & (first.keys() | second.keys()))
