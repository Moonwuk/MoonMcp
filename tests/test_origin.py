"""Origin-IP discovery — registrable base, MX exclusion, DNS-rebinding pin."""

import pytest

from moonmcp.recon import origin as om


def test_origin_base_avoids_public_suffix():
    assert om._origin_base("example.com") == "example.com"
    assert om._origin_base("www.example.com") == "example.com"
    assert om._origin_base("example.co.uk") == "example.co.uk"        # NOT stripped to co.uk
    assert om._origin_base("www.example.co.uk") == "example.co.uk"
    assert om._origin_base("a.b.example.com") == "b.example.com"       # still the same org


class _Dns:
    def __init__(self, a=None, records=None, canonical=None):
        self.a = a or []
        self.records = records or {}
        self.canonical_name = canonical
        self.error = None


class _Intel:
    def __init__(self, cloud=None, asn=None):
        self.cloud = cloud
        self.asn = asn


class _Tls:
    subject_alt_names: list[str] = []


@pytest.mark.asyncio
async def test_discover_origin_excludes_mx_and_pins_cert(monkeypatch):
    seen = {}

    async def _resolve(host, rdtypes=None, http_client=None):
        if "MX" in (rdtypes or ()):
            return _Dns(records={"MX": ["10 aspmx.l.google.com."]})
        return {
            "acme.com": _Dns(a=["1.1.1.1"]),            # CDN front
            "aspmx.l.google.com": _Dns(a=["9.9.9.9"]),  # shared mail IP
            "origin.acme.com": _Dns(a=["2.2.2.2"]),     # the real origin
        }.get(host, _Dns())

    async def _intel(client, ip):
        return {
            "1.1.1.1": _Intel(cloud="Cloudflare", asn="AS13335"),
            "9.9.9.9": _Intel(cloud="Google", asn="AS15169"),
        }.get(ip, _Intel(cloud="Hetzner", asn="AS24940"))

    async def _tls(host, port=443, connect_pin=None, **kw):
        seen["pin"] = connect_pin
        return _Tls()

    monkeypatch.setattr(om, "resolve", _resolve)
    monkeypatch.setattr(om, "ip_intel", _intel)
    monkeypatch.setattr(om, "inspect_certificate", _tls)

    sentinel = object()
    res = await om.discover_origin(object(), "acme.com", connect_pin=sentinel)
    assert seen["pin"] is sentinel                     # #6: the cert inspect is pinned
    assert res.behind_cdn is True
    assert "2.2.2.2" in res.likely_origins             # the off-CDN origin surfaces
    assert "9.9.9.9" not in res.likely_origins         # the shared MX IP does NOT
