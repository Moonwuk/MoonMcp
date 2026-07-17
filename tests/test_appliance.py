"""Edge-appliance fingerprint → version → KEV-CVE oracle."""

from urllib.parse import urlsplit

import pytest

from moonmcp import server as srv
from moonmcp.web import appliance as ap


def _prod(name_sub):
    return next(p for p in ap.PRODUCTS if name_sub in p.name)


# -- pure analysers ---------------------------------------------------------
def test_match_product():
    citrix = _prod("Citrix")
    assert ap.match_product(citrix, "... set-cookie: nsc_aaac=x ...") == "nsc_aaac"
    assert ap.match_product(citrix, "just an ordinary page") is None


def test_haystack_lowercases_body_and_headers():
    hay = ap.haystack("<h1>Pulse</h1>", ["Set-Cookie: DSID=abc"])
    assert "pulse" in hay and "dsid=abc" in hay


def test_extract_version_ivanti():
    ivanti = _prod("Ivanti")
    assert ap.extract_version(ivanti, "<version>22.7R2.4</version>") == "22.7R2.4"
    assert ap.extract_version(ivanti, "no version here") is None


def test_every_product_has_kev_cves():
    for p in ap.PRODUCTS:
        assert p.cves and any(c.get("kev") for c in p.cves), p.name


# -- probe against fake appliances ------------------------------------------
class _R:
    def __init__(self, status, text="", cookies=None):
        self.status = status
        self._t = text
        self._c = cookies or []

    def text(self, limit=None):
        return self._t

    def headers_map(self):
        return {"Content-Type": "text/html"}

    def get_all(self, name):
        return list(self._c) if name.lower() == "set-cookie" else []


class _Citrix:
    async def fetch(self, url, **kw):
        if urlsplit(url).path == "/vpn/index.html":
            return _R(200, "<html>Citrix Gateway</html>", cookies=["NSC_AAAC=abc; Secure"])
        return _R(404, "nf")


class _Ivanti:
    async def fetch(self, url, **kw):
        p = urlsplit(url).path
        if p == "/dana-na/auth/url_default/welcome.cgi":
            return _R(200, "<html>Welcome</html>", cookies=["DSID=xyz"])
        if p == "/dana-na/nc/nc_gina_ver.txt":
            return _R(200, "<version>22.7R2.4</version>")
        return _R(404, "nf")


class _Fortinet:
    async def fetch(self, url, **kw):
        if urlsplit(url).path == "/remote/login":
            return _R(200, "<form action='/remote/logincheck'>fgt_lang forticlient</form>")
        return _R(404, "nf")


class _NotAppliance:
    async def fetch(self, url, **kw):
        return _R(200, "<html>a normal marketing site</html>")


@pytest.mark.asyncio
async def test_probe_citrix():
    res = await ap.probe_appliance(_Citrix(), "https://vpn.x.test")
    assert res["verdict"] == "appliance_detected"
    f = next(x for x in res["findings"] if "Citrix" in x["product"])
    assert f["matched"]["signal"] == "nsc_aaac" and f["severity"] == "high"
    assert any("CVE-2023-4966" in c["id"] for c in f["cves"])


@pytest.mark.asyncio
async def test_probe_ivanti_with_version():
    res = await ap.probe_appliance(_Ivanti(), "https://vpn.x.test")
    f = next(x for x in res["findings"] if "Ivanti" in x["product"])
    assert f["version"] == "22.7R2.4"


@pytest.mark.asyncio
async def test_probe_fortinet():
    res = await ap.probe_appliance(_Fortinet(), "https://fw.x.test")
    assert any("Fortinet" in x["product"] for x in res["findings"])


@pytest.mark.asyncio
async def test_probe_not_appliance():
    res = await ap.probe_appliance(_NotAppliance(), "https://x.test")
    assert res["verdict"] == "none" and res["findings"] == []


@pytest.mark.asyncio
async def test_appliance_cve_probe_registered():
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "appliance_cve_probe" in tools
