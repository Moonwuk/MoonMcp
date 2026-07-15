"""Path-normalization ACL bypass (403/401 bypass)."""

import pytest

from moonmcp import server as srv
from moonmcp.web import pathnorm as pn


# -- pure helpers -----------------------------------------------------------
def test_variants_are_unique_and_transform_the_path():
    twins = pn.bypass_variants("https://x.test/admin/users")
    urls = [u for _, u in twins]
    assert len(urls) == len(set(urls))            # deduped
    assert "https://x.test/admin/users" not in urls  # never the original
    assert any("/admin/users/..;/" == u.split("x.test", 1)[1] or "..;" in u for u in urls)
    assert any("%2e" in u for u in urls)
    assert any(";x" in u for u in urls)           # matrix segment
    assert any("/admin//users" in u for u in urls)  # double slash


def test_variants_preserve_query():
    twins = pn.bypass_variants("https://x.test/admin?tab=1")
    assert all("tab=1" in u for _, u in twins)


def test_ingress_mesh_and_external_auth_twins():
    twins = pn.bypass_variants("https://x.test/admin")
    labels = {label for label, _ in twins}
    urls = [u for _, u in twins]
    assert "double-slash prefix" in labels
    assert any(u.endswith("//admin") for u in urls)          # Istio //
    assert any("%2fadmin" in u for u in urls)                # Envoy %2f
    assert any("/ADMIN" in u for u in urls)                  # Istio case
    assert any("%23" in u for u in urls)                     # Istio fragment
    # external-auth ($request_uri) traversal lane
    assert any("moonmcp/..%2fadmin" in u for u in urls)
    assert any("moonmcp/../admin" in u for u in urls)
    # invariants still hold with the new twins
    assert len(urls) == len(set(urls))
    assert "https://x.test/admin" not in urls


def test_assess_bypass_only_on_protected_to_2xx():
    assert pn.assess_bypass(403, 200) is True
    assert pn.assess_bypass(401, 204) is True
    assert pn.assess_bypass(200, 200) is False    # not protected to begin with
    assert pn.assess_bypass(403, 403) is False    # still blocked
    assert pn.assess_bypass(403, None) is False


# -- probe via fake clients -------------------------------------------------
class _R:
    def __init__(self, status, body=b""):
        self.status = status
        self.body = body


class _Client:
    """403 for the plain path; 200 only for URLs containing *open_marker*."""

    def __init__(self, open_marker):
        self._m = open_marker

    async def fetch(self, url, **kwargs):
        if self._m and self._m in url:
            return _R(200, b"secret admin panel")
        return _R(403, b"forbidden")


@pytest.mark.asyncio
async def test_probe_flags_a_bypassing_twin():
    res = await pn.probe_path_bypass(_Client("..;/"), "https://x.test/admin")
    assert res["protected"] is True
    assert any(f["twin_status"] == 200 and "..;" in f["url"] for f in res["findings"])


@pytest.mark.asyncio
async def test_probe_skips_when_not_protected():
    # baseline 200 → nothing to bypass, no twins fired
    class _Open:
        async def fetch(self, url, **kwargs):
            return _R(200, b"ok")

    res = await pn.probe_path_bypass(_Open(), "https://x.test/public")
    assert res["protected"] is False and res["findings"] == []


@pytest.mark.asyncio
async def test_probe_no_bypass_all_blocked():
    res = await pn.probe_path_bypass(_Client("NEVER_MATCHES"), "https://x.test/admin")
    assert res["protected"] is True and res["findings"] == []


# -- registration -----------------------------------------------------------
@pytest.mark.asyncio
async def test_path_bypass_tool_registered():
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "path_bypass_probe" in tools
