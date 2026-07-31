"""curl_cffi (browser-impersonation) transport — CA-bundle trust + bomb-bound.

These test _curl_cffi_fetch directly with a fake `_cf_requests`, so they run even
without curl_cffi installed.
"""

from moonmcp.net import http as h


class _FakeResp:
    def __init__(self, *, content=b"ok", with_iter=True, headers=None):
        self._content = content
        self.status_code = 200
        self.reason = "OK"
        self.url = "https://x.test/"
        self.headers = headers or {}
        if with_iter:
            self.iter_content = lambda chunk_size=65536: iter([content])

    def close(self):
        pass


class _FakeCf:
    def __init__(self, resp, sink=None):
        self._resp = resp
        self._sink = sink

    def request(self, **kw):
        if self._sink is not None:
            self._sink.update(kw)
        return self._resp


def test_curl_cffi_fetch_fails_closed_without_iter_content(monkeypatch):
    # Without a streaming API, reading r.content would buffer the whole decompressed
    # body (gzip/br bomb). The transport must error instead of materialising it.
    resp = _FakeResp(content=b"x" * 100_000, with_iter=False)
    monkeypatch.setattr(h, "_cf_requests", _FakeCf(resp), raising=False)
    res = h._curl_cffi_fetch("https://x.test/", "GET", {}, None, 5.0, True, 1024, "chrome")
    assert res.status is None
    assert "iter_content" in (res.error or "")


def test_curl_cffi_fetch_honors_ca_bundle(monkeypatch, tmp_path):
    # A custom MOONMCP_CA_BUNDLE must reach curl_cffi's `verify`, like the urllib path,
    # or a private-CA target fails only on the impersonation transport.
    bundle = tmp_path / "ca.pem"
    bundle.write_text("-----BEGIN CERTIFICATE-----\n")
    sink: dict = {}
    monkeypatch.setattr(h, "_cf_requests", _FakeCf(_FakeResp(), sink), raising=False)

    monkeypatch.setenv("MOONMCP_CA_BUNDLE", str(bundle))
    h._curl_cffi_fetch("https://x.test/", "GET", {}, None, 5.0, True, 4096, "chrome")
    assert sink["verify"] == str(bundle)

    # unset → verify is the plain bool
    monkeypatch.delenv("MOONMCP_CA_BUNDLE", raising=False)
    sink.clear()
    h._curl_cffi_fetch("https://x.test/", "GET", {}, None, 5.0, True, 4096, "chrome")
    assert sink["verify"] is True

    # verify_tls=False is never overridden by a bundle
    monkeypatch.setenv("MOONMCP_CA_BUNDLE", str(bundle))
    sink.clear()
    h._curl_cffi_fetch("https://x.test/", "GET", {}, None, 5.0, False, 4096, "chrome")
    assert sink["verify"] is False
