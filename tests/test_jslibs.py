"""js_library_scan (Retire.js-lite) — known-vulnerable JS library detector."""

import pytest

from moonmcp import server as srv
from moonmcp.recon import jslibs


# -- pure -----------------------------------------------------------------------
def test_version_tuple_parsing():
    assert jslibs._v("1.9.1") == (1, 9, 1)
    assert jslibs._v("1.9.1-beta") == (1, 9, 1)
    assert jslibs._v("2") == (2,)
    assert jslibs._v("not-a-version") == (0,)


@pytest.mark.parametrize("filename,expected_version", [
    ("https://cdn.example.com/js/jquery-1.9.1.min.js", "1.9.1"),
    ("jquery-2.1.0.js", "2.1.0"),
    ("jquery.js?ver=1.11.3", "1.11.3"),
])
def test_jquery_vulnerable_versions_detected(filename, expected_version):
    hits = jslibs.scan(filename)
    assert len(hits) == 1
    assert hits[0]["library"] == "jQuery"
    assert hits[0]["version"] == expected_version
    assert hits[0]["fixed_version"] == "3.5.0"
    assert "CVE-2020-11022" in hits[0]["cves"]


def test_jquery_patched_version_not_flagged():
    assert jslibs.scan("https://cdn.example.com/js/jquery-3.6.0.min.js") == []
    assert jslibs.scan("jquery-3.5.0.min.js") == []  # the fixed version itself is clean


def test_angularjs_vulnerable_version():
    hits = jslibs.scan("angular-1.6.9.min.js")
    assert any(h["library"] == "AngularJS" for h in hits)


def test_lodash_prototype_pollution_version():
    hits = jslibs.scan("lodash-4.17.15.min.js")
    assert hits and hits[0]["library"] == "Lodash"
    assert "CVE-2020-8203" in hits[0]["cves"]


def test_lodash_patched_version_not_flagged():
    assert jslibs.scan("lodash-4.17.21.min.js") == []


def test_moment_handlebars_bootstrap_vulnerable_versions():
    assert jslibs.scan("moment-2.24.0.min.js")[0]["library"] == "Moment.js"
    assert jslibs.scan("handlebars-4.1.0.min.js")[0]["library"] == "Handlebars"
    assert jslibs.scan("bootstrap-4.0.0.min.js")[0]["library"] == "Bootstrap"


def test_version_banner_in_js_snippet():
    snippet = "/*! jQuery v1.12.4 | (c) jQuery Foundation */"
    hits = jslibs.scan(snippet)
    assert hits and hits[0]["library"] == "jQuery" and hits[0]["version"] == "1.12.4"


def test_no_version_no_false_positive():
    assert jslibs.scan("https://cdn.example.com/js/jquery.min.js") == []
    assert jslibs.scan("some random script content with no library name") == []


def test_scan_all_dedupes_across_sources():
    sources = ["jquery-1.9.1.min.js", "jquery-1.9.1.js?whatever", "lodash-4.17.15.min.js"]
    hits = jslibs.scan_all(sources)
    libs = {(h["library"], h["version"]) for h in hits}
    assert ("jQuery", "1.9.1") in libs
    assert ("Lodash", "4.17.15") in libs
    # jQuery 1.9.1 appears twice across sources but should only be reported once
    assert sum(1 for h in hits if h["library"] == "jQuery") == 1


# -- tool -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_js_library_scan_registered(fresh_context):
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "js_library_scan" in tools


@pytest.mark.asyncio
async def test_js_library_scan_tool(fresh_context):
    res = await srv.js_library_scan(sources=["jquery-1.9.1.min.js", "app.js"])
    assert res["scanned"] == 2
    assert res["count"] == 1
    assert res["findings"][0]["library"] == "jQuery"
