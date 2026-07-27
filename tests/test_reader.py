"""Web page reader (web_read) — pure HTML extraction + the OSINT tool."""

import pytest

from moonmcp import server as srv
from moonmcp.intel import reader as readermod

_HTML = """<!doctype html><html><head>
<title>  Example &amp; Co </title>
<meta name="description" content="A page about widgets">
<style>.a{color:red}</style>
<script>var secret='do-not-leak';</script>
</head><body>
<nav><a href="/home">Home</a></nav>
<h1>Widgets</h1>
<p>The first paragraph of real content.</p>
<p>Contact <a href="https://vendor.example/contact">the vendor</a> today.</p>
<script>console.log('nope');</script>
</body></html>"""


def test_extract_readable_pulls_title_desc_text_links():
    out = readermod.extract_readable(_HTML, "https://site.example/page")
    assert out["title"] == "Example & Co"            # entity-decoded, trimmed
    assert out["description"] == "A page about widgets"
    # script/style content is stripped from the readable text
    assert "do-not-leak" not in out["text"]
    assert "console.log" not in out["text"]
    assert "first paragraph of real content" in out["text"]
    # links are absolutised and kept; javascript:/# are dropped
    urls = {link["url"] for link in out["links"]}
    assert "https://site.example/home" in urls
    assert "https://vendor.example/contact" in urls
    assert out["word_count"] > 0


def test_extract_readable_survives_garbage():
    # A malformed page must never raise.
    out = readermod.extract_readable("<html><body><p>unclosed <a href=", "https://x.example")
    assert isinstance(out["text"], str)


def test_looks_html_heuristics():
    assert readermod._looks_html("text/html", "<html>")
    assert readermod._looks_html("", "<!doctype html><title>x")
    assert not readermod._looks_html("application/json", '{"a":1}')
    assert not readermod._looks_html("text/plain", "just text")


def test_text_is_capped_at_max_chars():
    big = "<html><body>" + ("word " * 10000) + "</body></html>"
    out = readermod.extract_readable(big, "https://x.example", max_chars=100)
    assert len(out["text"]) <= 100 and out["truncated"] is True


@pytest.mark.asyncio
async def test_web_read_rejects_bad_scheme(fresh_context):
    res = await srv.web_read(url="file:///etc/passwd")
    assert "error" in res and "scheme" in res["error"]


@pytest.mark.asyncio
async def test_web_read_handles_blocked_network(fresh_context):
    # Nothing listening / outbound blocked → graceful error, never a raise.
    res = await srv.web_read(url="http://127.0.0.1:1/nope")
    assert res["url"].startswith("http://127.0.0.1:1")
    assert "error" in res


@pytest.mark.asyncio
async def test_web_read_reads_live_page(fresh_context, local_server):
    base, _ = local_server
    res = await srv.web_read(url=f"{base}/article")
    assert res["status"] == 200
    assert res["title"] == "CVE-2021-44228 Analysis"
    assert res["description"] == "Log4Shell deep dive"
    assert "remote code execution" in res["text"]
    assert "should-not-appear" not in res["text"]   # script stripped
    assert any("nvd.nist.gov" in link["url"] for link in res["links"])
