"""open_redirect _with_param must OVERWRITE the existing redirect param."""

from urllib.parse import parse_qs, urlsplit

from moonmcp.web import redirect as rd


def test_with_param_overwrites_existing_value():
    out = rd._with_param("https://x.test/login?next=/dashboard&lang=en", "next", "https://evil.test/")
    q = parse_qs(urlsplit(out).query)
    assert q["next"] == ["https://evil.test/"]   # single, overwritten (was appended before → 2 values)
    assert q["lang"] == ["en"]                   # unrelated params preserved


def test_with_param_appends_when_absent():
    out = rd._with_param("https://x.test/go", "url", "https://evil.test/")
    assert parse_qs(urlsplit(out).query)["url"] == ["https://evil.test/"]


def test_payloads_include_backslash_confusion():
    assert any("\\" in p for p in rd._PAYLOADS)
