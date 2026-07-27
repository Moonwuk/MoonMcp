"""Burp-style primitives: repeater, intruder, passive scan, history."""

from dataclasses import replace

import pytest

from moonmcp import intercept as ic
from moonmcp import server as srv
from moonmcp.net.http import HttpResult


# -- parse_raw_request ------------------------------------------------------
def test_parse_raw_origin_form():
    method, url, headers, body = ic.parse_raw_request(
        "GET /a?b=1 HTTP/1.1\nHost: ex.com\nX-T: 1\n\n"
    )
    assert method == "GET"
    assert url == "https://ex.com/a?b=1"
    assert headers == {"X-T": "1"}  # Host is dropped (urllib derives it)
    assert body == b""


def test_parse_raw_absolute_form_with_body():
    method, url, headers, body = ic.parse_raw_request(
        "POST http://ex.com/x HTTP/1.1\nContent-Type: text/plain\n\nhello"
    )
    assert (method, url) == ("POST", "http://ex.com/x")
    assert headers["Content-Type"] == "text/plain"
    assert body == b"hello"


def test_parse_raw_errors():
    with pytest.raises(ValueError):
        ic.parse_raw_request("GET /a HTTP/1.1\n\n")  # origin-form, no Host
    with pytest.raises(ValueError):
        ic.parse_raw_request("garbage")


# -- passive_findings -------------------------------------------------------
def test_passive_findings_over_result():
    result = HttpResult(
        url="https://h/", final_url="https://h/", status=200, reason="OK",
        headers=[("Server", "nginx/1.25.1"), ("X-Powered-By", "Express"),
                 ("Content-Type", "text/html")],
        body=b"<html><title>Hi</title>aws_secret_access_key='AKIAIOSFODNN7EXAMPLE'</html>",
        elapsed_ms=1.0,
    )
    pf = ic.passive_findings(result)
    assert pf["header_grade"] in {"A", "B", "C", "D", "E", "F"}
    names = {t["name"] for t in pf["technologies"]}
    assert "nginx" in names
    assert isinstance(pf["secret_count"], int)


# -- history store ----------------------------------------------------------
def test_history_store_add_list_get_clear():
    h = ic.HistoryStore(cap=3)
    for i in range(4):
        h.add(source="repeater", method="GET", url=f"https://h/{i}", host="h",
              status=200, req_headers={}, req_body=b"", resp_headers={},
              resp_body=b"x", resp_len=1, elapsed_ms=1.0)
    assert h.count == 3  # capped
    latest = h.list(limit=1)
    assert latest[0].url.endswith("/3")
    got = h.get(latest[0].id)
    assert got is not None and got.id == latest[0].id
    assert h.clear() == 3 and h.count == 0


# -- tools against the local server ----------------------------------------
@pytest.mark.asyncio
async def test_repeater_structured_and_history(local_server, fresh_context):
    base, _ = local_server
    res = await srv.http_repeater(url=f"{base}/echo", headers={"X-Probe": "1"})
    assert res["status"] == 200
    assert "exchange_id" in res
    assert "passive" in res
    hist = await srv.http_history()
    assert hist["count"] >= 1
    full = await srv.http_history(exchange_id=res["exchange_id"])
    assert full["url"].endswith("/echo")


@pytest.mark.asyncio
async def test_repeater_raw_absolute_form(local_server, fresh_context):
    base, port = local_server
    raw = f"GET {base}/echo HTTP/1.1\nX-Raw: yes\n\n"
    res = await srv.http_repeater(raw=raw)
    assert res["status"] == 200
    assert res["request"]["url"] == f"{base}/echo"


@pytest.mark.asyncio
async def test_repeater_out_of_scope(fresh_context):
    res = await srv.http_repeater(url="https://not-in-scope.example/")
    assert res["error"] == "out_of_scope"


@pytest.mark.asyncio
async def test_passive_scan_local(local_server, fresh_context):
    base, _ = local_server
    res = await srv.passive_scan(target=base)
    assert res["status"] == 200
    assert res["header_grade"] == "F"  # local server sets no security headers
    assert "nginx" in {t["name"] for t in res["technologies"]}


@pytest.mark.asyncio
async def test_intruder_flags(local_server, fresh_context):
    base, _ = local_server
    # /<payload>: '' -> 200 (baseline), 'missing' -> 404, 'admin' -> 403.
    res = await srv.intruder(template=f"{base}/§", payloads=["missing", "admin"])
    assert res["baseline"]["status"] == 200
    by_payload = {r["payload"]: r for r in res["results"]}
    assert "status-change" in by_payload["missing"]["flags"]
    assert by_payload["missing"]["status"] == 404


@pytest.mark.asyncio
async def test_intruder_reflection(local_server, fresh_context):
    base, _ = local_server
    res = await srv.intruder(template=f"{base}/reflect?name=§", payloads=["CANARY123"])
    r = res["results"][0]
    assert r["reflected"] is True
    assert "reflected" in r["flags"]


@pytest.mark.asyncio
async def test_intruder_is_intrusive_gated(fresh_context):
    fresh_context.settings = replace(fresh_context.settings, allow_intrusive=False)
    res = await srv.intruder(template="https://127.0.0.1/§", payloads=["x"])
    assert res["error"] == "disabled"


@pytest.mark.asyncio
async def test_intruder_marker_missing(fresh_context):
    res = await srv.intruder(template="https://127.0.0.1/no-marker", payloads=["x"])
    assert res["error"] == "invalid_input"
