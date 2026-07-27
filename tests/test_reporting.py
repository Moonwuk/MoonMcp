from moonmcp.reporting import format_markdown


def test_format_markdown_orders_and_renders():
    report = {
        "target": "example.com",
        "surface": {"subdomains": 12, "ips": ["1.2.3.4"], "technologies": ["nginx", "PHP"],
                    "open_ports": [80, 443]},
        "grades": {"Security headers": "C", "Email (SPF/DMARC)": "B"},
        "findings": [
            {"severity": "low", "title": "Low thing", "detail": "d1"},
            {"severity": "high", "title": "High thing", "detail": "d2", "evidence": "ev"},
            {"severity": "medium", "title": "Mid thing", "detail": "d3"},
        ],
    }
    md = format_markdown(report, generated_at="2026-07-08 00:00 UTC")
    assert "# MoonMCP recon report — `example.com`" in md
    assert "3 finding(s):" in md
    # high must be rendered before low
    assert md.index("High thing") < md.index("Low thing")
    assert "| Security headers | C |" in md
    assert "**Subdomains:** 12" in md
    assert "> ev" in md


def test_format_markdown_empty():
    md = format_markdown({"target": "x.com"})
    assert "No data collected" in md
    assert "authorised testing only" in md
