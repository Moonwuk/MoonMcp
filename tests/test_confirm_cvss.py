"""Finding confirmation (differential + OAST + signatures) and CVSS scoring."""

import pytest

from moonmcp import confirm, cvss
from moonmcp import server as srv


# -- CVSS 3.1 base score ----------------------------------------------------
def test_cvss_known_vectors():
    assert cvss.base_score(vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")["score"] == 9.8
    r = cvss.base_score(vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")
    assert r["score"] == 5.3
    assert r["severity"] == "medium"


def test_cvss_severity_bands_and_defaults():
    # No impact metrics -> 0.0 / none.
    z = cvss.base_score()
    assert z["score"] == 0.0 and z["severity"] == "none"
    assert cvss.severity_band(9.5) == "critical"
    assert cvss.severity_band(7.0) == "high"
    assert cvss.base_score(vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")["vector"].startswith("CVSS:3.1/")


def test_cvss_invalid_metric_raises():
    with pytest.raises(ValueError):
        cvss.base_score({"AV": "Z"})


@pytest.mark.asyncio
async def test_cvss_score_tool(fresh_context):
    res = await srv.cvss_score(vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert res["score"] == 9.8 and res["severity"] == "critical"
    res2 = await srv.cvss_score(av="N", ac="L", pr="N", ui="N", s="U", c="L", i="N", a="N")
    assert res2["score"] == 5.3


# -- confirmation logic (pure) ---------------------------------------------
def test_evaluate_verdicts():
    assert confirm.evaluate(oast_count=1)["verdict"] == "confirmed"
    assert confirm.evaluate(injection_hits=["sqli/MySQL"], reflected=True)["verdict"] == "confirmed"
    assert confirm.evaluate(injection_hits=["sqli/MySQL"])["verdict"] == "likely"
    assert confirm.evaluate(reflected=True)["verdict"] == "inconclusive"
    assert confirm.evaluate()["verdict"] == "unconfirmed"


# -- confirm_finding tool ---------------------------------------------------
@pytest.mark.asyncio
async def test_confirm_reflected_only_is_inconclusive(local_server, fresh_context):
    base, _ = local_server
    res = await srv.confirm_finding(target=f"{base}/reflect", param="name", payload="ZQREFLECT99")
    assert res["reflected"] is True
    assert res["verdict"] in ("inconclusive", "likely")
    assert "recorded_finding_id" not in res


@pytest.mark.asyncio
async def test_confirm_injection_confirmed_and_recorded(local_server, fresh_context):
    base, _ = local_server
    # The reflected payload is itself a MySQL error string → signature fires →
    # reflected + signature = confirmed.
    res = await srv.confirm_finding(
        target=f"{base}/reflect", param="name",
        payload="You have an error in your SQL syntax", injection_class="sqli",
        record=True, severity="high", title="SQLi on name",
    )
    assert res["verdict"] == "confirmed"
    assert any(h["class"] == "sqli" for h in res["injection_matches"])
    assert "recorded_finding_id" in res
    listing = await srv.list_findings()
    assert any(f["title"] == "SQLi on name" for f in listing["findings"])


@pytest.mark.asyncio
async def test_confirm_out_of_scope(fresh_context):
    res = await srv.confirm_finding(target="https://not-in-scope.example/x", param="q", payload="'")
    assert res["error"] == "out_of_scope"
