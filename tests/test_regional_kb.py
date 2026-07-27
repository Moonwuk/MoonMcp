"""Regional KB packs (Theme G): domestic KR DBMS + CQL error signatures, APAC WAFs."""

from moonmcp.knowledge import injections as inj
from moonmcp.web import waf


# -- domestic DBMS + CQL error-signature attribution -------------------------
def test_domestic_dbms_and_cql_signatures():
    cases = {
        "TBR-2114: syntax error near": "Tibero",
        "com.tmax.tibero.jdbc.TbDriver": "Tibero",
        "cubrid.jdbc.driver.CUBRIDException: -493": "CUBRID",
        "Altibase.jdbc.driver.AltibaseConnection error": "Altibase",
        "com.datastax.driver.core.exceptions.SyntaxError": "Cassandra/ScyllaDB (CQL)",
        "InvalidRequestException: no viable alternative at input '\\''": "Cassandra/ScyllaDB (CQL)",
    }
    for sample, tech in cases.items():
        hits = inj.match_signatures(sample, class_id="sqli")
        assert tech in {h["technology"] for h in hits}, (sample, hits)


def test_domestic_dbms_no_false_positive():
    # an ordinary MySQL error still attributes MySQL, not a domestic DBMS
    hits = inj.match_signatures("You have an error in your SQL syntax near", class_id="sqli")
    techs = {h["technology"] for h in hits}
    assert any("MySQL" in t for t in techs)
    assert not (techs & {"Tibero", "CUBRID", "Altibase"})
    # a benign page matches nothing
    assert inj.match_signatures("<html>welcome to our shop</html>", class_id="sqli") == []


# -- APAC WAF fingerprints ---------------------------------------------------
def _hit(name, *, headers=None, cookies="", server="", body=""):
    return waf._match(name, waf._SIGNATURES[name], headers or {}, cookies, server, body)


def test_apac_waf_fingerprints():
    assert _hit("Penta Security WAPPLES", body="<html>protected by WAPPLES</html>")
    assert _hit("MonitorApp AIWAF", cookies="aiwaf_session=abc")
    assert _hit("Cloudbric", body="blocked by Cloudbric")
    assert _hit("Scutum (ML-based)", cookies="scutum=1")
    assert _hit("Shadan-kun (攻撃遮断くん)", body="攻撃遮断くん によりブロック")


def test_apac_waf_no_false_positive():
    for name in ("Penta Security WAPPLES", "MonitorApp AIWAF", "Cloudbric"):
        assert _hit(name, body="<html>ordinary page</html>", server="nginx") is None
