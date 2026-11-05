"""Calibration-driven KB rows: Juice Shop 2026-10-29 live signatures must match."""

from moonmcp.knowledge.injections import match_signatures

LIVE = ("Error: SQLITE_ERROR: SELECTs to the left and right of UNION do not "
        "have the same number of result columns")


def test_sqlite_error_title_form_matches():
    r = match_signatures(LIVE)
    techs = " ".join(m["technology"] for m in r).lower()
    assert "sqlite" in techs
    assert any("SQLITE_ERROR:" in m["matched"] for m in r)


def test_union_mismatch_message_matches():
    r = match_signatures(LIVE)
    assert any("UNION" in m["matched"] for m in r)


def test_extended_result_code_prefixes_match():
    for sample in ("SQLITE_BUSY: database is locked",
                   "SQLITE_CONSTRAINT_UNIQUE: constraint failed",
                   "SQLITE_AUTH: not authorized"):
        assert match_signatures(sample), sample
