"""Email-security posture: SPF bare-`all` and DMARC sp=/pct= verdicts."""

import asyncio

from moonmcp.intel import email as em


def test_spf_policy_treats_bare_all_as_pass_any():
    # bare `all` == `+all` (SPF default qualifier) — a wide-open record.
    assert em._spf_policy("v=spf1 mx all") == "pass (any sender!)"
    assert em._spf_policy("v=spf1 +all") == "pass (any sender!)"
    assert em._spf_policy("v=spf1 -all") == "hard fail"
    assert em._spf_policy("v=spf1 ~all") == "soft fail"
    assert em._spf_policy("v=spf1 ?all") == "neutral"
    assert em._spf_policy("v=spf1 include:_spf.example.com -all") == "hard fail"


class _Rec:
    def __init__(self, records):
        self.records = records


def _fake_resolve(mapping):
    async def _resolve(name, rdtypes=(), http_client=None):
        return _Rec(mapping.get(name, {}))
    return _resolve


def test_bare_all_and_weak_dmarc_are_graded_down(monkeypatch):
    mapping = {
        "acme.test": {"TXT": ['"v=spf1 mx all"']},           # bare all (+all) + no CAA
        "_dmarc.acme.test": {"TXT": ['"v=DMARC1; p=reject; sp=none; pct=10"']},
    }
    monkeypatch.setattr(em, "resolve", _fake_resolve(mapping))
    res = asyncio.run(em.analyze_email_security(client=None, domain="acme.test"))

    issues = " || ".join(res.issues)
    assert "allows any sender" in issues                     # bare-all flagged
    assert res.spf_policy == "pass (any sender!)"
    assert res.dmarc_subdomain_policy == "none" and "sp=none" in issues
    assert res.dmarc_pct == 10 and "pct=10" in issues
    # wide-open SPF + carved-out/partial DMARC must not earn an A.
    assert res.grade != "A"


def test_full_enforcement_still_grades_well(monkeypatch):
    mapping = {
        "acme.test": {"TXT": ['"v=spf1 -all"'], "CAA": ['0 issue "letsencrypt.org"']},
        "_dmarc.acme.test": {"TXT": ['"v=DMARC1; p=reject"']},   # pct defaults to 100, sp inherits p
    }
    monkeypatch.setattr(em, "resolve", _fake_resolve(mapping))
    res = asyncio.run(em.analyze_email_security(client=None, domain="acme.test"))
    assert res.spf_policy == "hard fail"
    assert res.grade in ("A", "B")                           # strong posture keeps full credit
