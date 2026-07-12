"""saml_xsw_probe — SAML XML Signature Wrapping, pure + e2e."""

import pytest

from moonmcp import server as srv
from moonmcp.web import saml as samlmod

_SAMPLE_XML = (
    '<?xml version="1.0"?>'
    '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
    'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp1">'
    '<saml:Issuer>https://idp.example.com</saml:Issuer>'
    '<saml:Assertion xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="_assert1">'
    '<saml:Issuer>https://idp.example.com</saml:Issuer>'
    '<ds:Signature>'
    '<ds:SignedInfo><ds:Reference URI="#_assert1"/></ds:SignedInfo>'
    '<ds:SignatureValue>ZmFrZXNpZ25hdHVyZXZhbHVlPT0=</ds:SignatureValue>'
    '</ds:Signature>'
    '<saml:Subject><saml:NameID>alice@example.com</saml:NameID></saml:Subject>'
    '</saml:Assertion>'
    '</samlp:Response>'
)

_UNSIGNED_XML = (
    '<?xml version="1.0"?>'
    '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
    'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp2">'
    '<saml:Assertion ID="_assert2">'
    '<saml:Subject><saml:NameID>bob@example.com</saml:NameID></saml:Subject>'
    '</saml:Assertion>'
    '</samlp:Response>'
)

_DANGLING_REF_XML = (
    '<?xml version="1.0"?>'
    '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
    'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp3">'
    '<saml:Assertion xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="_assert3">'
    '<ds:Signature>'
    '<ds:SignedInfo><ds:Reference URI="#_nonexistent"/></ds:SignedInfo>'
    '<ds:SignatureValue>ZmFrZXNpZ25hdHVyZXZhbHVlPT0=</ds:SignatureValue>'
    '</ds:Signature>'
    '<saml:Subject><saml:NameID>carol@example.com</saml:NameID></saml:Subject>'
    '</saml:Assertion>'
    '</samlp:Response>'
)


# -- pure -------------------------------------------------------------------
def test_decode_response_passthrough_xml():
    assert samlmod.decode_response(_SAMPLE_XML) == _SAMPLE_XML


def test_decode_response_base64():
    import base64
    b64 = base64.b64encode(_SAMPLE_XML.encode()).decode()
    assert samlmod.decode_response(b64) == _SAMPLE_XML


def test_decode_response_unparseable_base64_falls_back_to_raw():
    assert samlmod.decode_response("not valid base64!!") == "not valid base64!!"


def test_parse_structure_basic():
    s = samlmod.parse_structure(_SAMPLE_XML)
    assert s["root_tag"] == "Response"
    assert s["assertion_count"] == 1
    assert s["assertions"][0]["id"] == "_assert1"
    assert s["assertions"][0]["nameid"] == "alice@example.com"
    assert s["signature_count"] == 1
    assert s["signatures"][0]["reference_uri"] == "#_assert1"


def test_parse_structure_unparseable():
    s = samlmod.parse_structure("<not><xml")
    assert s["error"] == "unparseable"
    assert "detail" in s


def test_assess_wrappable_signed_single_is_clean():
    s = samlmod.parse_structure(_SAMPLE_XML)
    a = samlmod.assess_wrappable(s)
    assert a == {
        "assessable": True, "unsigned": False, "multiple_assertions": False,
        "dangling_signature_references": [], "notes": [],
    }


def test_assess_wrappable_unsigned_flags_it():
    s = samlmod.parse_structure(_UNSIGNED_XML)
    a = samlmod.assess_wrappable(s)
    assert a["unsigned"] is True
    assert any("no <ds:Signature>" in n for n in a["notes"])


def test_assess_wrappable_dangling_reference_flags_it():
    s = samlmod.parse_structure(_DANGLING_REF_XML)
    a = samlmod.assess_wrappable(s)
    assert a["dangling_signature_references"] == ["#_nonexistent"]
    assert any("doesn't match any Assertion ID" in n for n in a["notes"])


def test_assess_wrappable_on_error_structure():
    a = samlmod.assess_wrappable({"error": "unparseable", "detail": "x"})
    assert a == {"assessable": False, "reason": "unparseable"}


def test_corrupt_signature_changes_only_the_signature_value():
    corrupted = samlmod.corrupt_signature(_SAMPLE_XML)
    assert corrupted is not None
    assert corrupted != _SAMPLE_XML
    s = samlmod.parse_structure(corrupted)
    assert s["assertion_count"] == 1
    assert s["assertions"][0]["nameid"] == "alice@example.com"  # untouched


def test_corrupt_signature_none_when_no_signature_value():
    assert samlmod.corrupt_signature(_UNSIGNED_XML) is None


def test_build_variant_unknown_raises():
    with pytest.raises(ValueError):
        samlmod.build_variant(_SAMPLE_XML, "bogus")


def test_build_variant_non_response_root_returns_none():
    bare_assertion = '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="a"/>'
    assert samlmod.build_variant(bare_assertion, "sibling_before") is None


def test_build_variant_no_assertion_returns_none():
    empty_response = ('<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
                      'ID="_r"/>')
    assert samlmod.build_variant(empty_response, "sibling_before") is None


def test_build_variant_sibling_before_forged_comes_first():
    out = samlmod.build_variant(_SAMPLE_XML, "sibling_before", forged_nameid="evil@x")
    s = samlmod.parse_structure(out)
    assert s["assertion_count"] == 2
    nameids = [a["nameid"] for a in s["assertions"]]
    assert nameids == ["evil@x", "alice@example.com"]
    ids = [a["id"] for a in s["assertions"]]
    assert ids[1] == "_assert1"  # original ID untouched
    assert ids[0] == "_assert1-forged"


def test_build_variant_sibling_after_forged_comes_last():
    out = samlmod.build_variant(_SAMPLE_XML, "sibling_after", forged_nameid="evil@x")
    s = samlmod.parse_structure(out)
    nameids = [a["nameid"] for a in s["assertions"]]
    assert nameids == ["alice@example.com", "evil@x"]


def test_build_variant_wrap_extension_forged_is_direct_child():
    out = samlmod.build_variant(_SAMPLE_XML, "wrap_extension", forged_nameid="evil@x")
    s = samlmod.parse_structure(out)
    assert s["assertion_count"] == 2
    nameids = [a["nameid"] for a in s["assertions"]]
    assert nameids == ["evil@x", "alice@example.com"]
    # The forged copy carries no signature; the original's is untouched wherever it now sits.
    assert s["signature_count"] == 1


def test_build_variant_forged_copy_has_no_signature():
    out = samlmod.build_variant(_SAMPLE_XML, "sibling_before", forged_nameid="evil@x")
    s = samlmod.parse_structure(out)
    assert s["signature_count"] == 1  # only the original's


def test_build_variant_falls_back_to_attribute_value_without_nameid():
    xml = (
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r">'
        '<saml:Assertion ID="_a">'
        '<saml:AttributeStatement><saml:Attribute><saml:AttributeValue>user'
        '</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>'
        '</saml:Assertion></samlp:Response>'
    )
    out = samlmod.build_variant(xml, "sibling_before", forged_nameid="evil@x")
    assert out is not None
    assert "evil@x" in out


# -- assess_variant -----------------------------------------------------------
def test_assess_variant_reflected_when_marker_only_in_variant_body():
    accepted = samlmod.Resp(status=200, length=100)
    corrupted = samlmod.Resp(status=403, length=50)
    variant = samlmod.Resp(status=200, length=110)
    res = samlmod.assess_variant(
        accepted=accepted, corrupted=corrupted, variant=variant,
        variant_body="Welcome, evil@x", accepted_body="Welcome, alice",
        corrupted_body="signature invalid", forged_marker="evil@x")
    assert res["reflected_forged_identity"] is True
    assert res["matches_accepted_baseline"] is True
    assert res["length_delta_vs_corrupted"] == 60


def test_assess_variant_not_reflected_when_marker_also_in_baseline():
    accepted = samlmod.Resp(status=200, length=100)
    corrupted = samlmod.Resp(status=200, length=100)
    variant = samlmod.Resp(status=200, length=100)
    res = samlmod.assess_variant(
        accepted=accepted, corrupted=corrupted, variant=variant,
        variant_body="evil@x appears here", accepted_body="evil@x boilerplate",
        corrupted_body="", forged_marker="evil@x")
    assert res["reflected_forged_identity"] is False  # appears in accepted baseline too


def test_assess_variant_not_matching_accepted_when_status_equals_corrupted():
    accepted = samlmod.Resp(status=200, length=100)
    corrupted = samlmod.Resp(status=200, length=100)
    variant = samlmod.Resp(status=200, length=100)
    res = samlmod.assess_variant(
        accepted=accepted, corrupted=corrupted, variant=variant,
        variant_body="", accepted_body="", corrupted_body="", forged_marker="")
    assert res["matches_accepted_baseline"] is False


# -- end-to-end ---------------------------------------------------------------
@pytest.mark.asyncio
async def test_saml_xsw_probe_registered(fresh_context):
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "saml_xsw_probe" in tools


@pytest.mark.asyncio
async def test_saml_xsw_probe_unparseable_response_returns_error(fresh_context):
    # No live server needed here -- an unparseable document short-circuits
    # before any HTTP request is made, so only the scope check needs to pass.
    res = await srv.saml_xsw_probe(acs_url="https://127.0.0.1/acs",
                                   saml_response="<not><xml")
    assert res["error"] == "unparseable"


@pytest.mark.asyncio
async def test_saml_xsw_probe_detects_first_wins_bypass(local_server, fresh_context):
    base, _ = local_server
    res = await srv.saml_xsw_probe(acs_url=f"{base}/saml-acs-vuln",
                                   saml_response=_SAMPLE_XML,
                                   forged_marker="moon-xsw-forged@internal")
    assert res["static_assessment"]["unsigned"] is False
    variants = res["variants"]
    # "grabs the first assertion" and "only looks at direct children" both get fooled...
    assert variants["sibling_before"]["reflected_forged_identity"] is True
    assert variants["wrap_extension"]["reflected_forged_identity"] is True
    # ...but "grabs the last assertion" isn't fooled by THIS harness's first-wins logic.
    assert variants["sibling_after"]["reflected_forged_identity"] is False
    assert "sibling_before" in res["vulnerable_variants"]
    assert "wrap_extension" in res["vulnerable_variants"]
    assert res["verdict"] == "confirmed"


@pytest.mark.asyncio
async def test_saml_xsw_probe_safe_endpoint_not_fooled(local_server, fresh_context):
    base, _ = local_server
    res = await srv.saml_xsw_probe(acs_url=f"{base}/saml-acs-safe",
                                   saml_response=_SAMPLE_XML,
                                   forged_marker="moon-xsw-forged@internal")
    for variant in res["variants"].values():
        assert variant["reflected_forged_identity"] is False
    assert res["vulnerable_variants"] == []
    assert res["verdict"] != "confirmed"


@pytest.mark.asyncio
async def test_saml_xsw_probe_baselines_reflect_signature_check(local_server, fresh_context):
    base, _ = local_server
    res = await srv.saml_xsw_probe(acs_url=f"{base}/saml-acs-vuln",
                                   saml_response=_SAMPLE_XML)
    assert res["baseline_accepted"]["status"] == 200
    assert res["baseline_corrupted"]["status"] == 403
