"""Unicode-normalization WAF-bypass probe — reflection differential (NFKC / case-fold)."""

import unicodedata
from urllib.parse import parse_qs, urlsplit

import pytest

from moonmcp import server as srv
from moonmcp.web import unicode_bypass as ub

C = ub.CANARY


def _vec(name):
    return next(v for v in ub.VECTORS if v.name == name)


# -- pure data / analysers --------------------------------------------------
def test_vectors_all_valid():
    for v in ub.VECTORS:
        got = (unicodedata.normalize("NFKC", v.raw) if v.kind == "nfkc" else v.raw.casefold())
        assert got == v.norm, v.name
        assert v.raw != v.norm
        assert v.kind in ("nfkc", "casefold")
    # the canary must survive both transforms unchanged, or it couldn't frame the injected char
    assert unicodedata.normalize("NFKC", C) == C == C.casefold()


def test_norm_forms_include_entities_for_dangerous():
    forms = ub.norm_forms(_vec("fullwidth_lt"))
    assert "<" in forms and "&lt;" in forms and "&#60;" in forms and "&#x3c;" in forms


def test_norm_forms_cover_apostrophe_encoder_quirks():
    # html.escape emits &#x27; for ' — real encoders also use &apos; (PHP ENT_HTML5) and the
    # zero-padded decimal &#039; (PHP default); both must be covered or those apps are missed
    forms = ub.norm_forms(_vec("fullwidth_squote"))
    assert "'" in forms and "&apos;" in forms and "&#039;" in forms and "&#39;" in forms


def test_norm_forms_letter_is_plain_only():
    assert ub.norm_forms(_vec("ligature_ff")) == ["ff"]


def test_assess_detects_nfkc_punctuation():
    hit = ub.assess_vector(_vec("fullwidth_lt"), f"<p>q={C}<{C}</p>")
    assert hit and hit["severity"] == "high" and hit["normalized_to"] == "<"


def test_assess_detects_entity_encoded_normalization():
    # the app normalized ＜→< then HTML-encoded the output — still a server-side normalization
    hit = ub.assess_vector(_vec("fullwidth_lt"), f"q={C}&lt;{C}")
    assert hit and hit["severity"] == "high"


def test_assess_passthrough_is_not_a_hit():
    # the raw fullwidth char is reflected unchanged → the app did NOT normalize
    assert ub.assess_vector(_vec("fullwidth_lt"), f"q={C}＜{C}") is None


def test_assess_kelvin_casefold_no_false_positive_on_passthrough():
    kv = _vec("kelvin_to_k")
    # casefold app: Kelvin folded to ASCII 'k' → a real hit (medium)
    hit = ub.assess_vector(kv, f"q={C}k{C}")
    assert hit and hit["severity"] == "medium" and hit["transform"] == "case-fold"
    # passthrough app reflecting the raw Kelvin sign (U+212A) must NOT be read as a fold —
    # a naive body.lower() would have turned U+212A into 'k' and false-fired here
    assert ub.assess_vector(kv, f"q={C}K{C}") is None


def test_assess_letter_medium():
    hit = ub.assess_vector(_vec("longs_to_s"), f"q={C}s{C}")
    assert hit and hit["severity"] == "medium" and hit["normalized_to"] == "s"


# -- probe against fake stateful apps ---------------------------------------
class _R:
    def __init__(self, status, text):
        self.status = status
        self._t = text
        self.body = text.encode()

    def text(self, limit=None):
        return self._t


def _q(u):
    return parse_qs(urlsplit(u).query).get("q", [""])[0]


class _NfkcApp:
    """Reflects the `q` param after NFKC normalization (fullwidth/ligature/long-s collapse)."""

    async def fetch(self, u, *, method="GET", body=None, headers=None, **kw):
        return _R(200, f"<p>results for {unicodedata.normalize('NFKC', _q(u))}</p>")


class _CasefoldApp:
    """Reflects `q` after NFKC *and* ASCII case-fold (so Kelvin U+212A → k as well)."""

    async def fetch(self, u, *, method="GET", body=None, headers=None, **kw):
        return _R(200, f"<p>results for {unicodedata.normalize('NFKC', _q(u)).casefold()}</p>")


class _PassthroughApp:
    """Reflects `q` verbatim — echoes input but never normalizes (no bypass)."""

    async def fetch(self, u, *, method="GET", body=None, headers=None, **kw):
        return _R(200, f"<p>results for {_q(u)}</p>")


class _DoubleReflectApp:
    """Repopulates the RAW query in a search box AND renders it NFKC-normalized in a results
    heading — a genuinely-normalizing app. The raw echo must NOT suppress the normalized hit."""

    async def fetch(self, u, *, method="GET", body=None, headers=None, **kw):
        q = _q(u)
        return _R(200, f'<input value="{q}"><h1>results for {unicodedata.normalize("NFKC", q)}</h1>')


class _NonReflectiveApp:
    async def fetch(self, u, *, method="GET", body=None, headers=None, **kw):
        return _R(200, "<p>static page, no echo</p>")


@pytest.mark.asyncio
async def test_probe_nfkc_app_finds_dangerous_not_kelvin():
    res = await ub.probe_unicode(_NfkcApp(), "https://x.test/search")
    assert res["reflective"] and res["dangerous"]
    names = {f["vector"] for f in res["findings"]}
    assert "fullwidth_lt" in names and "longs_to_s" in names
    assert "kelvin_to_k" not in names        # NFKC leaves Kelvin U+212A unchanged → no fold


@pytest.mark.asyncio
async def test_probe_casefold_app_also_finds_kelvin():
    res = await ub.probe_unicode(_CasefoldApp(), "https://x.test/search")
    names = {f["vector"] for f in res["findings"]}
    assert "kelvin_to_k" in names
    kv = next(f for f in res["findings"] if f["vector"] == "kelvin_to_k")
    assert kv["severity"] == "medium"


@pytest.mark.asyncio
async def test_probe_passthrough_app_no_findings():
    res = await ub.probe_unicode(_PassthroughApp(), "https://x.test/search")
    assert res["reflective"] and res["findings"] == [] and res["dangerous"] is False


@pytest.mark.asyncio
async def test_probe_multi_context_reflection_still_hits():
    # raw echo in a search box + normalized form in the heading: the normalization must still
    # be reported (a body-global raw-echo guard would false-negative here)
    res = await ub.probe_unicode(_DoubleReflectApp(), "https://x.test/search")
    assert res["dangerous"]
    assert "fullwidth_lt" in {f["vector"] for f in res["findings"]}


@pytest.mark.asyncio
async def test_probe_non_reflective_short_circuits():
    res = await ub.probe_unicode(_NonReflectiveApp(), "https://x.test/search")
    assert res["reflective"] is False and res["findings"] == []


# -- registration + dry_run -------------------------------------------------
@pytest.mark.asyncio
async def test_unicode_bypass_registered_and_dry_run(fresh_context):
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "unicode_bypass_probe" in tools
    prev = await srv.unicode_bypass_probe(target="http://127.0.0.1/search", dry_run=True)
    assert prev["dry_run"] is True
    assert prev["payload_count"] == len(ub.VECTORS)
    assert any(C in p for p in prev["payloads"])
