"""Active injection & exploitation probes.

Extracted from server.py. Scope-gated offensive detectors for the classic
injection classes — SQLi / CMDi / LFI / SSTI / string-interpolation, NoSQL
(+ GraphQL), parser-differential, ORM leak, SSRF (+ protocol smuggling), XXE,
SAML XSW, fastjson autotype and web-cache poisoning — plus the generic
`confirm_finding` re-tester. Importing this module registers them on the shared
`mcp` instance.
"""

from __future__ import annotations

import asyncio
import re
import secrets
from typing import Any

from .. import confirm as confirmmod
from ..knowledge import injections as injmod
from ..mcp_core import (
    _collect_oast,
    _require_scope,
    _run_time_based,
    _scope_check,
    active_tool,
    get_context,
    mcp,
)
from ..scope import normalize_target
from ..web import fastjson as fastjsonmod
from ..web import graphqli as gqlimod
from ..web import inject as injectmod
from ..web import interp as interpmod
from ..web import nosqli as nosqlimod
from ..web import ormleak as ormmod
from ..web import parserdiff as parserdiffmod
from ..web import probes as probesmod
from ..web import saml as samlmod
from ..web import ssrf_protocol as sspmod
from ..web import xxe as xxemod


@mcp.tool()
@active_tool(self_scoped=True)
async def confirm_finding(target: str, payload: str, param: str | None = None,
                          method: str = "GET", injection_class: str | None = None,
                          oast_token: str | None = None, record: bool = False,
                          severity: str = "medium", title: str = "") -> dict:
    """**Confirm a lead** before you report it — MoonMCP's differential + out-of-band
    validation gate (the "prove it, don't guess" step).

    Sends a **baseline** request (a benign canary) and a **test** request (your
    `payload`), then weighs the difference: was the payload **reflected** (and not
    in the baseline)? did the **status**/**length**/**timing** change? do
    **injection signatures** fire in the response (pass `injection_class`)? and —
    the strongest signal — did an **out-of-band callback** land (pass the
    `oast_token` from `oast_generate`)? Returns a verdict (`confirmed` / `likely` /
    `inconclusive` / `unconfirmed`) with the concrete signals. `param` injects into
    that query parameter; else the payload is the request body (POST). With
    `record`, a `confirmed` result is written to findings + memory. In scope only.
    """

    from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    await _require_scope(url, tool="confirm_finding")
    ctx = get_context()
    m = method.upper()
    canary = "moonc0nfirm42"

    if param:
        sp = urlsplit(url)
        q = dict(parse_qsl(sp.query, keep_blank_values=True))
        base_url = urlunsplit(sp._replace(query=urlencode({**q, param: canary})))
        test_url = urlunsplit(sp._replace(query=urlencode({**q, param: payload})))
        base_body = test_body = None
    else:
        base_url = test_url = url
        base_body = canary.encode() if m not in ("GET", "HEAD") else None
        test_body = payload.encode() if m not in ("GET", "HEAD") else None

    b = await ctx.http.fetch(base_url, method=m, body=base_body, follow_redirects=False,
                             scope_check=_scope_check())
    t = await ctx.http.fetch(test_url, method=m, body=test_body, follow_redirects=False,
                             scope_check=_scope_check())

    pb = payload.encode()
    reflected = bool(payload) and pb in t.body and pb not in b.body
    status_changed = b.status != t.status
    length_delta = len(t.body) - len(b.body)
    timing_delta = (t.elapsed_ms or 0.0) - (b.elapsed_ms or 0.0)

    hits: list[dict] = []
    if injection_class:
        # Only signatures the PAYLOAD INTRODUCES count. A signature already present in
        # the baseline (an endpoint in verbose-error mode, or an SPA bundle carrying a
        # "SyntaxError:"/SQL-error banner) is pre-existing, not payload-triggered —
        # pairing it with an ordinary reflected echo would drive confirm.evaluate to a
        # false "confirmed". Subtract baseline signatures, mirroring lfi_probe.
        base_sigs = {(h["technology"], h["matched"])
                     for h in injmod.match_signatures(b.text(200_000), class_id=injection_class)}
        hits = [h for h in injmod.match_signatures(t.text(200_000), class_id=injection_class)
                if (h["technology"], h["matched"]) not in base_sigs]
    hit_labels = [f"{h['class']}/{h['technology']}" for h in hits]

    interactions: list[dict] = []
    oast_err: str | None = None
    if oast_token:
        # The built-in self-host catcher (oast_selfhost) records callbacks locally
        # and sets no poll_url — read it directly, like ssrf_probe / oast_poll do.
        interactions, oast_err = await _collect_oast(ctx, oast_token)

    verdict = confirmmod.evaluate(
        reflected=reflected, status_changed=status_changed, length_delta=length_delta,
        injection_hits=hit_labels, oast_count=len(interactions), timing_delta_ms=timing_delta,
    )
    out: dict[str, Any] = {
        "target": url, "param": param, **verdict,
        "baseline": {"status": b.status, "length": len(b.body)},
        "test": {"status": t.status, "length": len(t.body)},
        "reflected": reflected, "injection_matches": hits[:10],
        "oast_interactions": interactions[:20],
    }
    if oast_err:
        out["oast_error"] = oast_err
    if verdict["verdict"] == "confirmed" and record:
        ts = ""
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        ftitle = title or f"Confirmed {injection_class or 'issue'} on {param or url}"
        f = ctx.findings.add(target=normalize_target(url), severity=severity, title=ftitle,
                             detail="; ".join(verdict["signals"]), evidence=payload,
                             type="confirmed", source="confirm_finding", created_at=ts)
        ctx.memory.add(kind="finding", title=ftitle, body="; ".join(verdict["signals"]),
                       target=normalize_target(url), severity=f.severity, source="confirm_finding",
                       trust="curated", provenance="manual", tags="finding,confirmed", created_at=ts)
        out["recorded_finding_id"] = f.id
    return out


# ---------------------------------------------------------------------------
# active detectors (differential probes for top-payout classes)
# ---------------------------------------------------------------------------
# The shared parameter-injection helper (query for GET/HEAD, form body otherwise).
_with_param = injectmod.with_param


@mcp.tool()
@active_tool(intrusive=True)
async def ssti_probe(target: str, param: str, method: str = "GET") -> dict:
    """**Server-Side Template Injection** probe. Injects benign arithmetic markers
    for each major engine (Jinja2/Twig, Freemarker, ERB, Smarty, Velocity, Razor,
    Handlebars) into `param` and checks whether the result (``7331*7=51317``)
    renders — i.e. the expression was *evaluated*, not reflected. Differential vs a
    control. Reports which engine fired. Intrusive; in scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    m = method.upper()
    burl, bbody = _with_param(url, param, "moonc0nfirm", m)
    b = await ctx.http.fetch(burl, method=m, body=bbody, follow_redirects=False, scope_check=_scope_check())
    tested: list[tuple[str, str, str]] = []
    for engine, payload in probesmod.SSTI_PAYLOADS:
        tu, tb = _with_param(url, param, payload, m)
        r = await ctx.http.fetch(tu, method=m, body=tb, follow_redirects=False, scope_check=_scope_check())
        tested.append((engine, payload, r.text(200_000)))
    findings = probesmod.ssti_findings(b.text(200_000), tested)
    # A single engine evaluating is a real signal; more than one "engine" rendering
    # 51317 at once is contradictory (a page emitting the digits by coincidence) —
    # downgrade rather than assert a confirmed multi-engine SSTI.
    contradictory = len(findings) > 1
    verdict = confirmmod.evaluate(
        reflected=bool(findings) and not contradictory,
        injection_hits=[f"ssti/{f['engine']}" for f in findings] if not contradictory else [])
    out = {"target": url, "param": param, **verdict, "engines": findings}
    if contradictory:
        out["verdict"] = "inconclusive"
        out["note"] = ("multiple template engines appear to evaluate the same arithmetic — likely "
                       "a coincidental digit match on the page, not SSTI; verify manually")
    return out


@mcp.tool()
@active_tool(intrusive=True)
async def sqli_probe(target: str, param: str, method: str = "GET",
                     context: str = "value", placement: str = "param",
                     name: str | None = None, oob: bool = False,
                     time_based: bool = False, waf_bypass: bool = False,
                     multibyte: bool = False, delay_s: float = 5.0,
                     oast_token: str | None = None, wait: float = 3.0) -> dict:
    """**SQL injection** probe — non-destructive, differential. Core: a single-quote
    **error** trigger (matched vs MoonMCP's SQL error signatures) + a reproducible
    **boolean** pair. Opt-in lanes for spots nuclei can't reach:
    `context` = value|order_by|limit (CASE twins for non-parameterizable positions),
    `placement` = param|header|cookie (with `name`), `oob` (per-DBMS DNS/HTTP **OAST**
    callback — start `oast_selfhost` first), `time_based` (per-DBMS sleep, confirmed only
    when the delay is proportional to `delay_s`), `waf_bypass` (JSON-operator + comment
    twins — flags SQLi reachable only when the plain boolean is blocked), `multibyte`
    (Shift-JIS/EUC-KR/GBK lead-byte charset bypass). No data extraction (→ sqlmap).
    Intrusive; in scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    m = method.upper()

    def _build(value: str, is_raw: bool = False):
        if placement in ("header", "cookie"):
            bu, bb = _with_param(url, param, "1", m) if param else (url, None)
            hdr = ({"Cookie": f"{name or 'sid'}={value}"} if placement == "cookie"
                   else {name or "User-Agent": value})
            return bu, bb, hdr
        if is_raw:
            return injectmod.inject_raw(url, param, value), None, {}
        u, b = _with_param(url, param, value, m)
        return u, b, {}

    async def _get(value: str, is_raw: bool = False):
        bu, bb, hh = _build(value, is_raw)
        return await ctx.http.fetch(bu, method=m, body=bb, headers=(hh or None),
                                    follow_redirects=False, scope_check=_scope_check())

    def _diff(t1, t2, f1, f2) -> tuple[bool, bool]:
        # Tolerate per-request jitter (nonce/timestamp/counter/ad rotation) measured
        # from the two identical sends of each arm; a real boolean differential must
        # EXCEED that noise floor, not merely differ by a byte. A byte-exact compare
        # false-negatived on any dynamic page (the common case for authed endpoints).
        jitter = max(abs(len(t1.body) - len(t2.body)), abs(len(f1.body) - len(f2.body)))
        tol = jitter + 16
        ts = (t1.status == t2.status) and abs(len(t1.body) - len(t2.body)) <= tol
        fs = (f1.status == f2.status) and abs(len(f1.body) - len(f2.body)) <= tol
        stable = bool(ts and fs)
        d = (t1.status != f1.status) or (abs(len(t1.body) - len(f1.body)) > tol)
        return stable, bool(stable and d)

    # --- core: error signatures (baseline-subtracted) + reproducible boolean (context-aware) ---
    # Subtract only AMBIENT SQL-error signatures — ones present regardless of the injected value
    # (a verbose-error endpoint, an SPA bundle carrying SQL keywords, a reflected param). Use TWO
    # benign controls: a bare number and a random alnum string. A signature that appears for BOTH
    # is genuinely ambient; one that appears for only one value TYPE is the benign value itself
    # erroring (e.g. a non-numeric string in an unquoted numeric context) — that is the very proof
    # of injection, so it must NOT be subtracted. Subtracting on a single string baseline would
    # false-NEGATIVE numeric-context error-based SQLi. (mirrors confirm_finding / lfi_probe.)
    def _sigset(resp):
        return {(h["technology"], h["matched"])
                for h in injmod.match_signatures(resp.text(200_000), class_id="sqli")}

    base_num = await _get("1")
    base_str = await _get(f"mcp{secrets.token_hex(3)}")
    ambient = _sigset(base_num) & _sigset(base_str)
    er = await _get(probesmod.SQLI_ERROR)
    hits = [h for h in injmod.match_signatures(er.text(200_000), class_id="sqli")
            if (h["technology"], h["matched"]) not in ambient]
    true_p, false_p = probesmod.sqli_context_twins(context)
    t1, t2 = await _get(true_p), await _get(true_p)
    f1, f2 = await _get(false_p), await _get(false_p)
    stable, bool_diff = _diff(t1, t2, f1, f2)

    lanes: dict[str, Any] = {}
    extra_hits: list[str] = []

    # --- multibyte charset-mismatch lane (param placement only) ---
    if multibyte and placement == "param":
        plain = await _get(probesmod.SQLI_PLAIN_QUOTE, is_raw=True)
        plain_hits = injmod.match_signatures(plain.text(200_000), class_id="sqli")
        mb: list[dict] = []
        for label, twin in probesmod.SQLI_MULTIBYTE_TWINS:
            r = await _get(twin, is_raw=True)
            sig = injmod.match_signatures(r.text(200_000), class_id="sqli")
            if sig and not plain_hits:   # errors where the plain %27 was neutralised
                mb.append({"charset": label, "technologies": [s["technology"] for s in sig][:3]})
        lanes["multibyte"] = {"plain_errored": bool(plain_hits), "bypass_charsets": mb}
        if mb:
            extra_hits.append("sqli/charset-bypass")

    # --- WAF-bypass lane: JSON-operator + comment twins ---
    if waf_bypass:
        wb: list[dict] = []
        for label, tp, fp in probesmod.SQLI_JSON_TWINS + probesmod.SQLI_ENCODING_TWINS:
            jt1, jt2 = await _get(tp), await _get(tp)
            jf1, jf2 = await _get(fp), await _get(fp)
            _s, jd = _diff(jt1, jt2, jf1, jf2)
            if jd:
                wb.append({"encoding": label})
        lanes["waf_bypass"] = {"plain_differential": bool_diff, "encoded_differentials": wb,
                               "bypass": bool(wb) and not bool_diff}
        if wb:
            extra_hits.append("sqli/waf-bypass-encoding" if not bool_diff else "sqli/encoded-differential")

    # --- time-based blind lane (repeated samples + scaling re-probe) ---
    if time_based:
        req = max(0.0, min(delay_s, 15.0))
        req_lo = max(req * 0.4, 0.5)
        tb = await _run_time_based(
            _get, probesmod.sqli_time_payloads(0), probesmod.sqli_time_payloads(req),
            probesmod.sqli_time_payloads(req_lo), req, req_lo, "dbms")
        lanes["time_based"] = {"requested_s": req, "confirm_s": round(req_lo, 3), "hits": tb}
        if tb:
            extra_hits.append("sqli/time-based")

    # --- out-of-band (OAST) lane, per DBMS ---
    oast_count = 0
    if oob:
        cb = ctx.oast.get(oast_token) if oast_token else None
        if cb is None and ctx.oast.configured:
            cb = ctx.oast.generate(label="sqli_oob")
        if cb is None:
            lanes["oob"] = {"error": "oast_unconfigured",
                            "detail": "start oast_selfhost or oast_configure before an OOB SQLi probe"}
        else:
            for _lbl, pl in probesmod.sqli_oob_payloads(cb.canary_host, cb.http_url):
                await _get(pl)
            await asyncio.sleep(max(0.0, min(wait, 8.0)))
            oh, oast_err = await _collect_oast(ctx, cb.token)
            oast_count = len(oh)
            lanes["oob"] = {"canary": cb.http_url, "token": cb.token,
                            "interaction_count": oast_count, "interactions": oh[:20]}
            if oast_err:
                lanes["oob"]["oast_error"] = oast_err
            if oh:
                extra_hits.append("sqli/oob-callback")

    timing_ms = max((h["delta_s"] for h in lanes.get("time_based", {}).get("hits", [])),
                    default=0.0) * 1000
    verdict = confirmmod.evaluate(
        injection_hits=[f"{h['class']}/{h['technology']}" for h in hits] + extra_hits,
        status_changed=bool_diff and (t1.status != f1.status),
        length_delta=(len(t1.body) - len(f1.body)) if bool_diff else 0,
        differential_confirmed=bool_diff,
        oast_count=oast_count, timing_delta_ms=timing_ms)
    out: dict[str, Any] = {
        "target": url, "param": param, "context": context, "placement": placement,
        **verdict, "error_signatures": hits[:10],
        "boolean_differential": bool_diff, "reproducible": stable,
        "true_status": t1.status, "true_len": len(t1.body),
        "false_status": f1.status, "false_len": len(f1.body)}
    if lanes:
        out["lanes"] = lanes
    return out


@mcp.tool()
@active_tool(intrusive=True)
async def cmdi_probe(target: str, param: str, method: str = "GET",
                     time_based: bool = True, delay_s: float = 3.0,
                     oob: bool = False, oast_token: str | None = None,
                     wait: float = 3.0) -> dict:
    """**Blind OS command injection** probe — non-destructive. Injects a small,
    non-combinatorial set of shell separators (`;` `|` `&&` `&` backtick `` ` `` `$()`)
    carrying ONLY a side-channel payload — never a command whose output is displayed
    (no `id`, `cat /etc/passwd`, `dir`). Two lanes: `time_based` (default on) — each
    separator + `sleep N`, confirmed only when the delay is proportional to `delay_s`
    (the same monotonic-timing check `sqli_probe`'s time-based lane uses, ruling out a
    uniformly-slow endpoint or jitter); `oob` — each separator + `curl <canary>`,
    confirmed by an **OAST** DNS/HTTP callback (start `oast_selfhost` first, or pass an
    `oast_token` from `oast_generate`). Success is proven by timing or a callback
    ONLY — command output is never displayed or exfiltrated (a reverse shell or
    reading file/output content is weaponization → Strix). Intrusive; in scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    m = method.upper()

    async def _get(value: str):
        u, b = _with_param(url, param, value, m)
        return await ctx.http.fetch(u, method=m, body=b, follow_redirects=False,
                                    scope_check=_scope_check())

    lanes: dict[str, Any] = {}
    extra_hits: list[str] = []
    timing_ms = 0.0

    if time_based:
        req = max(0.0, min(delay_s, 10.0))
        req_lo = max(req * 0.4, 0.5)
        tb = await _run_time_based(
            _get, probesmod.cmdi_time_payloads(0), probesmod.cmdi_time_payloads(req),
            probesmod.cmdi_time_payloads(req_lo), req, req_lo, "separator")
        lanes["time_based"] = {"requested_s": req, "confirm_s": round(req_lo, 3), "hits": tb}
        if tb:
            extra_hits.append("cmdi/time-based")
            timing_ms = max(h["delta_s"] for h in tb) * 1000

    oast_count = 0
    if oob:
        cb = ctx.oast.get(oast_token) if oast_token else None
        if cb is None and ctx.oast.configured:
            cb = ctx.oast.generate(label="cmdi_oob")
        if cb is None:
            lanes["oob"] = {"error": "oast_unconfigured",
                            "detail": "start oast_selfhost or oast_configure before an OOB cmdi probe"}
        else:
            for _sep, pl in probesmod.cmdi_oob_payloads(cb.http_url):
                await _get(pl)
            await asyncio.sleep(max(0.0, min(wait, 8.0)))
            oh, oast_err = await _collect_oast(ctx, cb.token)
            oast_count = len(oh)
            lanes["oob"] = {"canary": cb.http_url, "token": cb.token,
                            "interaction_count": oast_count, "interactions": oh[:20]}
            if oast_err:
                lanes["oob"]["oast_error"] = oast_err
            if oh:
                extra_hits.append("cmdi/oob-callback")

    verdict = confirmmod.evaluate(injection_hits=extra_hits, oast_count=oast_count,
                                  timing_delta_ms=timing_ms)
    return {"target": url, "param": param, **verdict, "lanes": lanes}


# path-traversal KB signatures that are *not* genuine file-content disclosure:
# they fire on benign JS (`require(`/`include(`), any generic filesystem-error
# page, or any host list containing `127.0.0.1 localhost`. They only prove the
# parameter *reaches* a file API — a weak lead, never a confirmed traversal.
_LFI_WEAK_SIGS = frozenset({
    "generic (error-based path leak)",
    "PHP wrapper error",
    "Windows hosts file",
})


@mcp.tool()
@active_tool(intrusive=True)
async def lfi_probe(target: str, param: str, method: str = "GET") -> dict:
    """**Path traversal / LFI** content-disclosure probe — non-destructive. Sends
    depth-escalating (`../` x1/x3/x6/x8), null-byte, double-URL-encoded, and
    Windows-style traversal variants at `param` and checks the response for a
    genuine **file-content signature** (the `root:x:0:0:` /etc/passwd anchor,
    win.ini `[fonts]`/`[extensions]` markers, and related patterns from the
    `path-traversal` knowledge base) — proof the traversal reached the filesystem,
    not just that a WAF let the payload's *shape* through (that's `waf_bypass_probe`'s
    canary). A benign baseline is fetched first and any signature it *also* produces
    is subtracted, so a JS bundle full of `require(` or a page that always echoes a
    filesystem error cannot be scored as a hit. Only signatures the traversal payload
    *introduces* count, and only genuine file-content anchors reach the `confirmed`
    verdict — error-based "reaches a file API" hits are reported as a weak lead.
    Reads only universally-present, non-sensitive files (never app source,
    credentials, or config) — proving reachability, not extracting data (deeper
    extraction is weaponization → Strix). Intrusive; in scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    m = method.upper()
    sc = _scope_check()

    async def _get(value: str, is_raw: bool):
        if is_raw:
            u = injectmod.inject_raw(url, param, value)
            return await ctx.http.fetch(u, method=m, follow_redirects=False, scope_check=sc)
        u, b = _with_param(url, param, value, m)
        return await ctx.http.fetch(u, method=m, body=b, follow_redirects=False, scope_check=sc)

    # Benign baseline: the same request with a harmless, non-traversal value. Any
    # signature that also fires here is a property of the endpoint (a JS bundle that
    # contains `require(`, a page that always shows a filesystem error, a config that
    # lists `127.0.0.1 localhost`), NOT of the traversal — subtract it and only count
    # signatures the traversal payload *introduces*.
    base = await _get(f"mcp{secrets.token_hex(3)}", False)
    base_sigs = {(h["technology"], h["matched"])
                 for h in injmod.match_signatures(base.text(50_000), class_id="path-traversal")}

    findings: list[dict] = []   # strong: genuine file-content disclosure (confirmed)
    leads: list[dict] = []      # weak: param reaches a file API (error-based lead)
    for label, payload, is_raw in probesmod.LFI_PAYLOADS:
        r = await _get(payload, is_raw)
        if r.status is None:
            continue
        new = [h for h in injmod.match_signatures(r.text(50_000), class_id="path-traversal")
               if (h["technology"], h["matched"]) not in base_sigs]
        if not new:
            continue
        strong = [h for h in new if h["technology"] not in _LFI_WEAK_SIGS]
        weak = [h for h in new if h["technology"] in _LFI_WEAK_SIGS]
        if strong:
            findings.append({"payload_label": label, "payload": payload,
                             "status": r.status, "signatures": strong[:5]})
        elif weak:
            leads.append({"payload_label": label, "payload": payload,
                          "status": r.status, "signatures": weak[:5]})

    # Only a genuine file-content signature the baseline lacks confirms disclosure.
    # Error-based leads never set `reflected`, so they cannot reach the strong
    # ("confirmed") path in confirm.evaluate — they fire on benign JS / error pages.
    verdict = confirmmod.evaluate(
        injection_hits=[f"{h['class']}/{h['technology']}" for f in findings for h in f["signatures"]],
        reflected=bool(findings))
    out: dict[str, Any] = {"target": url, "param": param, "tested": len(probesmod.LFI_PAYLOADS),
                           **verdict, "findings": findings, "leads": leads}
    if leads and not findings:
        out["note"] = ("only error-based 'reaches a file API' signals fired (no file "
                       "content recovered) — a weak lead, not a confirmed traversal; "
                       "verify the parameter's file-handling context manually")
    return out


@mcp.tool()
@active_tool(intrusive=True)
async def interp_probe(target: str, param: str, method: str = "GET") -> dict:
    """**Generic differential "interpretation" prober** (Backslash Powered
    Scanner-style) — a meta-probe, not a class-specific one. Sends five small,
    distinctive markers into `param` — each revealing ONE kind of character-level
    processing (backslash/escape handling, quote/string-context handling,
    NUL-byte truncation, `/./` path-segment normalization, bare `{}`
    template/structural-token handling) — and checks whether each was echoed
    literally or transformed. **Two or more independent markers agreeing** is the
    corroboration bar before this calls anything more than a weak signal (a
    single marker could be an unrelated WAF/encoder quirk). Never asserts a
    specific vulnerability class — `suggested_next` points at which
    class-specific probe (`sqli_probe`, `cmdi_probe`, `lfi_probe`, `ssti_probe`,
    `parser_diff_probe`, ...) to run given which markers fired. Intrusive; in
    scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    m = method.upper()
    sc = _scope_check()
    control = f"mcp{secrets.token_hex(4)}"

    hits: list[dict] = []
    for name, template, _tools, description in interpmod.MARKERS:
        value = interpmod.build_probe(control, template)
        u, b = _with_param(url, param, value, m)
        r = await ctx.http.fetch(u, method=m, body=b, follow_redirects=False, scope_check=sc)
        body = r.text(50_000) if r.status is not None else ""
        assessed = interpmod.assess_marker(control, template, body)
        hits.append({"marker": name, "description": description, **assessed})

    return {
        "target": url, "param": param, "control": control,
        "verdict": interpmod.verdict(hits),
        "corroborating_markers": sum(1 for h in hits if h["interpreted"]),
        "markers": hits,
        "suggested_next": interpmod.suggest_next(hits),
    }


@mcp.tool()
@active_tool(intrusive=True)
async def nosqli_probe(target: str, param: str, method: str = "POST") -> dict:
    """**NoSQL (MongoDB) operator-injection** probe — non-destructive. Sends an
    *object* where the app expects a *string* — `$ne`/`$gt`/`$nin` in both the
    bracket form (`param[$ne]=x`) and JSON form (`{"param":{"$ne":null}}`) — plus a
    `$where` server-side-JS **boolean** pair (`return true` vs `return false`).
    Confirmed when a *reproducible* operator twin flips the outcome vs a plain-string
    baseline (auth bypass / more records), the `$where` boolean differs, or a MongoDB
    error signature fires. No data extraction (no `$regex` char-oracle, no `sleep()` —
    those go to NoSQLMap/Strix). Intrusive; in scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    m = method.upper()
    bodies: list[str] = []

    async def _send(req, http_method):
        u, b, h = req
        r = await ctx.http.fetch(u, method=http_method, body=b, headers=(h or None),
                                 follow_redirects=False, scope_check=_scope_check())
        bodies.append(r.text(50_000))
        return nosqlimod.Resp(status=r.status, length=len(r.body),
                              session_cookie=nosqlimod.has_session_cookie(r.get_all("set-cookie")))

    # Negative baseline: a plain scalar unlikely to match, sent twice.
    c_req = nosqlimod.scalar_request(url, param, nosqlimod.CONTROL, m)
    control = (await _send(c_req, m), await _send(c_req, m))

    # Benign nested-key control: `param[zz]=CONTROL` (a NON-operator nested key). A
    # framework that parses brackets into an object (Express/qs, PHP) flips on this
    # too, regardless of the backend DB — so a bracket-operator flip that merely
    # matches this benign one is param parsing, not Mongo injection (corroboration).
    nested_req = nosqlimod.bracket_request(url, param, "zz", nosqlimod.CONTROL, m)
    nested_ctrl = (await _send(nested_req, m), await _send(nested_req, m))

    # Operator lane: bracket twins (corroborated vs the benign nested control) in the
    # requested method + JSON twins as POST.
    operator_hits: list[dict] = []
    for label, op, val in nosqlimod.BRACKET_TWINS:
        req = nosqlimod.bracket_request(url, param, op, val, m)
        twin = (await _send(req, m), await _send(req, m))
        hit = nosqlimod.assess_operator(control, twin, nested=nested_ctrl)
        if hit:
            operator_hits.append({"variant": label, **hit})
    # The JSON lane needs its OWN content-type-matched baseline: a JSON *scalar*
    # body ({"param": CONTROL}), so the only variable vs the operator twins is
    # scalar-vs-object. Comparing a JSON-object POST against the form/GET scalar
    # `control` misread a JSON-only API's content-type status flip (form 400 → JSON
    # 200) as $ne injection — a false positive on a non-injectable endpoint.
    json_control = (await _send(nosqlimod.json_request(url, param, nosqlimod.CONTROL), "POST"),
                    await _send(nosqlimod.json_request(url, param, nosqlimod.CONTROL), "POST"))
    for label, obj in nosqlimod.JSON_TWINS:
        req = nosqlimod.json_request(url, param, obj)
        twin = (await _send(req, "POST"), await _send(req, "POST"))
        hit = nosqlimod.assess_operator(json_control, twin)
        if hit:
            operator_hits.append({"variant": label, **hit})

    # $where server-side-JS boolean oracle (JSON body, boolean only).
    wt = (await _send(nosqlimod.json_request(url, param, nosqlimod.WHERE_TRUE), "POST"),
          await _send(nosqlimod.json_request(url, param, nosqlimod.WHERE_TRUE), "POST"))
    wf = (await _send(nosqlimod.json_request(url, param, nosqlimod.WHERE_FALSE), "POST"),
          await _send(nosqlimod.json_request(url, param, nosqlimod.WHERE_FALSE), "POST"))
    where_hit = nosqlimod.assess_where(wt, wf)

    # Error lane: MongoDB/BSON error signatures leaked by any twin.
    # Only signatures the OPERATOR payloads INTRODUCE count. A Mongo/JS error string
    # already present in the plain-scalar control responses (verbose app errors, or an
    # SPA bundle carrying "SyntaxError:"/"ReferenceError:"/"CastError") is pre-existing,
    # not injection — subtract it so it can't drive confirm.evaluate to a false "likely"
    # (mirrors lfi_probe / confirm_finding). A CastError the operator OBJECT actually
    # triggers is new -> still counted.
    _base_sig_keys = {(h["technology"], h["matched"])
                      for h in injmod.match_signatures("\n".join(bodies[:2]), class_id="nosqli")}
    sig_hits = [h for h in injmod.match_signatures("\n".join(bodies), class_id="nosqli")
                if (h["technology"], h["matched"]) not in _base_sig_keys]

    strong_op = next((h for h in operator_hits if h["strong"]), None)
    injection_hits = [f"nosqli/{h['variant']}" for h in operator_hits]
    injection_hits += [f"{h['class']}/{h['technology']}" for h in sig_hits]
    if where_hit:
        injection_hits.append("nosqli/$where-js")
    verdict = confirmmod.evaluate(
        injection_hits=injection_hits,
        status_changed=bool(strong_op) or bool(where_hit and where_hit["status_changed"]),
        length_delta=(where_hit["length_delta"] if where_hit else 0),
        differential_confirmed=bool(where_hit))
    return {"target": url, "param": param, "method": m, **verdict,
            "operator_hits": operator_hits, "where_oracle": where_hit,
            "error_signatures": sig_hits[:10],
            "baseline": {"status": control[0].status, "length": control[0].length}}


@mcp.tool()
@active_tool(intrusive=True)
async def graphql_nosqli(target: str, query: str, variable: str = "moon") -> dict:
    """**GraphQL → NoSQL operator-injection** — detection only. After `graphql_check`
    finds an endpoint, this tests whether a resolver forwards a client object straight
    into a Mongo/Mongoose filter. Give a GraphQL `query` referencing `$<variable>`
    declared as a JSON/Object scalar (e.g. `query($moon:JSON){login(filter:$moon){token}}`);
    the tool sends the variable as a plain-string baseline vs operator objects
    (`$ne`/`$gt`/`$in`/`$nin`) and flags a *reproducible* flip (a resolver returns data /
    more records where the scalar did not) or a Mongoose `CastError` in `errors[]`. If the
    server rejects the object with a GraphQL type error the variable is strictly typed →
    not injectable via it (reported, not a hit). Detection-only — no `$regex` extraction /
    `sleep()` (→ NoSQLMap/Strix). Intrusive; in scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    # Detection-only: refuse a write. The operator twins are match-everything filters,
    # so running them through a mutation/subscription could drive a mass write.
    op_head = re.sub(r"#[^\n]*", "", query).lstrip("﻿ \t\r\n")
    kw = re.match(r"[A-Za-z]+", op_head)
    first = kw.group(0).lower() if kw else ""
    if first in ("mutation", "subscription"):
        return {"target": url, "error": "invalid_input",
                "detail": f"graphql_nosqli is detection-only and refuses a {first} operation "
                          "(the operator twins broaden the filter to match all records, which "
                          "could drive a mass write). Supply a read `query`; mutation-based "
                          "validation is Strix's job."}
    ctx = get_context()
    bodies: list[str] = []

    async def _send(value):
        r = await ctx.http.fetch(
            url, method="POST", headers={"Content-Type": "application/json"},
            body=gqlimod.build_body(query, variable, value),
            follow_redirects=False, scope_check=_scope_check())
        full = r.text()                       # data/rejected need the WHOLE body, not a slice
        bodies.append(full[:50_000])
        return gqlimod.Resp(
            status=r.status, length=len(r.body),
            data=gqlimod.data_present(full), rejected=gqlimod.is_rejected(full),
            session=nosqlimod.has_session_cookie(r.get_all("set-cookie")))

    # String baseline (sent twice) vs each operator object (sent twice).
    control = (await _send(gqlimod.CONTROL), await _send(gqlimod.CONTROL))
    operator_hits: list[dict] = []
    any_rejected = False
    for label, obj in gqlimod.OPERATOR_TWINS:
        twin = (await _send(obj), await _send(obj))
        any_rejected = any_rejected or twin[0].rejected
        hit = gqlimod.assess_operator(control, twin)
        if hit:
            operator_hits.append({"operator": label, **hit})

    # Subtract signatures present in the string-baseline responses (bodies[:2]) so a
    # pre-existing benign JS/Mongo error (SyntaxError/ReferenceError/CastError in the
    # app's normal output) can't count as injection — only operator-INTRODUCED
    # signatures score. Mirrors lfi_probe / confirm_finding / nosqli_probe.
    _base_sig_keys = {(h["technology"], h["matched"])
                      for h in injmod.match_signatures("\n".join(bodies[:2]), class_id="nosqli")}
    sig_hits = [h for h in injmod.match_signatures("\n".join(bodies), class_id="nosqli")
                if (h["technology"], h["matched"]) not in _base_sig_keys]
    # A type rejection (independent of status) means the variable is strictly typed —
    # not injectable via it. Reported as its own state, never scored as a hit.
    strictly_typed = any_rejected and not operator_hits and not sig_hits

    strong_op = next((h for h in operator_hits if h["strong"]), None)
    injection_hits = [f"graphql-nosqli/{h['operator']}" for h in operator_hits]
    injection_hits += [f"{h['class']}/{h['technology']}" for h in sig_hits]
    verdict = confirmmod.evaluate(injection_hits=injection_hits, status_changed=bool(strong_op))
    return {"target": url, "variable": variable, **verdict,
            "operator_hits": operator_hits, "error_signatures": sig_hits[:10],
            "strictly_typed_variable": strictly_typed,
            "note": ("the operator object was rejected by GraphQL validation — the variable is "
                     "strictly typed (String); try an arg typed as a JSON/Object scalar"
                     if strictly_typed else None),
            "baseline": {"status": control[0].status, "length": control[0].length,
                         "data": control[0].data}}


@mcp.tool()
@active_tool(intrusive=True)
async def parser_diff_probe(target: str, param: str, method: str = "POST") -> dict:
    """**HTTP parser-differential** probe — a WAF-bypass *multiplier*, detection-only.
    A fronting WAF and the app behind it often parse the same request differently;
    that disagreement is the primitive behind most modern WAF bypasses. Sends benign
    canonical-vs-quirk twins carrying an inert canary and reports where the app **(a)
    decoded** an encoded-only canary — UTF-7 (`+AG0-`) or overlong UTF-8 (`%C1%AD`)
    reflected back as plain text (strong: a proven transform) — or **(b) accepted and
    parsed** a form a *standard* parser rejects — JSON comments / trailing commas / a
    leading UTF-8 BOM, or bare-LF multipart line endings — while an echo-everything
    endpoint is excluded (medium: a real lax-parser surface). Duplicate JSON keys /
    multipart fields are RFC-permitted, so they are reported only as a `precedence`
    lead (which value wins) and never raise the verdict. Delivers nothing executable
    and extracts nothing; smuggling a real payload through a confirmed differential is
    Strix's job. Best against an endpoint that echoes `param`. Intrusive; in scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    m = method.upper()

    async def _send(req, http_method):
        u, b, h = req
        r = await ctx.http.fetch(u, method=http_method, body=b, headers=(h or None),
                                 follow_redirects=False, scope_check=_scope_check())
        body = r.text(50_000).lower()
        return parserdiffmod.Resp(
            status=r.status, length=len(r.body),
            has_canary=parserdiffmod.CANARY in body,
            has_decoy=parserdiffmod.DECOY in body)

    C, D = parserdiffmod.CANARY, parserdiffmod.DECOY
    lanes: list[dict] = []

    # --- decode lanes (strong): sent encoded-only; a plain-canary reflection proves
    #     the app applied the transform.
    utf7_base = await _send(parserdiffmod.form_canonical(url, param, C, "POST"), "POST")
    utf7_quirk = await _send(parserdiffmod.utf7_form(url, param, C), "POST")
    hit = parserdiffmod.assess_decode(utf7_base, utf7_quirk)
    if hit:
        lanes.append({"lane": "charset_utf7", **hit})

    ov_base = await _send(parserdiffmod.form_canonical(url, param, C, "GET"), "GET")
    ov_quirk = await _send(parserdiffmod.overlong_query(url, param, C), "GET")
    hit = parserdiffmod.assess_decode(ov_base, ov_quirk)
    if hit:
        lanes.append({"lane": "overlong_utf8", **hit})

    # --- JSON tolerance lanes (standard-parser-rejected → scored): canonical + a
    #     reject-control that gates out echo-everything endpoints.
    j_base = await _send(parserdiffmod.json_canonical(url, param, C), "POST")
    j_invalid = await _send(parserdiffmod.json_invalid(url, param, C), "POST")
    json_quirks = [
        ("json_comment", parserdiffmod.json_comment(url, param, C)),
        ("json_trailing", parserdiffmod.json_trailing(url, param, C)),
        ("json_bom", parserdiffmod.json_bom(url, param, C)),
    ]
    for label, req in json_quirks:
        hit = parserdiffmod.assess_tolerance(j_base, await _send(req, "POST"), j_invalid)
        if hit:
            lanes.append({"lane": label, **hit})

    # --- multipart tolerance lane (bare-LF line endings a strict CRLF parser rejects).
    mp_base = await _send(parserdiffmod.multipart_canonical(url, param, C), "POST")
    mp_invalid = await _send(parserdiffmod.multipart_invalid(url, param, C), "POST")
    hit = parserdiffmod.assess_tolerance(
        mp_base, await _send(parserdiffmod.multipart_lf(url, param, C), "POST"), mp_invalid)
    if hit:
        lanes.append({"lane": "multipart_lf", **hit})

    # --- precedence leads (RFC-permitted duplicate keys / fields → informational
    #     only, never scored: acceptance is standard, only *which value wins* matters).
    precedence: list[dict] = []
    p = parserdiffmod.assess_precedence(
        j_base, await _send(parserdiffmod.json_dupkey(url, param, D, C), "POST"))
    if p:
        precedence.append({"lane": "json_dupkey", **p})
    p = parserdiffmod.assess_precedence(
        mp_base, await _send(parserdiffmod.multipart_dup(url, param, D, C), "POST"))
    if p:
        precedence.append({"lane": "multipart_dup", **p})

    decode_hit = any(x["strong"] for x in lanes)
    injection_hits = [f"parser-diff/{x['lane']}" for x in lanes]
    verdict = confirmmod.evaluate(
        injection_hits=injection_hits,
        reflected=decode_hit,
        status_changed=False)
    return {"target": url, "param": param, "method": m, **verdict,
            "lanes": lanes, "precedence": precedence,
            "reflective": utf7_base.has_canary or j_base.has_canary,
            "note": None if lanes else
            "no scored parser differential observed (or endpoint does not echo the parameter)"}


@mcp.tool()
@active_tool(intrusive=True)
async def orm_leak_probe(target: str, orm: str = "auto", base: str = "filter",
                         method: str = "GET") -> dict:
    """**ORM leak / relational-filter injection** — a filter differential nuclei and
    `sqli_probe` both miss (no raw SQL). When an app spreads request params into an ORM
    filter, an injected lookup filters by a hidden field (`password`, `reset_token`,
    `is_superuser`). Injects each lookup as a new kwarg with an **empty prefix** (matches
    all rows) vs an **unlikely prefix** (matches none): a reproducible differential means
    the lookup is applied and the field is queryable. `orm` = auto|django|prisma|ransack;
    Prisma/Ransack nest under `base` (the filter object's param name). Detection-only — no
    value is read out (char-by-char extraction / mass-assignment → logic_probe / Strix).
    Intrusive; in scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    sc = _scope_check()
    m = method.upper()
    cands = ormmod.candidates(orm, base)

    async def _get(pname: str, value: str) -> tuple:
        u, b = _with_param(url, pname, value, m)
        r = await ctx.http.fetch(u, method=m, body=b, follow_redirects=False, scope_check=sc)
        return (r.status, len(r.body))

    findings: list[dict] = []
    for family, label, pname in cands:
        all_pair = (await _get(pname, ""), await _get(pname, ""))
        none_pair = (await _get(pname, ormmod.CONTROL_NONE), await _get(pname, ormmod.CONTROL_NONE))
        # Cheap gate first: only pay for the reflection control (a second, longer
        # no-match value) when a reproducible differential already looks present.
        if not ormmod.looks_applied(all_pair, none_pair):
            continue
        none_alt = (await _get(pname, ormmod.CONTROL_NONE_ALT),
                    await _get(pname, ormmod.CONTROL_NONE_ALT))
        if ormmod.assess_lookup(all_pair, none_pair, none_alt):
            findings.append({
                "orm": family, "field": label, "param": pname,
                "severity": "high", "verdict": "review",
                "detail": f"injected ORM lookup '{pname}' filters the result set (empty-prefix vs "
                          f"no-match differ, reproducibly) — the hidden field '{label}' is queryable; "
                          "it can be read char-by-char (weaponize via Strix, not here)"})
    verdict = confirmmod.evaluate(
        injection_hits=[f"orm-injection/{f['field']}" for f in findings],
        status_changed=bool(findings))
    return {"target": url, "orm": orm, "tested": len(cands), **verdict, "findings": findings}


@mcp.tool()
@active_tool(intrusive=True)
async def ssrf_probe(target: str, param: str, method: str = "GET",
                     oast_token: str | None = None, wait: float = 2.0) -> dict:
    """**Blind SSRF** probe. Plants an **OAST canary** URL in `param`, sends the
    request, waits briefly, then checks whether the target called back — a landed
    callback is strong proof of blind SSRF. Start `oast_selfhost` (or
    `oast_configure`) first, or pass an existing `oast_token` from `oast_generate`.
    Intrusive; in scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    cb = ctx.oast.get(oast_token) if oast_token else None
    if cb is None:
        if not ctx.oast.configured:
            return {"error": "oast_unconfigured",
                    "detail": "start oast_selfhost or oast_configure before probing for blind SSRF"}
        cb = ctx.oast.generate(label="ssrf_probe")
    m = method.upper()
    tu, tb = _with_param(url, param, cb.http_url, m)
    await ctx.http.fetch(tu, method=m, body=tb, follow_redirects=False, scope_check=_scope_check())
    await asyncio.sleep(max(0.0, min(wait, 5.0)))
    hits, oast_err = await _collect_oast(ctx, cb.token)
    verdict = confirmmod.evaluate(oast_count=len(hits))
    out = {"target": url, "param": param, "canary": cb.http_url, "token": cb.token,
           **verdict, "interactions": hits[:20]}
    if oast_err:
        out["oast_error"] = oast_err
        out["note"] = ("could not verify the callback channel — the OAST poll failed, so this is "
                       "NOT a clean no-hit; re-check with oast_poll")
    elif not hits:
        out["note"] = "no callback yet — the target may call back later; re-check with oast_poll"
    return out


@mcp.tool()
@active_tool(intrusive=True)
async def xxe_probe(target: str, body: str = "", content_type: str = "application/json",
                    method: str = "POST", oast_token: str | None = None,
                    wait: float = 3.0) -> dict:
    """**Blind XXE** probe — two non-destructive lanes.

    `format_confusion`: rewrites `body` (a JSON object, or form-urlencoded per
    `content_type`) into an equivalent XML document and resends it with the
    ORIGINAL Content-Type — some frameworks parse a body by *sniffing its shape*
    rather than strictly enforcing the declared type, so a "JSON-only" endpoint
    may still hand it to an XML parser. This lane alone proves nothing about XXE;
    it just tells you whether the `oob` lane is worth trying here.

    `oob`: injects a `<!DOCTYPE>` external entity referencing a MoonMCP **OAST**
    canary (sent as `Content-Type: application/xml`) and polls for a DNS/HTTP
    callback — a callback is unambiguous proof the parser dereferenced an
    external entity. **Never reads file contents** (no exfil channel is built,
    unlike a real XXE PoC) — start `oast_selfhost`/`oast_configure` first, or
    pass an `oast_token` from `oast_generate`. Intrusive; in scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    m = method.upper()
    sc = _scope_check()
    ct = content_type.lower()

    result: dict[str, Any] = {"target": url}

    confusion: dict[str, Any] = {}
    if body:
        xml_body = xxemod.json_to_xml(body) if "json" in ct else (
            xxemod.form_to_xml(body) if "form" in ct else None)
        if xml_body is not None:
            r = await ctx.http.fetch(url, method=m, body=xml_body.encode(),
                                     headers={"Content-Type": content_type},
                                     follow_redirects=False, scope_check=sc)
            confusion = {
                "rewritten_body": xml_body, "status": r.status,
                "note": ("sent WITH the original Content-Type — a response that looks "
                         "successful (2xx / same shape as a normal request) suggests the "
                         "framework parses the body by its shape, not the declared type; "
                         "try the oob lane against this endpoint."),
            }
        else:
            confusion = {"error": "not_rewritable",
                        "detail": "body isn't a JSON object or form-urlencoded content"}
    result["format_confusion"] = confusion

    oast_count = 0
    cb = ctx.oast.get(oast_token) if oast_token else None
    if cb is None and ctx.oast.configured:
        cb = ctx.oast.generate(label="xxe_probe")
    if cb is None:
        result["oob"] = {"error": "oast_unconfigured",
                         "detail": "start oast_selfhost or oast_configure before an OOB XXE probe"}
    else:
        payload = xxemod.xxe_oob_payload(cb.http_url)
        await ctx.http.fetch(url, method=m, body=payload.encode(),
                             headers={"Content-Type": "application/xml"},
                             follow_redirects=False, scope_check=sc)
        await asyncio.sleep(max(0.0, min(wait, 8.0)))
        hits, oast_err = await _collect_oast(ctx, cb.token)
        oast_count = len(hits)
        result["oob"] = {"canary": cb.http_url, "token": cb.token,
                         "interaction_count": oast_count, "interactions": hits[:20]}
        if oast_err:
            result["oob"]["oast_error"] = oast_err

    verdict = confirmmod.evaluate(oast_count=oast_count)
    result.update(verdict)
    return result


@mcp.tool()
@active_tool(intrusive=True)
async def saml_xsw_probe(acs_url: str, saml_response: str, relay_state: str = "",
                         forged_marker: str = samlmod.DEFAULT_FORGED_NAMEID) -> dict:
    """**SAML XML Signature Wrapping (XSW)** probe. Give it a legitimately
    signed `saml_response` (base64 — the HTTP-POST binding wire format — or raw
    XML) already captured from a real login (via `http_history`/Burp/a
    browser), and the SP's `acs_url` (Assertion Consumer Service endpoint).

    First reports a **static structural read** (no network): assertion/signature
    counts, and whether any `<ds:Signature>` `Reference URI` fails to match an
    `Assertion` `ID` in the document — all classic XSW enablers.

    Then resends the document three ways, each cloning the original signed
    assertion, stripping the clone's signature, and overwriting its claimed
    identity with `forged_marker`, spliced in per one of three representative
    topologies (not the full XSW1-8 taxonomy — a small representative set, see
    `moonmcp/web/saml.py`): `sibling_before` (tests "grabs the first
    assertion"), `sibling_after` ("grabs the last"), `wrap_extension` ("only
    looks at direct children of Response" — the original is relocated one
    level deeper). The original assertion's signature is never touched.

    Confirmation is layered: `reflected_forged_identity` — `forged_marker`
    showing up in a variant's response but in NEITHER baseline's — is the
    strongest, replay-noise-independent signal (the SP consumed the forged,
    unsigned identity). `matches_accepted_baseline` is a weaker secondary
    signal (status matches a verbatim resend of the original rather than a
    signature-corrupted control) — noisier, since SAML anti-replay
    (`OneTimeUse`/`InResponseTo`) can reject repeat sends independent of
    signature binding. Never forges a valid signature — the wrapping trick IS
    the attack. Intrusive; in scope only.
    """

    import base64
    from urllib.parse import urlencode

    ctx = get_context()
    sc = _scope_check()

    xml_text = samlmod.decode_response(saml_response)
    structure = samlmod.parse_structure(xml_text)
    if "error" in structure:
        return {"acs_url": acs_url, "error": structure["error"], "detail": structure.get("detail")}
    assessment = samlmod.assess_wrappable(structure)

    async def _post(xml_doc: str) -> tuple[Any, str]:
        b64 = base64.b64encode(xml_doc.encode()).decode()
        body = urlencode({"SAMLResponse": b64, "RelayState": relay_state}).encode()
        r = await ctx.http.fetch(acs_url, method="POST", body=body,
                                 headers={"Content-Type": "application/x-www-form-urlencoded"},
                                 follow_redirects=False, scope_check=sc)
        resp = samlmod.Resp(status=r.status, length=len(r.body), location=r.header("Location") or "")
        return resp, r.text(50_000)

    accepted_resp, accepted_body = await _post(xml_text)

    corrupted_xml = samlmod.corrupt_signature(xml_text)
    if corrupted_xml is not None:
        corrupted_resp, corrupted_body = await _post(corrupted_xml)
    else:
        b64 = base64.b64encode(xml_text.encode()).decode()
        truncated = b64[:-4] if len(b64) > 8 else b64 + "AAAA"
        body = urlencode({"SAMLResponse": truncated, "RelayState": relay_state}).encode()
        r = await ctx.http.fetch(acs_url, method="POST", body=body,
                                 headers={"Content-Type": "application/x-www-form-urlencoded"},
                                 follow_redirects=False, scope_check=sc)
        corrupted_resp = samlmod.Resp(status=r.status, length=len(r.body), location=r.header("Location") or "")
        corrupted_body = r.text(50_000)

    # Reflection control: submit the forged marker in a document any correct SP MUST
    # reject (the signed original's signature corrupted, so nothing authenticates). If
    # the marker still reflects here, the endpoint just echoes the posted document (a
    # verbose error/debug page) — so plain echo can't masquerade as consumption and
    # drive a false "confirmed" bypass.
    echo_control_body = ""
    base_for_echo = corrupted_xml if corrupted_xml is not None else xml_text
    echo_xml = samlmod.build_variant(base_for_echo, samlmod.VARIANTS[0], forged_nameid=forged_marker)
    if echo_xml is not None:
        _echo_resp, echo_control_body = await _post(echo_xml)

    variants: dict[str, dict] = {}
    for v in samlmod.VARIANTS:
        mutated = samlmod.build_variant(xml_text, v, forged_nameid=forged_marker)
        if mutated is None:
            variants[v] = {"error": "not_applicable",
                          "detail": "document isn't a samlp:Response with an assertion"}
            continue
        vresp, vbody = await _post(mutated)
        variants[v] = samlmod.assess_variant(
            accepted=accepted_resp, corrupted=corrupted_resp, variant=vresp,
            variant_body=vbody, accepted_body=accepted_body, corrupted_body=corrupted_body,
            forged_marker=forged_marker, echo_control_body=echo_control_body)

    scored = {v: a for v, a in variants.items() if "error" not in a}
    # Only the strong, replay-noise-independent signal earns a spot in this
    # top-level summary -- matches_accepted_baseline alone is too noisy to
    # report as "vulnerable" (see the docstring); it's still visible per-variant.
    hit_variants = [v for v, a in scored.items() if a["reflected_forged_identity"]]
    strongest = next((v for v, a in scored.items() if a["reflected_forged_identity"]), None)
    reflected_hits = [f"saml-xsw/{v}" for v, a in scored.items() if a["reflected_forged_identity"]]
    verdict = confirmmod.evaluate(
        reflected=bool(reflected_hits),
        injection_hits=reflected_hits,
        status_changed=any(a["matches_accepted_baseline"] for a in scored.values()),
        length_delta=(scored[strongest]["length_delta_vs_corrupted"] if strongest else 0))

    return {
        "acs_url": acs_url,
        "structure": structure,
        "static_assessment": assessment,
        **verdict,
        "baseline_accepted": {"status": accepted_resp.status, "length": accepted_resp.length},
        "baseline_corrupted": {"status": corrupted_resp.status, "length": corrupted_resp.length},
        "variants": variants,
        "vulnerable_variants": hit_variants,
        "caveat": ("SAML anti-replay (OneTimeUse conditions, InResponseTo tracking) can make "
                  "status/length baselines noisy across repeated sends of the same assertion "
                  "ID -- reflected_forged_identity (the forged marker appearing in a variant's "
                  "response but neither baseline's) is the strongest signal and is independent "
                  "of that noise."),
    }


@mcp.tool()
@active_tool(intrusive=True)
async def ssrf_protocol_probe(target: str, param: str, method: str = "GET",
                              ports: str = "db", oast_token: str | None = None,
                              wait: float = 3.0) -> dict:
    """**SSRF → internal datastore** reach — protocol-smuggling + internal-port detection.
    Two safe lanes: (1) inject `gopher://`/`dict://`/`ftp://` (+ an `http://` control)
    canaries and poll OAST — a callback proves the sink dereferences that scheme (raw-TCP
    reach to internal Redis/memcached, etc.); gopher/dict/ftp callbacks need a DNS/TCP OAST
    (`oast_configure`), the built-in HTTP catcher only sees the http control. (2) inject
    `http://127.0.0.1:<db_port>/` and diff the response vs a closed-port control — a
    differential = the sink reaches internal services. No payload bytes are delivered;
    weaponization → Strix. Intrusive; in scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    m = method.upper()
    sc = _scope_check()

    async def _get(value: str):
        u, b = _with_param(url, param, value, m)
        return await ctx.http.fetch(u, method=m, body=b, follow_redirects=False, scope_check=sc)

    poll_errors: list[str] = []

    async def _poll(cb) -> list:
        hits, err = await _collect_oast(ctx, cb.token)
        if err and err not in poll_errors:
            poll_errors.append(err)
        return hits

    # Lane 1 — scheme-deref OAST canaries (one token per scheme for attribution).
    scheme_hits: dict[str, int] = {}
    scheme_note = None
    if not ctx.oast.configured:
        scheme_note = "OAST unconfigured — scheme-deref lane skipped (start oast_selfhost/oast_configure)"
    else:
        canaries = {s: ctx.oast.generate(label=f"ssrf_proto_{s}") for s in sspmod.SCHEMES}
        for s, cb in canaries.items():
            await _get(sspmod.scheme_payload(s, cb.canary_host, cb.http_url))
        await asyncio.sleep(max(0.0, min(wait, 8.0)))
        for s, cb in canaries.items():
            n = len(await _poll(cb))
            if n:
                scheme_hits[s] = n

    # Lane 2 — internal-port reachability differential.
    port_list = sspmod.parse_ports(ports)
    ctrl_url = sspmod.closed_control_url()
    ctrl_r = await _get(ctrl_url)
    ctrl = (ctrl_r.status, len(ctrl_r.body))
    reachable: list[str] = []
    for label, iurl in sspmod.internal_port_targets(port_list):
        r = await _get(iurl)
        # pass the URL-length bias so a longer (multi-digit) DB port doesn't read as
        # reachable purely because the sink echoed the longer URL back.
        if sspmod.assess_reachability(ctrl, (r.status, len(r.body)),
                                      reflect_len_delta=len(iurl) - len(ctrl_url)):
            reachable.append(label)

    non_http_schemes = {s: n for s, n in scheme_hits.items() if s != "http"}
    verdict = confirmmod.evaluate(
        oast_count=sum(non_http_schemes.values()),
        injection_hits=(["ssrf/internal-port-reach"] if reachable else []),
        status_changed=bool(reachable))
    out: dict[str, Any] = {"target": url, "param": param, **verdict,
                           "scheme_callbacks": scheme_hits, "reachable_internal_ports": reachable}
    if poll_errors:
        out["oast_error"] = poll_errors[0]
    if scheme_note:
        out["scheme_note"] = scheme_note
    if non_http_schemes:
        out["detail"] = (f"the sink dereferenced non-HTTP scheme(s) {list(non_http_schemes)} — raw-TCP "
                         "reach to internal services; hand the gopher payload (Redis SET/CONFIG, etc.) to Strix")
    elif reachable:
        out["detail"] = (f"the sink reached internal port(s) {reachable} — SSRF into the internal network; "
                         "pivot with gopher/dict via Strix")
    return out


@mcp.tool()
@active_tool(intrusive=True)
async def fastjson_oast_probe(target: str, method: str = "POST",
                              oast_token: str | None = None, wait: float = 3.0) -> dict:
    """**Fastjson / Jackson autoType** deserialization probe (the #1 CN Java-stack bug).
    POSTs benign `@type` OAST canaries (`java.net.Inet4Address` / `java.net.URL`, plus the
    Jackson array form) to a JSON endpoint — their ONLY effect is a DNS/HTTP lookup to the
    canary. A callback proves the endpoint deserializes attacker-controlled `@type` (the
    vuln class is confirmed) with no JNDI gadget and no code landed. Start `oast_selfhost`
    (or `oast_configure`) first. Weaponization → Strix. Intrusive; in scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    cb = ctx.oast.get(oast_token) if oast_token else None
    if cb is None:
        if not ctx.oast.configured:
            return {"error": "oast_unconfigured",
                    "detail": "start oast_selfhost or oast_configure before a Fastjson OAST probe"}
        cb = ctx.oast.generate(label="fastjson_oast")
    m = method.upper()
    host = cb.canary_host or cb.http_url
    sent: list[str] = []
    for label, body in fastjsonmod.fastjson_payloads(host, cb.http_url):
        await ctx.http.fetch(url, method=m, body=body,
                             headers={"Content-Type": fastjsonmod.JSON_CT},
                             follow_redirects=False, scope_check=_scope_check())
        sent.append(label)
    await asyncio.sleep(max(0.0, min(wait, 8.0)))
    hits, oast_err = await _collect_oast(ctx, cb.token)
    verdict = confirmmod.evaluate(oast_count=len(hits))
    out = {"target": url, "canary": cb.http_url, "token": cb.token, "payloads_sent": sent,
           **verdict, "interactions": hits[:20]}
    if oast_err:
        out["oast_error"] = oast_err
        out["note"] = ("could not verify the callback channel — the OAST poll failed, so this is "
                       "NOT a clean no-hit; re-check with oast_poll")
    elif not hits:
        out["note"] = ("no callback yet — the sink may not deserialize @type, or it calls back later; "
                       "re-check with oast_poll")
    else:
        out["detail"] = ("the endpoint resolved our benign @type canary — Fastjson/Jackson autoType "
                         "deserialization is reachable; hand gadget selection + the JNDI server to Strix")
    return out


@mcp.tool()
@active_tool(intrusive=True)
async def cache_probe(target: str) -> dict:
    """**Web cache poisoning** probe. Sends the request with common **unkeyed**
    headers (`X-Forwarded-Host`, `X-Forwarded-Scheme`, …) carrying a canary and
    checks whether the value is **reflected** while the response looks
    **cacheable** — the combination that lets an unkeyed input poison the cache.
    Detection-only (one canary per header). Intrusive; in scope only.
    """

    import secrets

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    canary = "moonpc" + secrets.token_hex(4)
    b = await ctx.http.fetch(url, follow_redirects=False, scope_check=_scope_check())
    base_body = b.text(200_000)
    reflected: list[dict] = []
    for h in probesmod.CACHE_HEADERS:
        r = await ctx.http.fetch(url, headers={h: f"{canary}.evil.example"},
                                 follow_redirects=False, scope_check=_scope_check())
        if canary in r.text(200_000) and canary not in base_body:
            reflected.append({"header": h, "reflected_canary": canary})
    is_cacheable, reasons = probesmod.cacheable(b.headers_map())
    if reflected and is_cacheable:
        verdict = "likely"
    elif reflected:
        verdict = "inconclusive"
    else:
        verdict = "unconfirmed"
    return {"target": url, "verdict": verdict, "unkeyed_reflection": reflected,
            "cacheable": is_cacheable, "cache_signals": reasons}
