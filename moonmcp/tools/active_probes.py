"""Active web / infrastructure probes.

Extracted from server.py. Scope-gated detectors that don't fit the injection or
web-check families: cache deception, tech-stack + RCE surface, SSRF-to-metadata,
CRLF, business-logic / race / multi-step-workflow abuse, second-order SQLi,
value tampering, in-band secret leak, reset poisoning, path-normalisation
bypass, debug-panel + sourcemap exposure, port scan, datastore exposure, content
discovery, HTTP-method + WAF-efficacy + request-smuggling (desync) probes. The
shared `_http_datastore` reader moves with them. Importing registers them on `mcp`.
"""

from __future__ import annotations

import asyncio
from typing import Any

from .. import confirm as confirmmod
from ..context import to_dict
from ..knowledge import injections as injmod
from ..mcp_core import (
    _collect_oast,
    _connect_pin,
    _require_scope,
    _scope_check,
    _split_host_port,
    active_tool,
    get_context,
    mcp,
)
from ..net import ports as portsmod
from ..recon import content as contentmod
from ..recon import datastores as datastoresmod
from ..recon import sourcemaps as sourcemapsmod
from ..scope import normalize_target
from ..web import authflow as authflowmod
from ..web import cache_deception as cachedecmod
from ..web import crlf as crlfmod
from ..web import debugpanel as debugpanelmod
from ..web import desync as desyncmod
from ..web import inject as injectmod
from ..web import logic as logicmod
from ..web import methods as methodsmod
from ..web import pathnorm as pathnormmod
from ..web import secondorder as somod
from ..web import singlepacket as spmod
from ..web import ssrf_meta as ssrfmetamod
from ..web import stacks as stacksmod
from ..web import value as valuemod
from ..web import waf_bypass as wafbypassmod
from ..web import workflow as workflowmod


@mcp.tool()
@active_tool(intrusive=True)
async def cache_deception_probe(target: str) -> dict:
    """Test an authenticated page for **web cache deception** — the cache storing
    your private response under an attacker-readable key via a path-confusion
    variant (`/x.css`, `;x.css`, encoded traversal). Pass the URL of a page that
    requires login (set the session with `auth_set` first); it fetches the private
    page authed vs anonymously, then re-reads each crafted variant cookieless and
    flags a leak (confirmed when the cookieless variant also carries a cache-HIT
    header). Intrusive: it primes the cache with your own private page.
    """

    ctx = get_context()
    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    result = await cachedecmod.probe_cache_deception(ctx.http, url, scope_check=_scope_check())
    return to_dict(result)


@mcp.tool()
@active_tool(intrusive=True)
async def stack_probe(target: str, include_rce_probes: bool = False) -> dict:
    """Fingerprint an in-scope host for high-payout CN/RU enterprise stacks and run
    deterministic, non-destructive unauth checks: Nacos `User-Agent` auth bypass,
    Apache Shiro `rememberMe`, Alibaba Druid monitor exposure, 1C-Bitrix admin,
    and an unauthenticated ClickHouse HTTP interface (point the target at `:8123`).

    The ThinkPHP invokefunction probe sends a **real RCE primitive**
    (`call_user_func_array("md5", ...)`) — a benign `md5()` echo, but the server
    *executes* it. It is therefore opt-in via `include_rce_probes=True`; without
    that flag the ThinkPHP RCE check is skipped and only the passive fingerprint
    runs. Confirmed hits are proofs, not exploits — weaponization goes to Strix.
    Intrusive: it touches known exploit paths.
    """

    ctx = get_context()
    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    result = await stacksmod.probe_stack(ctx.http, url, scope_check=_scope_check(),
                                         include_rce_probes=include_rce_probes)
    return to_dict(result)


@mcp.tool()
@active_tool(intrusive=True)
async def ssrf_metadata_probe(target: str, param: str, method: str = "GET",
                              confirm_creds: bool = False) -> dict:
    """**Response-based** SSRF → cloud-metadata credential theft (the Capital One
    pattern). Injects each provider's instance-metadata URL (AWS / GCP / Azure /
    Alibaba / Yandex / Oracle / DigitalOcean) into `param` and scans the response
    for that provider's credential signature — proving a full-read SSRF that reaches
    the metadata service. Complements the blind `ssrf_probe`. Intrusive; in scope
    only. Header-gated providers (GCP/Azure/Oracle) only leak if the vulnerable
    server forwards our request header.

    **Two tiers:** `confirm_creds=False` (default) runs only the metadata-root
    fingerprint probes (ami-id, instance-id, hostname) — safe detection without
    extracting live credentials. `confirm_creds=True` additionally probes the
    IAM/token endpoints that return real, usable cloud credentials. Run the
    fingerprint first; confirm creds only when you need the proof.
    """

    ctx = get_context()
    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    findings = await ssrfmetamod.probe_ssrf_metadata(
        ctx.http, url, param, method=method, scope_check=_scope_check(),
        confirm_creds=confirm_creds)
    # `findings` always carries the informational "(note)" dry_run entry in default
    # mode, so it is never empty — only an actual leak (verdict="confirmed") means
    # vulnerable. Keying "vulnerable" off bool(findings) reported EVERY probe as a
    # confirmed metadata SSRF, a critical false positive.
    leaks = [f for f in findings if f.get("verdict") == "confirmed"]
    return {
        "target": url, "param": param,
        "vulnerable": bool(leaks), "findings": findings,
        "note": ("full-read SSRF to cloud metadata confirmed — rotate the exposed credentials"
                 if leaks else "no metadata credential signatures reflected in the response"),
    }


@mcp.tool()
@active_tool()
async def crlf_probe(target: str, param: str, method: str = "GET") -> dict:
    """Test a parameter for **CRLF injection / HTTP response splitting**: injects a
    benign marker header (`X-Moonmcp-Inj: 1`) through `param` via CR/LF variants
    (bare-LF, fragment, unicode/overlong, double-encoded, Set-Cookie split) and
    flags a vuln when the marker surfaces as a *real* response header/cookie (not
    body reflection). Non-destructive; in scope only. Common on redirect/`lang`/
    routing params.
    """

    ctx = get_context()
    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    findings = await crlfmod.probe_crlf(ctx.http, url, param, method=method,
                                        scope_check=_scope_check())
    return {"target": url, "param": param, "vulnerable": bool(findings), "findings": findings,
            "note": ("CRLF header injection confirmed" if findings
                     else "no injected header surfaced — parameter appears CR/LF-safe")}


@mcp.tool()
@active_tool(intrusive=True)
async def logic_probe(target: str, param: str | None = None, method: str = "GET",
                      confirm_state_change: bool = False) -> dict:
    """Business-logic ABUSE sweep on an endpoint: **parameter tampering**
    (negative/zero/overflow on money/quantity params — pass `param`, or the
    money/quantity params in the URL query are auto-targeted) + a **mass-assignment**
    check (POSTs privileged fields like role/is_admin/balance and flags reflected
    ones). Returns LEADS (verdict=review) to confirm against the flow — drive it
    with the `business_logic_hunt` prompt. Intrusive; in scope only.
    """

    ctx = get_context()
    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    sc = _scope_check()
    params = [param] if param else logicmod.numeric_params(logicmod.query_keys(url))
    findings: list[dict] = []
    for p in params:
        findings.extend(await logicmod.probe_parameter_tampering(
            ctx.http, url, p, method=method, scope_check=sc))
    findings.extend(await logicmod.probe_mass_assignment(
        ctx.http, url, scope_check=sc, dry_run=not confirm_state_change))
    return {
        "target": url, "tested_params": params, "findings": findings,
        "note": (f"{len(findings)} logic lead(s) — verify the real-world effect against the flow"
                 if findings else "no automatable logic leads; drive the flow per business_logic_hunt"),
    }


@mcp.tool()
@active_tool(intrusive=True)
async def race_probe(target: str, method: str = "POST", n: int = 20,
                     single_packet: bool = True, headers: dict[str, str] | None = None,
                     body: str | None = None,
                     confirm_state_change: bool = False) -> dict:
    """**Race-condition / limit-bypass** probe on a state-changing endpoint (coupon
    apply, vote, withdrawal, invite, signup). By default uses the **single-packet
    attack** (HTTP/1.1 last-byte synchronization) so all N requests complete at the
    server within ~1 ms — neutralizing network jitter, which the naive parallel-fire
    approach can't. Reports how many returned 2xx; >1 on a should-be-once action is a
    race. Engagement `auth_set` cookies/headers are injected automatically; pass extra
    `headers`/`body` as needed. Set `single_packet=False` for the plain asyncio-gather
    fallback. Confirm the side effect actually happened >1×. Intrusive; in scope only.
    """

    from urllib.parse import urlsplit

    ctx = get_context()
    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    # State-changing gate: the race probe fires N real requests at a should-be-
    # once action. dry_run (default) refuses and describes what would happen.
    if not confirm_state_change:
        return {
            "target": url, "method": method.upper(), "n": n,
            "sent": 0, "success_2xx": 0, "status_histogram": {},
            "verdict": "dry_run",
            "detail": f"would fire {n} parallel {method} requests at {url}; re-run with "
                      "confirm_state_change=True to actually test (WARNING: on a vulnerable "
                      "should-be-once action this performs it up to N times — real side "
                      "effect with no rollback).",
        }
    if single_packet:
        parts = urlsplit(url)
        tls = parts.scheme != "http"
        host = parts.hostname or ""
        port = parts.port or (443 if tls else 80)
        path = parts.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"
        hdrs = {**ctx.auth.merged_headers(), **(headers or {})}
        req = spmod.build_request(host, path, method=method, headers=hdrs, body=(body or ""),
                                  user_agent=ctx.settings.user_agent)
        result = await spmod.single_packet_race(host, port, tls, req, n,
                                                timeout=max(10.0, ctx.settings.timeout),
                                                connect_pin=_connect_pin())
        return {"target": url, "method": method.upper(), **result}
    result = await logicmod.probe_race(ctx.http, url, method=method, n=n,
                                       scope_check=_scope_check(), dry_run=False)
    return {"target": url, "method": method.upper(), "technique": "asyncio-gather", **result}


@mcp.tool()
@active_tool(self_scoped=True, intrusive=True)
async def workflow_probe(steps: list[dict]) -> dict:
    """**Workflow / step-skipping** abuse on a multi-step flow. Pass the flow as an
    ORDERED list of steps — each a dict `{"url", "method"?, "body"?, "success"?}`
    (or a bare URL string) — e.g. cart→address→payment→confirm, or register→verify→
    access. It fetches every step *after the first* cold (without completing the
    prior steps): a flow that enforces its order redirects back / errors, a broken one
    serves the step (order confirmed without payment, account activated without email
    verification). `success` is an optional marker string that positively identifies a
    step's completed content. Returns `review` leads (confirm the business effect).
    Intrusive; in scope only — the steps' hosts are scope-checked.
    """

    ctx = get_context()
    # self_scoped: enforce the intrusive gate + scope + SSRF-resolve guard on EACH
    # step's host (the decorator can't scope-check the steps list itself).
    for s in steps:
        u = s if isinstance(s, str) else (s.get("url") if isinstance(s, dict) else None)
        if u:
            await _require_scope(str(u), intrusive=True, tool="workflow_probe")
    result = await workflowmod.probe_workflow_skip(ctx.http, steps, scope_check=_scope_check())
    n = len(result.get("findings", []))
    result["note"] = (f"{n} step-skipping lead(s) — confirm the business effect of reaching the step "
                      "without its prerequisites" if n
                      else "no step served cold — the flow appears to enforce its sequence")
    return result


@mcp.tool()
@active_tool(self_scoped=True, intrusive=True)
async def second_order_sqli_probe(write: dict, read: list[str] | str, param: str = "comment",
                                  oob: bool = False, wait: float = 3.0,
                                  oast_token: str | None = None) -> dict:
    """**Second-order (stored) SQL injection** — the sink is a DIFFERENT endpoint from
    the injection (a stateless scanner sees nothing). Seed a uniquely-tagged value at
    the `write` endpoint (`{"url","method"?,"body"?}` — inject into `param`, or use a
    `body` template with a `{payload}` placeholder), then drive the `read` endpoint(s)
    and look for a SQL **error** signature that only appears after the seed, or a
    reflected-tag **boolean** differential (equal-length twins, so a verbatim echo gives
    nothing). `oob=True` seeds a tagged OAST payload and polls for a callback. Returns
    `review` leads; extraction → sqlmap `--second-url` / Strix. Intrusive; in scope only.
    """

    ctx = get_context()
    if not isinstance(write, dict) or not write.get("url"):
        return {"error": "invalid_input", "detail": "write must be {'url':..., 'method'?, 'body'?}"}
    w_raw = str(write["url"]).strip()
    w_url = w_raw if "://" in w_raw else f"https://{w_raw}"
    w_method = str(write.get("method") or "POST").upper()
    w_body_tpl = write.get("body")
    w_ctype = write.get("content_type")
    reads = somod.normalize_reads(read)
    for r in reads:
        r["url"] = r["url"] if "://" in r["url"] else f"https://{r['url']}"
    if not reads:
        return {"error": "invalid_input", "detail": "read must be a URL or list of URLs"}

    await _require_scope(w_url, intrusive=True, tool="second_order_sqli_probe")
    for r in reads:
        await _require_scope(r["url"], intrusive=True, tool="second_order_sqli_probe")
    sc = _scope_check()

    async def _write(value: str):
        if isinstance(w_body_tpl, str) and "{payload}" in w_body_tpl:
            hdr = {"Content-Type": w_ctype} if w_ctype else None
            await ctx.http.fetch(w_url, method=w_method, body=w_body_tpl.replace("{payload}", value).encode(),
                                 headers=hdr, follow_redirects=False, scope_check=sc)
        else:
            u, b = injectmod.with_param(w_url, param, value, w_method)
            await ctx.http.fetch(u, method=w_method, body=b, follow_redirects=False, scope_check=sc)

    async def _read_all() -> list:
        obs = []
        for r in reads:
            resp = await ctx.http.fetch(r["url"], method=r["method"], follow_redirects=False, scope_check=sc)
            obs.append(somod.ReadObs(resp.status, resp.text(50_000)))
        return obs

    async def _cycle(value: str) -> list:
        await _write(value)
        return await _read_all()

    tag = somod.make_tag()
    seeds = somod.seed_payloads(tag)
    control = await _cycle(seeds["control"])
    error = await _cycle(seeds["error"])
    # The boolean twins are sent TWICE each so assess_read can measure per-request jitter
    # (a dynamic sink's timestamp/nonce) and require the true/false flip to EXCEED it —
    # a byte-exact length compare false-positived on any dynamic read sink.
    true_r = (await _cycle(seeds["true"]), await _cycle(seeds["true"]))
    false_r = (await _cycle(seeds["false"]), await _cycle(seeds["false"]))

    def _match(t: str) -> list:
        return injmod.match_signatures(t, class_id="sqli")

    findings: list[dict] = []
    for i, r in enumerate(reads):
        hit = somod.assess_read(tag, control[i], error[i],
                                (true_r[0][i], true_r[1][i]), (false_r[0][i], false_r[1][i]), _match)
        if hit:
            findings.append({"read": r["url"], **hit})

    oast_count = 0
    oob_out: dict | None = None
    if oob:
        cb = ctx.oast.get(oast_token) if oast_token else None
        if cb is None and ctx.oast.configured:
            cb = ctx.oast.generate(label="second_order_sqli")
        if cb is None:
            oob_out = {"error": "oast_unconfigured"}
        else:
            await _cycle(somod.oob_seed(tag, cb.http_url, cb.canary_host))
            await asyncio.sleep(max(0.0, min(wait, 8.0)))
            oh, oast_err = await _collect_oast(ctx, cb.token)
            oast_count = len(oh)
            oob_out = {"canary": cb.http_url, "token": cb.token,
                       "interaction_count": oast_count, "interactions": oh[:20]}
            if oast_err:
                oob_out["oast_error"] = oast_err

    has_error = any(f["error_signatures"] for f in findings)
    verdict = confirmmod.evaluate(
        injection_hits=["sqli/second-order" for _ in findings] + (["sqli/second-order-oob"] if oast_count else []),
        reflected=has_error, status_changed=any(f["boolean_differential"] for f in findings),
        oast_count=oast_count)
    out: dict[str, Any] = {"write": w_url, "reads": [r["url"] for r in reads], "tag": tag,
                           **verdict, "findings": findings}
    if oob_out is not None:
        out["oob"] = oob_out
    return out


@mcp.tool()
@active_tool(intrusive=True)
async def value_probe(target: str, param: str | None = None, coupon_code: str | None = None,
                      method: str = "GET",
                      confirm_state_change: bool = False) -> dict:
    """**Value / financial-logic** manipulation on money fields. Auto-targets value
    params in the URL (amount/price/balance/discount/coupon/points/currency…) — or
    pass `param` — and sends the manipulations a correct server must reject: **negative**
    amounts, **zero**, integer **overflow**, sub-cent **precision**, **>100 % discount**,
    and **currency swap/downgrade**. If `coupon_code` is given, also tests single-use
    **coupon/gift-card reuse** (apply the same code repeatedly). Accepted-like-baseline =
    a value-logic lead (verdict `review`; confirm the charged/credited amount). Intrusive;
    in scope only.

    **Coupon-reuse is state-changing** (it redeems the code N times — real financial
    loss, no rollback). `confirm_state_change=False` (default) runs the value/currency
    detection (diff against a baseline) but refuses the coupon-reuse apply, returning a
    `dry_run` verdict. Set `confirm_state_change=True` to actually test coupon reuse.
    """

    ctx = get_context()
    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    sc = _scope_check()
    keys = logicmod.query_keys(url)
    money = [param] if param else valuemod.money_fields(keys)
    findings: list[dict] = []
    for f in money:
        findings.extend(await valuemod.probe_value_tampering(ctx.http, url, f, method=method, scope_check=sc))
    for f in valuemod.currency_fields(keys):
        findings.extend(await valuemod.probe_currency_swap(ctx.http, url, f, method=method, scope_check=sc))
    out: dict = {"target": url, "tested_fields": money, "findings": findings}
    if coupon_code:
        cfields = valuemod.coupon_fields(keys)
        field = cfields[0] if cfields else (param or "coupon")
        out["coupon_reuse"] = await valuemod.probe_coupon_reuse(
            ctx.http, url, field, coupon_code,
            method=(method if method != "GET" else "POST"), scope_check=sc,
            dry_run=not confirm_state_change)
    n = len(findings) + (1 if out.get("coupon_reuse", {}).get("verdict") == "review" else 0)
    out["note"] = (f"{n} value-logic lead(s) — confirm the real charged/credited amount"
                   if n else "no value manipulation accepted; drive the money flow per business_logic_hunt")
    return out


@mcp.tool()
@active_tool()
async def response_leak_probe(target: str, method: str = "GET", data: str | None = None,
                              content_type: str = "application/json") -> dict:
    """Drive an OTP / password-reset / email-verification endpoint and check whether
    the **out-of-band secret leaks in-band**: an OTP, 2FA code, reset token or
    verification link returned in the response body instead of by email/SMS (whoever
    triggers the flow reads it → instant account takeover — a top fintech-API bug).
    Pass `data` (e.g. `{"email":"me@acme.test"}`) to trigger the flow. Secrets are
    **redacted** in the output. In scope only.
    """

    ctx = get_context()
    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    body = data.encode() if data else None
    headers = {"Content-Type": content_type} if data else None
    findings = await authflowmod.probe_response_leak(
        ctx.http, url, method=method, body=body, headers=headers, scope_check=_scope_check())
    return {
        "target": url, "vulnerable": bool(findings), "findings": findings,
        "note": (f"{len(findings)} in-band secret leak(s) — the OTP/reset secret should be "
                 "delivered out-of-band; confirm it's the real one" if findings
                 else "no in-band OTP/reset secret found in the response body"),
    }


@mcp.tool()
@active_tool()
async def reset_poison_probe(target: str, canary: str | None = None, method: str = "POST",
                             data: str | None = None,
                             content_type: str = "application/json") -> dict:
    """**Password-reset poisoning**: send the reset request with the host-routing
    headers (`Host`, `X-Forwarded-Host`, `Forwarded`, …) set to an attacker host and
    flag any reflected back in the response body / `Location` — a signal the reset
    link is built from a user-controlled host, so the victim's reset token is
    delivered to the attacker (full ATO). Pass `data` (e.g. `{"email":"victim@acme.test"}`);
    omit `canary` to auto-use an OAST host (start `oast_selfhost`/`oast_configure`)
    which also catches a server-side host fetch. The connection stays on the in-scope
    host — only the header is poisoned. In scope only.
    """

    ctx = get_context()
    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    cb = None
    host = (canary or "").strip()
    if not host:
        if ctx.oast.configured:
            cb = ctx.oast.generate(label="reset_poison")
            host = cb.canary_host or ""
        if not host:
            host = "moonmcp-poison.example"
    body = data.encode() if data else None
    headers = {"Content-Type": content_type} if data else None
    findings = await authflowmod.probe_reset_poison(
        ctx.http, url, host, method=method, body=body, headers=headers,
        scope_check=_scope_check())
    out: dict = {
        "target": url, "canary": host, "reflected": bool(findings), "findings": findings,
        "note": (f"host reflected via {len(findings)} header(s) — verify the reset email's link "
                 "points at the canary" if findings
                 else "no poisoning header was reflected — reset host looks server-fixed"),
    }
    if cb is not None:
        out["oast_token"] = cb.token
        out["oast_note"] = "poll with oast_poll — a callback means the server fetched the poisoned host"
    return out


@mcp.tool()
@active_tool()
async def path_bypass_probe(target: str) -> dict:
    """**403/401 path-normalization bypass**: point at a route that returns 401/403
    and this replays normalization twins (`/admin/..;/`, `/%2e/admin`, matrix `;x`,
    trailing `%2f`/`%2e`, double slash, `%`-encoded char) — a front proxy and the
    backend disagreeing on normalization can skip the ACL while still resolving the
    resource (CVE-2024-0204-class). Flags any twin that flips the status to 2xx
    (verdict `review` — confirm the body is the real protected content). GET-only,
    non-destructive. In scope only.
    """

    ctx = get_context()
    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    result = await pathnormmod.probe_path_bypass(ctx.http, url, scope_check=_scope_check())
    n = len(result.get("findings", []))
    result["target"] = url
    result["note"] = result.get("note") or (
        f"{n} normalization twin(s) reached the protected route — verify the content"
        if n else "no normalization twin bypassed the ACL")
    return result


@mcp.tool()
@active_tool()
async def debug_exposure(target: str) -> dict:
    """Detect **exposed framework debug pages / consoles** left on in production:
    Laravel Ignition (`/_ignition`), Symfony profiler (`/_profiler`, `/app_dev.php`),
    Laravel Telescope/Horizon, Spring Boot Actuator (`/actuator/env`), Django debug
    toolbar, the Werkzeug/Flask interactive debugger (`/console`), Adminer,
    phpMyAdmin, Rails dev info. Confirms each by a distinctive content signature (no
    soft-404 FPs). Several leak the framework signing secret → feed `analyze_config`
    to classify the forge-to-RCE chain; a couple are direct RCE. GET-only. In scope only.
    """

    ctx = get_context()
    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    findings = await debugpanelmod.probe_debug_panels(ctx.http, url, scope_check=_scope_check())
    return {
        "target": url, "exposed": bool(findings), "findings": findings,
        "note": (f"{len(findings)} debug panel(s) exposed — pull any leaked APP_KEY/APP_SECRET into "
                 "analyze_config for the forge chain" if findings
                 else "no known framework debug panel exposed"),
    }


@mcp.tool()
@active_tool()
async def recover_sourcemaps(target: str) -> dict:
    """**Recover original source from a shipped `.js.map`.** Give a `.js` or `.js.map`
    URL (or a page): fetches the source map, reconstructs every module's original
    pre-minification source from `sourcesContent[]`, separates app source from vendor
    (`node_modules`/webpack runtime), flags config/secret-looking files, and runs the
    recovered app source through the secret scanner. A shipped source map discloses the
    app's real source tree + hard-coded secrets. `analyze_js` detects the map; this
    recovers it. In scope only.
    """

    ctx = get_context()
    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    return await sourcemapsmod.recover(ctx.http, url, scope_check=_scope_check())


# Network-fingerprinting tools live in moonmcp/tools/netfp.py (imported below).


# ---------------------------------------------------------------------------
# active (intrusive) — scope-gated + allow_intrusive
# ---------------------------------------------------------------------------
@mcp.tool()
@active_tool(intrusive=True)
async def port_scan(
    target: str,
    ports: str = "top",
    grab_banner: bool = False,
    timeout: float = 2.0,
) -> dict:
    """TCP connect-scan an in-scope host. ``ports`` is 'top' (a curated common
    set) or a spec like '80,443,8000-8100'. Optionally grabs service banners.
    Unprivileged and non-malformed (full handshake). Intrusive: requires
    MOONMCP_ALLOW_INTRUSIVE and the host to be in scope.
    """

    host = normalize_target(target)
    port_list = portsmod.parse_ports(ports)
    if len(port_list) > 5000:
        return {"error": "too_many_ports", "detail": f"{len(port_list)} ports requested; cap is 5000"}
    ctx = get_context()
    result = await portsmod.scan_ports(
        host,
        port_list,
        timeout=timeout,
        # Respect the operator's MOONMCP_MAX_CONCURRENCY safety knob (was silently
        # multiplied by 10, so a configured cap of 20 opened up to 200 sockets); the
        # shared rate limiter still paces total throughput.
        concurrency=max(1, ctx.settings.max_concurrency),
        grab_banner=grab_banner,
        limiter=ctx.governor.limiter,
        connect_pin=_connect_pin(),
    )
    return to_dict(result)


_DB_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


async def _http_datastore(ctx, host: str, port: int, kind: str, timeout: float) -> dict | None:
    """Fetch the datastore's read-only HTTP path and run its pure interpreter."""

    url = f"http://{host}:{port}{datastoresmod.HTTP_PATHS[kind]}"
    try:
        r = await ctx.http.fetch(url, method="GET", follow_redirects=False,
                                 timeout=timeout, scope_check=_scope_check())
    except Exception:
        return None
    return datastoresmod.HTTP_INTERPRETERS[kind](r.status, r.headers_map(), r.text(20_000))


@mcp.tool()
@active_tool(intrusive=True)
async def db_exposure(target: str, ports: str = "db", timeout: float = 4.0) -> dict:
    """**Unauthenticated datastore exposure sweep** — speaks the minimal read-only
    handshake for each data store and reports which answer with **no auth**. Raw-TCP:
    Redis (`PING`/`INFO`), Memcached (`version`), MongoDB (`listDatabases` wire query).
    HTTP: Elasticsearch/OpenSearch, CouchDB, InfluxDB (`/ping`), Hadoop YARN
    (`/ws/v1/cluster/info`), TiDB status (`/status`). Non-destructive — no writes, no
    dumps, no app submit; exploitation of an exposed store is handed to Strix. `ports`
    is 'db' (the curated DB set), or a spec like '6379,27017' (a host:port target
    probes just that port). Intrusive: requires MOONMCP_ALLOW_INTRUSIVE and scope.
    """

    host, p = _split_host_port(target, 0)
    explicit_port = p if p else None
    ctx = get_context()
    port_list = datastoresmod.ports_to_check(explicit_port, ports)
    result = datastoresmod.DatastoreResult(host=host, checked=port_list)
    sem = asyncio.Semaphore(min(20, max(1, ctx.settings.max_concurrency * 4)))
    limiter = ctx.governor.limiter
    to = max(0.5, min(timeout, 15.0))

    async def _check(port: int) -> dict | None:
        entry = datastoresmod.DB_PORTS.get(port)
        if entry is None:
            return None
        service, kind = entry
        async with sem:
            if limiter is not None:
                await limiter.acquire()
            if kind in datastoresmod.RAW_PROBES:
                hit = await datastoresmod.RAW_PROBES[kind](host, port, to, connect_pin=_connect_pin())
            else:
                hit = await _http_datastore(ctx, host, port, kind, to)
        return {"port": port, "service": service, **hit} if hit else None

    checks = await asyncio.gather(*[_check(p) for p in port_list], return_exceptions=True)
    result.findings = [c for c in checks if isinstance(c, dict)]
    result.findings.sort(key=lambda f: (_DB_SEV_ORDER.get(f["severity"], 5), f["port"]))
    return to_dict(result)


@mcp.tool()
@active_tool(intrusive=True)
async def content_discovery(
    target: str,
    wordlist: list[str] | None = None,
    concurrency: int = 15,
) -> dict:
    """Probe an in-scope host for common sensitive paths (admin panels, API docs,
    .git/.env, backups, config files, ...) using a compact built-in wordlist or a
    caller-supplied one. Reports each path's status, size and content type.
    **Auto-calibrates a soft-404 baseline first** (fetches random paths) and suppresses
    catch-all/SPA echoes, so a hit is a real resource — see `suppressed`/`calibrated` in
    the result. Intrusive: requires MOONMCP_ALLOW_INTRUSIVE and the host to be in scope.
    """

    host, port = _split_host_port(target, 443)
    raw = target.strip()
    scheme = "http" if raw.startswith("http://") else "https"
    ctx = get_context()
    result = await contentmod.probe_paths(
        ctx.http, host, scheme=scheme, port=port, wordlist=wordlist,
        concurrency=min(concurrency, ctx.settings.max_concurrency),
        scope_check=_scope_check(),
    )
    return to_dict(result)


@mcp.tool()
@active_tool(intrusive=True)
async def http_methods(target: str) -> dict:
    """Enumerate an in-scope URL's allowed HTTP methods (from OPTIONS) and probe
    sensitive ones (TRACE, PUT, DELETE, PATCH) to flag XST or write-enabled
    endpoints. Intrusive (it sends potentially state-changing methods): requires
    MOONMCP_ALLOW_INTRUSIVE and the host in scope.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    result = await methodsmod.check_methods(ctx.http, url, scope_check=_scope_check())
    return to_dict(result)


@mcp.tool()
@active_tool(intrusive=True)
async def waf_efficacy(target: str) -> dict:
    """Test how effective an in-scope target's WAF is: sends **benign canary**
    payloads across the common attack categories (XSS, SQLi, LFI, RCE, SSTI,
    traversal, XXE) to see which the WAF blocks, then applies simple transforms
    (case-swap, comment-break, encoding, null-byte) to check whether trivial
    obfuscation bypasses it. Reports protected vs unprotected categories and any
    bypasses. Payloads do nothing harmful. Intrusive: requires
    MOONMCP_ALLOW_INTRUSIVE and the host in scope.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    result = await wafbypassmod.test_waf_efficacy(ctx.http, url, scope_check=_scope_check())
    return to_dict(result)


@mcp.tool()
@active_tool(intrusive=True)
async def desync_probe(target: str) -> dict:
    """Detection-only HTTP request-smuggling **indicator** probe for an in-scope
    host. Sends single, complete, well-formed requests (no partial/dangling
    requests — nothing is left to poison a connection) to observe how the server
    handles ambiguous framing (both Content-Length + Transfer-Encoding, and
    obfuscated Transfer-Encoding). Reports indicators only — NOT a confirmed
    finding; verify manually with a dedicated tool. Intrusive: requires
    MOONMCP_ALLOW_INTRUSIVE and the host in scope.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    result = await desyncmod.probe_desync(url, timeout=max(10.0, get_context().settings.timeout),
                                          user_agent=get_context().settings.user_agent, connect_pin=_connect_pin())
    return to_dict(result)


@mcp.tool()
@active_tool(intrusive=True)
async def desync_modern_probe(target: str) -> dict:
    """Detection-only probe for **modern (2025 "HTTP/1.1 Must Die") desync**: 0.CL,
    TE.0, `Expect: 100-continue` mishandling and chunk-extension parsing. Uses the
    **timeout-differential** technique — each probe runs on its own fresh
    `Connection: close` socket that is closed immediately, so no second request ever
    shares the connection and **nothing is smuggled to a victim**; it infers which
    length header the server honours from whether it waits for the body it was
    promised. Reports timing indicators only — NOT a confirmed finding (verify with a
    dedicated tool). Intrusive: requires MOONMCP_ALLOW_INTRUSIVE and the host in scope.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    result = await desyncmod.probe_modern_desync(url, timeout=max(6.0, get_context().settings.timeout / 2),
                                                 user_agent=get_context().settings.user_agent, connect_pin=_connect_pin())
    return to_dict(result)
