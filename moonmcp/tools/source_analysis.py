"""Client-source & secret analysis.

Extracted from server.py. Crawl an app, harvest and analyse its JavaScript
(endpoints, vulnerable libraries), parse OpenAPI specs, scan the page + JS for
leaked secrets, and check Firebase RTDB / Supabase exposure. The shared
`_fetch_app_source` helper (page + linked JS) moves with them. Importing this
module registers the tools on the shared `mcp` instance.
"""

from __future__ import annotations

from typing import Any

from ..context import to_dict
from ..mcp_core import (
    _require_scope,
    _scope_check,
    active_tool,
    get_context,
    mcp,
    safe_tool,
)
from ..recon import crawl as crawlmod
from ..recon import firebase as firebasemod
from ..recon import jsendpoints as jsmod
from ..recon import jslibs as jslibsmod
from ..recon import openapi as openapimod
from ..recon import secrets as secretsmod
from ..recon import supabase as supabasemod
from ..scope import ScopeError


@mcp.tool()
@active_tool()
async def crawl(target: str, max_pages: int = 10) -> dict:
    """Lightly crawl an in-scope site (depth 1, bounded) and extract its attack
    surface: internal links, forms + their input names, JavaScript/asset URLs,
    query parameters, external hosts it reaches, and any emails. HTML parsing
    only — no browser. In scope only; redirects that leave scope are not followed.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    result = await crawlmod.crawl(
        ctx.http, url, scope_check=_scope_check(), max_pages=max(1, min(max_pages, 30))
    )
    return to_dict(result)


@mcp.tool()
@active_tool()
async def analyze_js(target: str, max_scripts: int = 15) -> dict:
    """Deep-extract the hidden API surface from a page **and its JavaScript** —
    absolute and relative endpoints/routes that a UI crawl never sees, plus any
    **source maps** (`.map`) that reconstruct the original source. Fetches the
    page, then its same-origin scripts (bounded), and returns a deduped endpoint
    list ready to feed the batch prober / parameter fuzzer. In scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    return await jsmod.analyze(ctx.http, url, max_scripts=max(1, min(max_scripts, 40)),
                               scope_check=_scope_check())


@mcp.tool()
@safe_tool
async def js_library_scan(sources: list[str]) -> dict:
    """**Known-vulnerable JS library detector** (Retire.js-lite) — matches script
    URLs/filenames (and, best-effort, an in-body version banner) already surfaced
    by `analyze_js`/`crawl` against a small bundled table of historically-
    vulnerable library versions: jQuery <3.5.0 (DOM XSS via `.html()`), AngularJS
    <1.8.0 (CSP/expression-sandbox bypass → XSS), Lodash <4.17.21 (prototype
    pollution), Moment.js <2.29.2 (ReDoS), Handlebars <4.5.3 (prototype-pollution
    RCE gadget), Bootstrap <4.1.2 (tooltip/popover XSS). Pure regex + version
    comparison — no content-hash database (a deliberate zero-dependency trade
    against Retire.js's fuller but harder-to-maintain coverage). Pass the `.url`
    values from `analyze_js`'s `scripts_analysed` (or any script src/JS snippet you
    have) as `sources`. No traffic, no scope needed — scans data you already fetched.
    """

    hits = jslibsmod.scan_all(sources)
    return {"scanned": len(sources), "count": len(hits), "findings": hits}


@mcp.tool()
@active_tool(self_scoped=True)
async def parse_openapi(target: str | None = None, content: str | None = None) -> dict:
    """Parse an OpenAPI/Swagger spec into an endpoint / parameter / method
    inventory — an exposed `openapi.json` / `swagger.json` is a map of the whole
    API attack surface. Pass a `target` URL to fetch the spec (in scope), or paste
    the spec as `content`. Returns every operation (method, path, params, whether
    auth is required, request-body types), the servers, security schemes, and
    flags (operations with NO security, deprecated ops). Feed the paths to
    `probe_batch` and the params to `discover_parameters`.
    """

    if content:
        return openapimod.parse_spec(content)
    if target:
        raw = target.strip()
        url = raw if "://" in raw else f"https://{raw}"
        await _require_scope(url, tool="parse_openapi")
        return await openapimod.fetch_and_parse(get_context().http, url, scope_check=_scope_check())
    return {"error": "invalid_input", "detail": "pass a 'target' URL or inline 'content'"}


@mcp.tool()
@active_tool()
async def extract_secrets(target: str, scan_js: bool = True, max_js: int = 15) -> dict:
    """Fetch an in-scope page (and, by default, its linked JavaScript) and scan
    for exposed secrets: cloud keys (AWS/GCP), API tokens (GitHub, Slack, Stripe,
    Twilio, SendGrid, ...), private keys, JWTs and risky credential assignments.
    Uses high-precision, prefix-anchored patterns; findings are redacted. In scope only.
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    scan = await secretsmod.scan_secrets(
        ctx.http, url, scope_check=_scope_check(), include_js=scan_js,
        max_js=max(1, min(max_js, 40)),
    )
    data = to_dict(scan)
    data["count"] = scan.count
    return data


async def _fetch_app_source(ctx, url: str, sc, max_js: int = 10) -> tuple[str, list[str]]:
    """Fetch a page + its linked JS; return ``(combined_text, sources)`` for scanning
    an app's embedded backend config (Firebase/Supabase)."""

    from urllib.parse import urljoin
    sources: list[str] = []
    parts: list[str] = []
    page = await ctx.http.fetch(url, follow_redirects=True, timeout=12.0, scope_check=sc)
    if page.status is None:
        return "", sources
    html = page.text(500_000)
    final = page.final_url or url
    sources.append(final)
    parts.append(html)
    try:
        _, js, _, _ = crawlmod._extract(final, html)
    except Exception:
        js = set()
    for jm in crawlmod._JS_URL_RE.finditer(html):
        js.add(urljoin(final, jm.group(1)))
    js_files = [u for u in js if u.lower().split("?")[0].endswith(".js")][:max(1, min(max_js, 30))]
    for jurl in js_files:
        if not sc(jurl):
            continue
        jr = await ctx.http.fetch(jurl, follow_redirects=True, timeout=12.0, scope_check=sc)
        if jr.status is None or not jr.body:
            continue
        sources.append(jurl)
        parts.append(jr.text(800_000))
    return "\n".join(parts), sources


@mcp.tool()
@active_tool(self_scoped=True)
async def firebase_exposure(target: str, database_url: str | None = None, max_js: int = 10) -> dict:
    """**Firebase RTDB open-rules** exposure — safe read-only. Harvests
    `databaseURL`/`projectId` from the page + JS `firebaseConfig` (or pass
    `database_url`), then one unauthenticated `GET <databaseURL>/.json?shallow=true`
    (`shallow=true` = top-level keys only, no bulk pull). A 200 with JSON (not
    "Permission denied") = open Security Rules → the whole dataset is readable. A
    discovered `projectId` is reported as a Firestore follow-up lead. Bulk dump → Strix.
    In scope only (the RTDB backend host is scope-checked too).
    """

    raw = target.strip()
    url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    await _require_scope(url, tool="firebase_exposure")
    sc = _scope_check()
    text, sources = await _fetch_app_source(ctx, url, sc, max_js)
    cfg = firebasemod.parse_firebase_config(text)
    if database_url:
        cfg["databaseURL"] = database_url.rstrip("/")
    out: dict[str, Any] = {"target": url, "config": cfg, "sources_scanned": len(sources)}
    db = cfg.get("databaseURL")
    if not db:
        out["verdict"] = "no_firebase_config"
        out["note"] = "no firebaseConfig / databaseURL found in the page or its JS"
        return out
    probe = firebasemod.rtdb_probe_url(db)
    try:
        await _require_scope(probe, tool="firebase_exposure")
    except ScopeError as exc:
        out["verdict"] = "backend_out_of_scope"
        out["note"] = f"discovered RTDB {db} but it is out of scope ({exc}) — add it to scope to test"
        return out
    r = await ctx.http.fetch(probe, follow_redirects=True, timeout=12.0, scope_check=sc)
    out["rtdb_url"] = db
    out["rtdb_status"] = r.status
    finding = firebasemod.assess_rtdb(r.status, r.text(50_000))
    out.update(finding or {"verdict": "inconclusive"})
    if cfg.get("projectId"):
        out["firestore_lead"] = (
            f"projectId '{cfg['projectId']}' — also check Firestore: GET https://firestore."
            f"googleapis.com/v1/projects/{cfg['projectId']}/databases/(default)/documents/<collection>")
    return out


@mcp.tool()
@active_tool(self_scoped=True)
async def supabase_exposure(target: str, project_url: str | None = None, anon_key: str | None = None,
                            max_tables: int = 15, max_js: int = 10) -> dict:
    """**Supabase RLS-off** exposure — safe read-only. Harvests the project URL
    (`https://<ref>.supabase.co`) + the public `anon` key from the app JS (or pass
    `project_url`/`anon_key`), fetches the PostgREST schema at `/rest/v1/?apikey=<anon>`
    to enumerate tables, then `GET /rest/v1/<table>?select=*&limit=1` — a 200 returning a
    row = Row-Level Security OFF (the public key can SELECT the table). Uses the app's own
    public key against its own API; `limit=1`, rows are NOT returned. Bulk dump → Strix.
    In scope only (the Supabase backend host is scope-checked too).
    """

    raw = target.strip()
    app_url = raw if "://" in raw else f"https://{raw}"
    ctx = get_context()
    await _require_scope(app_url, tool="supabase_exposure")
    sc = _scope_check()
    text, sources = await _fetch_app_source(ctx, app_url, sc, max_js)
    cfg = supabasemod.parse_supabase_config(text)
    if project_url:
        cfg["url"] = project_url.rstrip("/")
    if anon_key:
        cfg["anon_key"], cfg["key_type"] = anon_key, "provided"
    out: dict[str, Any] = {"target": app_url, "sources_scanned": len(sources),
                           "project_url": cfg.get("url"), "key_type": cfg.get("key_type")}
    surl, key = cfg.get("url"), cfg.get("anon_key")
    if not surl or not key:
        out["verdict"] = "no_supabase_config"
        out["note"] = "no Supabase URL + anon key found in the page or its JS"
        return out
    try:
        await _require_scope(surl, tool="supabase_exposure")
    except ScopeError as exc:
        out["verdict"] = "backend_out_of_scope"
        out["note"] = f"discovered {surl} but it is out of scope ({exc}) — add it to scope to test"
        return out
    hdr = {"apikey": key, "Authorization": f"Bearer {key}"}
    schema = await ctx.http.fetch(supabasemod.schema_url(surl, key), headers=hdr,
                                  follow_redirects=True, timeout=12.0, scope_check=sc)
    tables = supabasemod.parse_tables(schema.text(200_000))
    out["tables_discovered"] = len(tables)
    open_tables: list[str] = []
    for t in tables[:max(1, min(max_tables, 40))]:
        r = await ctx.http.fetch(supabasemod.table_url(surl, t, key), headers=hdr,
                                 follow_redirects=False, timeout=12.0, scope_check=sc)
        if supabasemod.assess_table(r.status, r.text(50_000)):
            open_tables.append(t)
    out["rls_off_tables"] = open_tables
    if open_tables:
        out.update(verdict="confirmed", severity="high",
                   detail=(f"{len(open_tables)} table(s) readable with the public anon key (RLS off): "
                           f"{', '.join(open_tables[:10])} — full SELECT exposure. Bulk dump → Strix."))
    else:
        out["verdict"] = "no_open_tables"
        out["detail"] = "no table returned a row to the anon key (RLS appears enabled)"
    return out
