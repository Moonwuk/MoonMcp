"""Edge-appliance fingerprint → version → known-exploited-CVE oracle — detection only.

Internet-facing VPN / ADC / firewall appliances (Citrix NetScaler, Ivanti Connect Secure,
Fortinet SSL-VPN, Palo Alto GlobalProtect, F5 BIG-IP) are the single most mass-exploited attack
surface — most of CISA's KEV "actively exploited" top entries are these boxes. A plain web
scanner walks straight past them: the tell is a login portal at a product-specific path plus a
distinctive cookie/header/body marker. This probe fingerprints the appliance from those markers,
reads the version where the box discloses it (e.g. Ivanti's ``nc_gina_ver.txt``), and attaches
the product's **known-exploited CVEs** to check.

Detection-only: it sends **benign GETs to fingerprint + version-disclosure paths only** — never
an exploit (no CVE-2018-13379 traversal read, no CVE-2024-3400 injection). Confirming a specific
version against a CVE and weaponizing is delegated to nuclei / Strix.

Sources: CISA KEV catalog; vendor advisories (Citrix Bleed CVE-2023-4966, Ivanti
CVE-2023-46805/CVE-2024-21887, Fortinet CVE-2024-21762/CVE-2022-40684, PAN CVE-2024-3400, F5
CVE-2022-1388).
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Product:
    name: str
    paths: tuple[str, ...]                 # fingerprint paths to GET (first hit wins)
    signals: tuple[str, ...]               # product-specific substrings (matched case-insensitively)
    cves: tuple[dict, ...]                 # {"id", "note", "kev": bool}
    version_path: str | None = None        # a benign version-disclosure path, if the box has one
    version_re: str | None = None


PRODUCTS: tuple[Product, ...] = (
    Product(
        "Citrix NetScaler / Gateway (ADC)",
        ("/vpn/index.html", "/logon/LogonPoint/tmindex.html", "/"),
        ("nsc_aaac", "nsc_temp", "ns-cache", "citrix gateway", "/vpn/js/", "rdx/core"),
        ({"id": "CVE-2023-4966", "note": "Citrix Bleed — session-token memory leak", "kev": True},
         {"id": "CVE-2023-3519", "note": "unauth RCE", "kev": True},
         {"id": "CVE-2019-19781", "note": "path-traversal RCE", "kev": True}),
    ),
    Product(
        "Ivanti Connect Secure / Pulse Secure",
        ("/dana-na/auth/url_default/welcome.cgi", "/dana-na/nc/nc_gina_ver.txt"),
        ("dana-na", "dsid", "pulse secure", "ivanti", "welcome.cgi"),
        ({"id": "CVE-2023-46805 + CVE-2024-21887", "note": "auth-bypass + command-injection chain",
          "kev": True},
         {"id": "CVE-2021-22893", "note": "unauth RCE", "kev": True},
         {"id": "CVE-2019-11510", "note": "arbitrary file read", "kev": True}),
        version_path="/dana-na/nc/nc_gina_ver.txt",
        version_re=r"<version>\s*([\d.]+[Rr]?[\d.]*)\s*</version>|([\d]+\.[\d]+[Rr][\d.]+)",
    ),
    Product(
        "Fortinet FortiOS SSL-VPN",
        ("/remote/login", "/remote/fgt_lang?lang=en"),
        ("/sslvpn/", "fgt_lang", "forticlient", "sslvpn_login", "logincheck"),
        ({"id": "CVE-2024-21762", "note": "out-of-bounds write pre-auth RCE", "kev": True},
         {"id": "CVE-2022-42475", "note": "heap overflow RCE", "kev": True},
         {"id": "CVE-2022-40684", "note": "auth bypass", "kev": True},
         {"id": "CVE-2018-13379", "note": "path-traversal credential leak", "kev": True}),
    ),
    Product(
        "Palo Alto GlobalProtect",
        ("/global-protect/login.esp", "/global-protect/portal/css/login.css", "/ssl-vpn/login.esp"),
        ("globalprotect portal", "pangp", "global-protect", "/ssl-vpn/"),
        ({"id": "CVE-2024-3400", "note": "unauth command injection (arbitrary file create)", "kev": True},
         {"id": "CVE-2019-1579", "note": "pre-auth RCE", "kev": True}),
    ),
    Product(
        "F5 BIG-IP",
        ("/tmui/login.jsp", "/"),
        ("bigipserver", "f5 networks", "/tmui/", "bigip"),
        ({"id": "CVE-2022-1388", "note": "iControl REST auth bypass RCE", "kev": True},
         {"id": "CVE-2023-46747", "note": "AJP request smuggling → RCE", "kev": True},
         {"id": "CVE-2020-5902", "note": "TMUI RCE", "kev": True}),
    ),
)


def haystack(body: str, header_lines: list[str]) -> str:
    """The lower-cased text to match signals against: body + header/cookie lines (pure)."""

    return (" ".join([body or "", *header_lines])).lower()


def match_product(prod: Product, hay: str) -> str | None:
    """The first product signal present in *hay*, or None (pure)."""

    return next((s for s in prod.signals if s in hay), None)


def extract_version(prod: Product, text: str) -> str | None:
    """Pull a version string from a version-disclosure response, if the product defines a
    pattern and it matches (pure)."""

    if not prod.version_re:
        return None
    m = re.search(prod.version_re, text or "")
    if not m:
        return None
    return next((g for g in m.groups() if g), None)


def _header_lines(r) -> list[str]:
    lines: list[str] = []
    try:
        lines += [f"{k}: {v}" for k, v in r.headers_map().items()]
    except Exception:  # noqa: BLE001 - a header accessor quirk must not abort fingerprinting
        pass
    try:
        lines += r.get_all("set-cookie")
    except Exception:  # noqa: BLE001
        pass
    return lines


async def probe_appliance(client, base_url: str, *, scope_check=None) -> dict:
    """Fingerprint an edge appliance at *base_url* and attach its known-exploited CVEs.
    Detection-only — fingerprint + version-disclosure GETs, never an exploit."""

    root = base_url.rstrip("/")

    async def _get(path: str):
        return await client.fetch(root + path, method="GET", follow_redirects=False,
                                  timeout=12.0, scope_check=scope_check)

    findings: list[dict] = []
    for prod in PRODUCTS:
        matched = None
        for path in prod.paths:
            r = await _get(path)
            if r.status is None:
                continue
            hit = match_product(prod, haystack(r.text(60_000), _header_lines(r)))
            if hit:
                matched = {"path": path, "signal": hit, "status": r.status}
                break
        if not matched:
            continue
        version = None
        if prod.version_path:
            vr = await _get(prod.version_path)
            if vr.status == 200:
                version = extract_version(prod, vr.text(20_000))
        kev = [c["id"] for c in prod.cves if c.get("kev")]
        findings.append({
            "product": prod.name, "severity": "high", "matched": matched, "version": version,
            "cves": list(prod.cves),
            "detail": (f"{prod.name} login portal exposed (matched `{matched['signal']}`)"
                       + (f", version {version}" if version else "")
                       + f". Known-exploited CVEs to verify: {', '.join(kev)}. Confirm the exact "
                       "version/patch and weaponize via nuclei / Strix — no exploit was sent."),
        })

    return {"target": root, "verdict": "appliance_detected" if findings else "none",
            "findings": findings}
