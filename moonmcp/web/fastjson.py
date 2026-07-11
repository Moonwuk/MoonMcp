"""Fastjson / Jackson autoType deserialization — benign OAST-canary detector.

The #1 CN Java-stack bug: JSON binders that embed a class name (``@type``) instantiate
it and fire setters during parse, so ``JdbcRowSetImpl`` / ``BasicDataSource`` turn a
setter into a JNDI lookup → LDAP/RMI → RCE (CVE-2017-18349, CVE-2022-25845, the 1.2.x
chains). ``docs/TECHNIQUES.md`` describes it, but there was no active detector.

Detection (safe, OAST): the community's standard *probe* payloads use a benign, non-gadget
type whose only effect is an outbound DNS/HTTP lookup — ``java.net.Inet4Address`` /
``java.net.URL``. A callback to MoonMCP's OAST canary proves the endpoint deserializes
attacker-controlled ``@type`` (the vuln class is confirmed) **without** ever naming a JNDI
gadget or landing code. Weaponization (gadget selection, the JNDI server) → Strix.

Pure payload builders here; the ``fastjson_oast_probe`` tool posts them and polls OAST.
Sources: https://github.com/safe6Sec/Fastjson · https://www.yaklang.com/products/article/yakit-technical-study/fast-Json/ ·
https://github.com/wyzxxz/jndi_tool . See docs/DATABASE_RESEARCH.md D.2.
"""

from __future__ import annotations

import json

# Content-Types a Fastjson/Jackson body endpoint typically accepts.
JSON_CT = "application/json"


def fastjson_payloads(oast_host: str, http_url: str) -> list[tuple[str, bytes]]:
    """Benign ``@type`` OAST canaries — ``(label, json_body)``. Each payload's ONLY
    effect is a DNS/HTTP lookup to the canary; no JNDI gadget, no code execution.

    - ``java.net.Inet4Address`` resolves ``oast_host`` (DNS) regardless of JDK/autoType.
    - ``java.net.URL`` triggers an HTTP/DNS lookup on ``http_url`` (the nested form
      forces the ``hashCode`` resolve that Fastjson URL probes rely on).
    - the Jackson array form ``["java.net.URL", "..."]`` covers Jackson polymorphic typing.
    """

    return [
        ("fastjson-inetaddress",
         json.dumps({"@type": "java.net.Inet4Address", "val": oast_host}).encode()),
        ("fastjson-url",
         json.dumps({"@type": "java.net.URL", "val": http_url}).encode()),
        ("fastjson-url-hashcode",
         json.dumps({"@type": "java.net.URL", "val": {"@type": "java.net.URL", "val": http_url}}).encode()),
        ("jackson-url",
         json.dumps(["java.net.URL", http_url]).encode()),
    ]
