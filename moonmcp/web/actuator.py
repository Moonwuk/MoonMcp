"""Spring Boot Actuator exploitation-recon + Jolokia — detection only.

`debug_exposure` flags that `/actuator/env` is *reachable*; this goes the last mile and turns
that into the actual loot, without exploiting anything:

* **`/env` leaked secrets** — parse the property sources and report every **secret-named**
  property (`*.password`, `*.secret`, `*.token`, api/access/private keys, connection strings)
  whose value is **not masked** (`******`). Spring sanitizes matching keys by default, so a
  visible value is a real misconfiguration / non-standard key name → credential disclosure.
* **`/heapdump` confirmed** — a full JVM heap dump = every in-memory secret, session and token.
  Confirmed by reading only the first bytes and matching the **HPROF magic**
  (`JAVA PROFILE 1.0.x`) with a bounded read — never downloading the (often GB-sized) dump.
* **`/mappings`** — the internal route map (attack-surface enumeration).
* **Jolokia** (`/actuator/jolokia` or `/jolokia`) — JMX-over-HTTP: `/jolokia/version` confirms
  it, `/jolokia/list` enumerates MBeans; we flag **RCE-capable** MBeans (MLet
  `getMBeansFromURL`, `createJNDIRealm`, Logback `reloadByURL`, DiagnosticCommand) **without
  invoking any of them** — that weaponization is Strix's job.

Boot 1.x (`/env`) and Boot 2/3 (`/actuator/env`) layouts are both handled. Everything is a
benign GET; the heap dump read is capped. Source: Wallarm/Veracode Actuator advisories, the
Jolokia MBean-RCE class (CVE-2018-1000130 & the JNDI/MLet chains).
"""

from __future__ import annotations

import json
import re

# Property names that should never expose a value in /env.
_SECRET_NAME = re.compile(
    r"(?i)(pass(word|wd)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|"
    r"credential|client[_-]?secret|conn(ection)?[_-]?string|datasource\.password|dsn|"
    r"authorization|encrypt|signing[_-]?key|aws[_-]?secret)")

# JMX MBeans / operations that lead to code execution — flagged, never invoked.
_RCE_MBEANS = ("getmbeansfromurl", "type=mlet", "createjndirealm", "reloadbyurl",
               "diagnosticcommand", "jolokia:type=config", "loaderrepository",
               "com.sun.management:type=hotspotdiagnostic")

HPROF_MAGIC = b"JAVA PROFILE 1.0"
# Boot 1.x /env markers — gate root-/env detection so an unrelated JSON endpoint isn't parsed
# as an actuator env (which would false-flag any `token`/`password`-named field).
_BOOT1_MARKERS = ('"systemProperties"', '"systemEnvironment"', '"applicationConfig', '"profiles"')


# --------------------------------------------------------------------------- #
# pure analysers
# --------------------------------------------------------------------------- #
def is_secret_name(name: str) -> bool:
    return bool(_SECRET_NAME.search(name or ""))


def is_masked(val) -> bool:
    """Spring sanitizes secret-named props to ``******``; treat empty/null/all-star as masked.

    A boolean is a configuration *flag* (`*-enabled`, `*-required`, `encryption: true`), never
    credential material — so a boolean-valued secret-named property is not a leak (and `bool` is a
    subclass of `int`, so it must be excluded before the generic non-string branch). A numeric value
    is still treated as a real leak (a digits-only password/PIN can serialise as a number)."""

    if val is None:
        return True
    if isinstance(val, bool):
        return True                                   # config flag, not a credential
    if not isinstance(val, str):
        return False                                  # a non-string (numeric/struct) value is a real leak
    s = val.strip()
    return s == "" or s.lower() in ("null", "none") or (bool(s) and set(s) <= {"*"})


def _preview(val) -> str:
    s = val if isinstance(val, str) else json.dumps(val)
    s = s.replace("\n", " ")
    return s if len(s) <= 60 else s[:57] + "…"


def leaked_secrets(env_json: dict) -> list[dict]:
    """Extract secret-named properties with an unmasked value from an ``/env`` document,
    handling both the Boot 2/3 (``propertySources[].properties{name:{value}}``) and the flatter
    Boot 1.x layouts (pure)."""

    leaks: list[dict] = []
    seen: set[str] = set()

    def _add(name, val, source=None):
        if is_secret_name(name) and not is_masked(val) and name not in seen:
            seen.add(name)
            leaks.append({"property": name, "value_preview": _preview(val), "source": source})

    srcs = env_json.get("propertySources") if isinstance(env_json, dict) else None
    if isinstance(srcs, list):                        # Boot 2/3
        for src in srcs:
            if not isinstance(src, dict):
                continue
            props = src.get("properties", {})
            if isinstance(props, dict):
                for name, meta in props.items():
                    val = meta.get("value") if isinstance(meta, dict) else meta
                    _add(name, val, src.get("name"))
    elif isinstance(env_json, dict):                  # Boot 1.x fallback: walk string leaves
        for src_name, section in env_json.items():
            if isinstance(section, dict):
                for name, val in section.items():
                    _add(name, val, src_name)
    return leaks


def is_heapdump(first_bytes: bytes) -> bool:
    """Does the response start with the HPROF magic — a real JVM heap dump? (pure)"""

    return (first_bytes or b"")[:len(HPROF_MAGIC)] == HPROF_MAGIC


def jolokia_agent(body: str) -> str | None:
    """Return the Jolokia agent version from a ``/jolokia/version`` response, or None (pure)."""

    try:
        doc = json.loads(body)
    except (ValueError, TypeError):
        return None
    val = doc.get("value") if isinstance(doc, dict) else None
    if isinstance(val, dict) and val.get("agent"):
        return str(val["agent"])
    return None


def dangerous_mbeans(list_body: str) -> list[str]:
    """RCE-capable MBean/operation markers present in a ``/jolokia/list`` response (pure)."""

    low = (list_body or "").lower()
    return [m for m in _RCE_MBEANS if m in low]


# --------------------------------------------------------------------------- #
# async probe
# --------------------------------------------------------------------------- #
async def probe_actuator(client, base_url: str, *, scope_check=None) -> dict:
    """Fingerprint Spring Boot Actuator + Jolokia at *base_url* and surface leaked secrets, a
    confirmed heap dump, the route map, and RCE-capable JMX MBeans — all detection-only."""

    root = base_url.rstrip("/")

    async def _get(path, **kw):
        r = await client.fetch(root + path, method="GET", follow_redirects=False,
                               timeout=12.0, scope_check=scope_check, **kw)
        return r

    # Discover the actuator base: Boot 2/3 `/actuator`, else legacy Boot 1.x at root.
    base = None
    idx = await _get("/actuator")
    if idx.status == 200 and '"_links"' in idx.text(20_000):
        base = "/actuator"
    else:
        legacy = await _get("/env")
        lt = legacy.text(4000)
        if legacy.status == 200 and lt.lstrip()[:1] == "{" and any(m in lt for m in _BOOT1_MARKERS):
            base = ""                                 # Boot 1.x serves /env at the root

    findings: list[dict] = []

    if base is not None:
        # /env — leaked secrets
        env = await _get(f"{base}/env")
        if env.status == 200:
            for leak in leaked_secrets(_json(env.text(500_000))):
                findings.append({"kind": "actuator_env_secret", "severity": "high",
                                 "endpoint": f"{base}/env", **leak,
                                 "detail": f"/env exposes an unmasked secret property `{leak['property']}`"})
        # /heapdump — HPROF-magic confirm with a bounded read (never download the whole dump)
        hd = await _get(f"{base}/heapdump", max_body=64, headers={"Range": "bytes=0-63"})
        if hd.status in (200, 206) and is_heapdump(hd.body):
            findings.append({"kind": "actuator_heapdump", "severity": "critical",
                             "endpoint": f"{base}/heapdump",
                             "detail": "a live JVM heap dump is downloadable (HPROF magic confirmed) "
                                       "— it contains every in-memory secret/session/token. Analyze "
                                       "offline (VisualVM / a HeapDump scanner)"})
        # /mappings — internal route map
        mp = await _get(f"{base}/mappings")
        if mp.status == 200 and ('"mappings"' in mp.text(2000) or '"dispatcherServlet"' in mp.text(2000)):
            findings.append({"kind": "actuator_mappings", "severity": "low",
                             "endpoint": f"{base}/mappings",
                             "detail": "the internal route map is exposed — enumerate hidden endpoints"})

    # Jolokia — under the actuator base and at the classic root path.
    for jbase in dict.fromkeys([f"{base}/jolokia" if base is not None else None, "/jolokia"]):
        if jbase is None:
            continue
        ver = await _get(f"{jbase}/version")
        agent = jolokia_agent(ver.text(20_000)) if ver.status == 200 else None
        if not agent:
            continue
        listing = await _get(f"{jbase}/list", headers={"Accept": "application/json"})
        mbeans = dangerous_mbeans(listing.text(500_000)) if listing.status == 200 else []
        findings.append({
            "kind": "jolokia", "severity": "high" if mbeans else "medium",
            "endpoint": jbase, "agent": agent, "rce_mbeans": mbeans,
            "detail": (f"Jolokia (JMX-over-HTTP) agent {agent} is exposed unauthenticated"
                       + (f" and exposes RCE-capable MBeans ({', '.join(mbeans)}) — weaponize the "
                          "JNDI/MLet chain via Strix" if mbeans else " — enumerate MBeans with grpcurl/Strix"))})
        break                                         # one working jolokia mount is enough

    verdict = ("confirmed" if any(f["severity"] in ("critical", "high") for f in findings)
               else "exposed" if findings else "not_actuator")
    return {"target": root, "actuator_base": base, "verdict": verdict, "findings": findings}


def _json(text: str) -> dict:
    try:
        doc = json.loads(text)
        return doc if isinstance(doc, dict) else {}
    except (ValueError, TypeError):
        return {}
