"""Dependency-confusion recon.

A manifest surfaced during recon (``package.json``, ``composer.json``,
``requirements.txt``, ``Pipfile``) names the project's dependencies. If a name is
used privately (internal/unscoped) but **does not exist on the public registry**,
an attacker can publish a higher-version public package that the victim's build
pulls instead → supply-chain RCE (the Microsoft/Apple pattern).

This parses the manifest and existence-checks each dependency against its public
registry — a 404 marks a hijack candidate. It queries the *registry*, never the
target, so it is passive OSINT.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from urllib.parse import quote

from ..net.http import HttpClient

# ecosystem -> public-registry existence-check URL template ({name} is url-encoded)
_REGISTRY = {
    "npm": "https://registry.npmjs.org/{name}",
    "pypi": "https://pypi.org/pypi/{name}/json",
    "rubygems": "https://rubygems.org/api/v1/gems/{name}.json",
    "composer": "https://repo.packagist.org/p2/{name}.json",
}

_REQ_NAME_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)")


def detect_ecosystem(content: str, filename: str | None = None) -> str | None:
    name = (filename or "").lower()
    if name.endswith("package.json") or '"dependencies"' in content and '"devDependencies"' in content:
        return "npm"
    if name.endswith("composer.json") or '"require"' in content and "/" in content:
        return "composer"
    if name.endswith(("requirements.txt", ".pip")) or name == "requirements":
        return "pypi"
    if name.endswith("pipfile") or "[packages]" in content.lower():
        return "pypi"
    if name.endswith("gemfile"):
        return "rubygems"
    return None


def parse_dependencies(content: str, ecosystem: str) -> list[str]:
    """Extract dependency names for *ecosystem* from a manifest (best-effort, stdlib)."""

    names: list[str] = []
    if ecosystem in ("npm", "composer"):
        try:
            data = json.loads(content)
        except (ValueError, json.JSONDecodeError):
            return []
        keys = (("dependencies", "devDependencies", "peerDependencies", "optionalDependencies")
                if ecosystem == "npm" else ("require", "require-dev"))
        for k in keys:
            block = data.get(k)
            if isinstance(block, dict):
                names.extend(str(n) for n in block)
        if ecosystem == "composer":
            names = [n for n in names if "/" in n and not n.startswith(("php", "ext-", "lib-"))]
    elif ecosystem == "pypi":
        in_pkgs = True  # requirements.txt has no sections; Pipfile does
        for raw in content.splitlines():
            line = raw.strip()
            low = line.lower()
            if low.startswith("[") and low.endswith("]"):
                in_pkgs = low in ("[packages]", "[dev-packages]")
                continue
            if not line or line.startswith(("#", "-")):
                continue
            if in_pkgs:
                m = _REQ_NAME_RE.match(line)
                if m:
                    names.append(m.group(1))
    elif ecosystem == "rubygems":
        for raw in content.splitlines():
            m = re.match(r"""\s*gem\s+['"]([^'"]+)['"]""", raw)
            if m:
                names.append(m.group(1))
    # de-dupe, preserve order
    seen: set[str] = set()
    deduped: list[str] = []
    for n in names:
        if n not in seen:
            seen.add(n)
            deduped.append(n)
    return deduped


async def _npm_scope_owned(client: HttpClient, scope: str) -> bool:
    """Does the npm ``scope`` (e.g. ``@acme``) have any published public package? If so
    it is a REGISTERED scope and an attacker CANNOT publish under it — a 404 on a
    package under it is NOT dependency confusion. Best-effort: any failure returns
    False, so the caller stays conservative and reports a verify-first lead."""

    s = scope.lstrip("@")
    if not s:
        return False
    url = f"https://registry.npmjs.org/-/v1/search?text=scope:{quote(s, safe='')}&size=1"
    try:
        r = await client.fetch(url, follow_redirects=True, timeout=12.0)
    except Exception:  # noqa: BLE001 - registry hiccup → treat as unknown, not owned
        return False
    if r.status != 200:
        return False
    try:
        return int(json.loads(r.text()).get("total") or 0) > 0
    except (ValueError, TypeError, AttributeError):
        return False


async def check_dependencies(client: HttpClient, names: list[str], ecosystem: str, *,
                             scope_check: Callable[[str], bool] | None = None) -> list[dict]:
    """Existence-check each dependency against its public registry (404 = claimable)."""

    tpl = _REGISTRY.get(ecosystem)
    if tpl is None:
        return []
    out: list[dict] = []
    for name in names:
        url = tpl.format(name=quote(name, safe="@/"))
        r = await client.fetch(url, follow_redirects=True, timeout=12.0)
        scoped = ecosystem == "npm" and name.startswith("@")
        if r.status == 404:
            if scoped:
                # A registered @scope can't be claimed even if THIS package is absent —
                # npm reserves scopes independently of individual package existence, so
                # package-404 != scope-claimable. Confirm the scope is actually free
                # before asserting a high-severity dependency-confusion finding.
                scope = name.split("/", 1)[0]
                if await _npm_scope_owned(client, scope):
                    verdict, severity = "not_claimable", "info"
                    detail = (f"absent on the public registry, but the {scope} scope is REGISTERED "
                              "(has published packages) — an attacker cannot publish under it, so "
                              "this is NOT dependency confusion.")
                else:
                    verdict, severity = "claimable", "medium"
                    detail = (f"absent, and no public package found under {scope} — possibly "
                              "claimable, but VERIFY the scope is truly unregistered (a reserved "
                              "but empty org scope is not claimable) before reporting.")
            else:
                verdict, severity = "claimable", "medium"
                detail = "package name absent on the public registry — publishable by anyone"
        elif r.status == 200:
            verdict, severity, detail = "exists", "info", "already published on the public registry"
        else:
            verdict, severity, detail = "unknown", "info", f"registry returned HTTP {r.status}"
        out.append({"name": name, "ecosystem": ecosystem, "registry_status": r.status,
                    "verdict": verdict, "severity": severity, "detail": detail})
    return out
