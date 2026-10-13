"""Deep API schema extraction from JS bundles (Angular/React/webpack).

Born from the PT Cloud AF engagement (2026-09-04): the REST prefix
(`rest:"/api/ptaf"`, `version:"v4"`), the body schemas (field names, types,
regex patterns, required lists) and the content-negotiation secret
(Accept: application/json) were all extracted by hand from minified
`main.js`. This module automates that: feed it a bundle URL (or text) and it
returns the reconstructed API surface — endpoints, methods, request/response
field schemas, security permissions, version prefixes.

What it extracts:
- REST base config: `backend:{rest:"...", version:"..."}` (Angular env patterns)
- Endpoint definitions: `_.endpoint="...", _.method="..."` (FastAPI-style
  generated clients) plus generic `"/path"` string scanning
- Body schemas: JSON-schema fragments following `Body={type:"object",...}`
  with per-field type/pattern/required/example
- Security annotations: `_.security=["auth.users.create"]` permission names
- Response variants: `x-variant-check` oneOf discriminators
- Format hints worth probing: `format:"email"`, `format:"uuid"`,
  `format:"password"`, enum arrays, example values (UUIDs, emails, versions)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class FieldSchema:
    name: str
    type: str = ""
    pattern: str = ""
    format: str = ""
    example: str = ""
    required: bool = False
    enum: list = field(default_factory=list)

    def to_dict(self) -> dict:
        out = {"name": self.name, "type": self.type}
        if self.pattern:
            out["pattern"] = self.pattern[:120]
        if self.format:
            out["format"] = self.format
        if self.example:
            out["example"] = self.example[:80]
        if self.required:
            out["required"] = True
        if self.enum:
            out["enum"] = self.enum
        return out


@dataclass
class EndpointSchema:
    path: str
    method: str = "GET"
    security: list = field(default_factory=list)
    request_fields: list = field(default_factory=list)   # list[FieldSchema]
    response_fields: list = field(default_factory=list)  # list[FieldSchema]
    notes: list = field(default_factory=list)

    def to_dict(self) -> dict:
        out = {"method": self.method, "path": self.path}
        if self.security:
            out["security"] = self.security
        if self.request_fields:
            out["body"] = [f.to_dict() for f in self.request_fields]
        if self.response_fields:
            out["response"] = [f.to_dict() for f in self.response_fields]
        if self.notes:
            out["notes"] = self.notes
        return out


# ─── bundle fetching ──────────────────────────────────────────────────────

def _fetch(url: str) -> str:
    import urllib.request
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                     "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    })
    with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
        return r.read().decode("utf-8", errors="replace")


# ─── extractors ───────────────────────────────────────────────────────────

_BACKEND_CFG = re.compile(
    r'backend\s*:\s*\{\s*rest\s*:\s*"([^"]+)"\s*,\s*version\s*:\s*"([^"]+)"'
)
_ENDPOINT_DEF = re.compile(r'\.endpoint\s*=\s*"([^"]+)"[^}]*?\.method\s*=\s*"([^"]+)"')
_SECURITY = re.compile(r'\.security\s*=\s*\[([^\]]*)\]')
_PROP = re.compile(r'(\w+)\s*:\s*\{(?:example\s*:\s*("[^"]*"|!0|!1|[0-9.-]+)\s*,)?'
                   r'type\s*:\s*"(\w+)"(?:\s*,\s*pattern\s*:\s*"((?:[^"\\]|\\.)*)")?'
                   r'(?:\s*,\s*format\s*:\s*"(\w+)")?')
_REQUIRED = re.compile(r'required\s*:\s*\[([^\]]*)\]')
_UUID_EX = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')


def _unescape(s: str) -> str:
    return s.replace("\\/", "/").replace("\\\\", "\\").replace('\\"', '"')


def extract_schemas(text: str, max_endpoints: int = 60) -> dict:
    """Extract the API surface from a (minified) JS bundle text."""

    result: dict = {"endpoints": [], "rest_config": None, "interesting": {}}

    # 1. REST base config
    m = _BACKEND_CFG.search(text)
    if m:
        result["rest_config"] = {"rest": m.group(1), "version": m.group(2)}

    # 2. Endpoint definitions with method
    seen = set()
    for m in _ENDPOINT_DEF.finditer(text):
        path, method = m.group(1), m.group(2)
        if (path, method) in seen or len(result["endpoints"]) >= max_endpoints:
            continue
        seen.add((path, method))
        # Look ahead in a window for the Body schema + security
        window = text[m.start():m.start() + 4000]
        ep = EndpointSchema(path=path, method=method)

        sm = _SECURITY.search(window)
        if sm:
            ep.security = [p.strip().strip('"\'') for p in sm.group(1).split(",") if p.strip()]

        bm = re.search(r'\.Body\s*=\s*\{', window)
        if bm:
            # The body object runs until the matching close at required:[...] or
            # Responses — take a bounded chunk and parse props.
            chunk = window[bm.start():bm.start() + 2500]
            fields = _parse_fields(chunk)
            ep.request_fields = fields

            rm = _REQUIRED.search(chunk)
            if rm:
                req_names = {p.strip().strip('"\'') for p in rm.group(1).split(",") if p.strip()}
                for f in ep.request_fields:
                    if f.name in req_names:
                        f.required = True

        resp_m = re.search(r'Responses\.CREATED|Responses\.OK', window)
        if resp_m:
            chunk2 = window[resp_m.start():resp_m.start() + 2000]
            ep.response_fields = _parse_fields(chunk2)

        # variant discriminators (oneOf)
        if 'x-variant-check' in window:
            ep.notes.append("has oneOf variant response")

        result["endpoints"].append(ep.to_dict())

    # 3. Interesting constants for follow-up probing
    uuids = sorted(set(_UUID_EX.findall(text)))[:10]
    if uuids:
        result["interesting"]["uuid_examples"] = uuids
    emails = sorted(set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}', text)))[:10]
    if emails:
        result["interesting"]["emails"] = emails
    versions = sorted(set(re.findall(r'\b\d+\.\d+\.\d+(?:-[0-9a-z]+)?\b', text)))[:10]
    if versions:
        result["interesting"]["version_strings"] = versions

    # 4. Plain API-ish path strings (fallback surface discovery)
    paths = sorted(set(re.findall(r'"(/(?:api|v\d|auth|mfa)/[a-z0-9_/.\-]{2,60})"', text)))
    if paths:
        result["interesting"]["path_strings"] = paths[:40]

    return result


def _parse_fields(chunk: str) -> list:
    fields = []
    seen_names = set()
    for pm in _PROP.finditer(chunk):
        name = pm.group(1)
        if name in seen_names or name in ("errors", "items", "error_codes"):
            continue
        seen_names.add(name)
        example = pm.group(2) or ""
        if isinstance(example, str):
            example = example.strip('"')
        elif example == "!0":
            example = "true"
        elif example == "!1":
            example = "false"
        fs = FieldSchema(
            name=name,
            type=pm.group(3) or "",
            pattern=_unescape(pm.group(4) or ""),
            format=pm.group(5) or "",
            example=str(example)[:80],
        )
        # enum arrays: enum:[!1] or enum:["a","b"]
        em = re.search(rf'{name}\s*:\s*\{{[^}}]*?enum\s*:\s*\[([^\]]*)\]', chunk)
        if em:
            vals = [v.strip().strip('"\'') for v in em.group(1).split(",") if v.strip()]
            fs.enum = [True if v == '!0' else False if v == '!1' else v for v in vals][:8]
        fields.append(fs)
        if len(fields) >= 12:
            break
    return fields


# ─── MCP tool entry ───────────────────────────────────────────────────────

async def extract_api_schemas(target: str, max_scripts: int = 3) -> dict:
    """Fetch a page, pull its same-origin scripts, and deep-extract the API
    surface from each bundle. Returns reconstructed endpoint schemas."""

    base_html = _fetch(target) if target.startswith("http") else target
    scripts = re.findall(r'src="([^"]+\.js)"', base_html)[:max_scripts]

    out: dict = {"url": target, "scripts": [], "schemas": []}
    # base URL directory for relative resolution
    page_base = target if target.endswith("/") else target.rsplit("/", 1)[0] + "/"
    if "://" in page_base and "/" not in page_base.split("://", 1)[1]:
        page_base += "/"
    for s in scripts:
        if s.startswith("http"):
            surl = s
        elif s.startswith("/"):
            # path-absolute: resolve against the origin
            origin = "/".join(target.split("/")[:3])  # scheme://host
            surl = origin + s
        else:
            # relative: resolve against the page base directory
            surl = page_base + s
        try:
            text = _fetch(surl)
        except Exception as exc:
            out["scripts"].append({"url": surl, "error": str(exc)[:100]})
            continue
        schemas = extract_schemas(text)
        out["scripts"].append({
            "url": surl,
            "bytes": len(text),
            "endpoints": len(schemas["endpoints"]),
            "rest_config": schemas["rest_config"],
        })
        out["schemas"].append(schemas)
    return out