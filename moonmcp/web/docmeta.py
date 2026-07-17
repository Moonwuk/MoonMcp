"""Document-metadata OSINT — extract authors, software, internal paths, GPS from public files.

Public documents leak the organisation's internals in their metadata: the **author /
last-editor usernames** (password-spray + phishing targets), the **software and versions**
(tech-stack → CVE), **internal file paths / UNC shares** (usernames, internal hostnames,
directory layout), embedded **emails**, and **GPS coordinates** in photos. Pulling that from a
handful of PDFs/Office files/images off a target's site (the classic FOCA / metagoofil play)
maps the org before a single active packet.

This is the passive **reader** side (paired with `web_search` / `search_dorks`): fetch a public
document and parse its metadata with the **standard library only** — regex over the PDF Info
dict + XMP, ``zipfile`` + ``ElementTree`` over Office Open XML ``docProps`` (hardened against
zip-bombs and XXE), a compact EXIF reader for JPEG, and PNG text chunks. Nothing is written or
executed; the document bytes are untrusted input, parsed defensively.

Note: compressed PDF object streams (PDF ≥1.5) can hide the Info dict from a plain-text scan —
for those, fall back to exiftool. Legacy OLE ``.doc/.xls`` are not parsed here.
"""

from __future__ import annotations

import io
import re
import struct
import zipfile
from xml.etree import ElementTree as ET

# Cap on a single OOXML metadata member's *uncompressed* size — a zip-bomb guard (real
# core.xml/app.xml are a few KB).
_MAX_MEMBER = 2_000_000

# OOXML metadata namespaces.
_NS = {
    "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
    "dc": "http://purl.org/dc/elements/1.1/",
    "dcterms": "http://purl.org/dc/terms/",
    "ep": "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties",
}

# Fields whose values are person names (usernames / real names).
_AUTHOR_KEYS = {"author", "creator", "last_modified_by", "artist", "manager"}
# Fields that name software / versions.
_SOFTWARE_KEYS = {"producer", "creator_tool", "application", "app_version", "software", "make", "model"}

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
# Internal filesystem paths / UNC shares / file URIs that leak usernames + hostnames.
_PATH_RE = re.compile(
    r"[A-Za-z]:\\[^\s\"'<>|]+"                       # C:\Users\jsmith\...
    r"|\\\\[A-Za-z0-9._-]+\\[^\s\"'<>|]+"            # \\fileserver\share\...
    r"|/(?:home|Users|var|srv|opt|mnt|media)/[^\s\"'<>|:*?]+"   # /home/jsmith/...
    r"|file://[^\s\"'<>]+")
# Usernames embedded in the common path shapes.
_USER_IN_PATH = re.compile(r"(?:[A-Za-z]:\\Users\\|/home/|/Users/)([^\\/\s]+)")


# --------------------------------------------------------------------------- #
# type detection (pure)
# --------------------------------------------------------------------------- #
def detect_kind(data: bytes) -> str:
    """Sniff the document type from magic bytes: ``pdf`` | ``ooxml`` | ``jpeg`` | ``png`` |
    ``zip`` | ``unknown`` (pure)."""

    if data[:5] == b"%PDF-":
        return "pdf"
    if data[:3] == b"\xff\xd8\xff":
        return "jpeg"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if data[:4] == b"PK\x03\x04":
        # a zip — OOXML if it carries the OPC content-types part.
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                names = set(z.namelist())
            return "ooxml" if "[Content_Types].xml" in names else "zip"
        except zipfile.BadZipFile:
            return "zip"
    return "unknown"


# --------------------------------------------------------------------------- #
# PDF (pure) — regex over the raw bytes (Info dict + XMP), no PDF dependency
# --------------------------------------------------------------------------- #
def _pdf_string(raw: str) -> str:
    """Decode a captured PDF string body: a hex string (``<FEFF…>`` UTF-16 or ASCII) or a
    literal, best-effort (pure)."""

    s = raw.strip()
    if re.fullmatch(r"[0-9A-Fa-f\s]+", s) and len(s.replace(" ", "")) % 2 == 0:
        try:
            b = bytes.fromhex(s.replace(" ", ""))
            if b[:2] == b"\xfe\xff":
                return b[2:].decode("utf-16-be", "replace").strip()
            return b.decode("latin-1", "replace").strip()
        except ValueError:
            pass
    return re.sub(r"\\([()\\])", r"\1", s).strip()          # unescape \( \) \\


_PDF_INFO_KEYS = {
    "Author": "author", "Creator": "creator", "Producer": "producer",
    "Title": "title", "Subject": "subject", "Keywords": "keywords",
    "CreationDate": "created", "ModDate": "modified", "Company": "company",
}
_XMP_TAGS = {
    "creator_tool": r"<xmp:CreatorTool>([^<]+)</xmp:CreatorTool>",
    "producer": r"<pdf:Producer>([^<]+)</pdf:Producer>",
    "created": r"<xmp:CreateDate>([^<]+)</xmp:CreateDate>",
    "modified": r"<xmp:ModifyDate>([^<]+)</xmp:ModifyDate>",
    "author": r"<dc:creator>.*?<rdf:li[^>]*>([^<]+)</rdf:li>",
}


def parse_pdf(data: bytes) -> dict:
    """Extract the PDF ``/Info`` dictionary + XMP metadata by scanning the raw bytes (pure).
    Catches the common uncompressed case; compressed object streams need exiftool."""

    text = data.decode("latin-1", "replace")
    out: dict[str, str] = {}
    for key, norm in _PDF_INFO_KEYS.items():
        m = re.search(rf"/{key}\s*\(((?:[^()\\]|\\.)*)\)", text)
        if not m:
            m = re.search(rf"/{key}\s*<([0-9A-Fa-f\s]+)>", text)
        if m:
            val = _pdf_string(m.group(1))
            if val and norm not in out:
                out[norm] = val
    xmp = re.search(r"<x:xmpmeta[^>]*>.*?</x:xmpmeta>", text, re.DOTALL)
    if xmp:
        blob = xmp.group(0)
        for norm, pat in _XMP_TAGS.items():
            if norm in out:
                continue
            m = re.search(pat, blob, re.DOTALL)
            if m and m.group(1).strip():
                out[norm] = m.group(1).strip()
    return out


# --------------------------------------------------------------------------- #
# Office Open XML (pure) — zipfile + ElementTree, hardened
# --------------------------------------------------------------------------- #
def _safe_xml(z: zipfile.ZipFile, name: str) -> ET.Element | None:
    """Read one OOXML member and parse it — refusing an oversized (zip-bomb) member and any
    DOCTYPE/ENTITY (XXE / billion-laughs) since metadata parts never legitimately carry one."""

    try:
        info = z.getinfo(name)
    except KeyError:
        return None
    if info.file_size > _MAX_MEMBER:
        return None
    raw = z.read(name)
    head = raw[:4096].lstrip().lower()
    if b"<!doctype" in head or b"<!entity" in raw[:8192].lower():
        return None
    try:
        return ET.fromstring(raw)
    except ET.ParseError:
        return None


def _ooxml_subtype(names: set[str]) -> str:
    if "word/document.xml" in names:
        return "docx"
    if "xl/workbook.xml" in names:
        return "xlsx"
    if "ppt/presentation.xml" in names:
        return "pptx"
    return "ooxml"


def parse_ooxml(data: bytes) -> dict:
    """Extract ``docProps/core.xml`` + ``docProps/app.xml`` metadata from an OOXML file (pure)."""

    out: dict[str, str] = {}
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            names = set(z.namelist())
            out["_subtype"] = _ooxml_subtype(names)
            core = _safe_xml(z, "docProps/core.xml")
            app = _safe_xml(z, "docProps/app.xml")
    except zipfile.BadZipFile:
        return out

    core_map = {
        f"{{{_NS['dc']}}}creator": "author",
        f"{{{_NS['cp']}}}lastModifiedBy": "last_modified_by",
        f"{{{_NS['dcterms']}}}created": "created",
        f"{{{_NS['dcterms']}}}modified": "modified",
        f"{{{_NS['dc']}}}title": "title",
        f"{{{_NS['dc']}}}subject": "subject",
        f"{{{_NS['dc']}}}description": "description",
        f"{{{_NS['cp']}}}keywords": "keywords",
        f"{{{_NS['cp']}}}revision": "revision",
        f"{{{_NS['cp']}}}lastPrinted": "last_printed",
        f"{{{_NS['cp']}}}category": "category",
    }
    if core is not None:
        for el in core:
            norm = core_map.get(el.tag)
            if norm and el.text and el.text.strip():
                out[norm] = el.text.strip()
    app_map = {"Application": "application", "AppVersion": "app_version",
               "Company": "company", "Manager": "manager", "Template": "template",
               "TotalTime": "edit_minutes"}
    if app is not None:
        for el in app:
            local = el.tag.split("}")[-1]
            norm = app_map.get(local)
            if norm and el.text and el.text.strip():
                out[norm] = el.text.strip()
    return out


# --------------------------------------------------------------------------- #
# JPEG / PNG EXIF (pure) — compact reader for the OSINT-relevant tags
# --------------------------------------------------------------------------- #
_EXIF_TAGS = {0x010F: "make", 0x0110: "model", 0x0131: "software",
              0x0132: "datetime", 0x013B: "artist", 0x8298: "copyright"}
_TYPE_SIZE = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8}


def _exif_from_tiff(tiff: bytes) -> dict:
    """Parse a TIFF/EXIF block (IFD0 + GPS IFD) into the OSINT tags incl. decimal GPS (pure)."""

    out: dict[str, str] = {}
    if len(tiff) < 8 or tiff[:2] not in (b"II", b"MM"):
        return out
    be = tiff[:2] == b"MM"
    e = ">" if be else "<"

    def u16(o):
        return struct.unpack(e + "H", tiff[o:o + 2])[0]

    def u32(o):
        return struct.unpack(e + "I", tiff[o:o + 4])[0]

    def read_ifd(off):
        entries = {}
        if off + 2 > len(tiff):
            return entries, 0
        count = u16(off)
        p = off + 2
        for _ in range(count):
            if p + 12 > len(tiff):
                break
            tag, typ, num = u16(p), u16(p + 2), u32(p + 4)
            size = _TYPE_SIZE.get(typ, 0) * num
            if size == 0:
                p += 12
                continue
            voff = p + 8 if size <= 4 else u32(p + 8)
            entries[tag] = (typ, num, voff)
            p += 12
        nxt = u32(p) if p + 4 <= len(tiff) else 0
        return entries, nxt

    def val_str(typ, num, voff):
        if voff + _TYPE_SIZE.get(typ, 0) * num > len(tiff):
            return ""
        if typ == 2:                                  # ASCII
            return tiff[voff:voff + num].split(b"\x00")[0].decode("latin-1", "replace").strip()
        if typ in (3, 4):                             # SHORT/LONG
            fmt = "H" if typ == 3 else "I"
            return str(struct.unpack(e + fmt, tiff[voff:voff + _TYPE_SIZE[typ]])[0])
        return ""

    def rationals(voff, num):
        vals = []
        for i in range(num):
            o = voff + i * 8
            if o + 8 > len(tiff):
                break
            n, d = u32(o), u32(o + 4)
            vals.append(n / d if d else 0.0)
        return vals

    ifd0, _ = read_ifd(u32(4))
    for tag, (typ, num, voff) in ifd0.items():
        if tag in _EXIF_TAGS:
            v = val_str(typ, num, voff)
            if v:
                out[_EXIF_TAGS[tag]] = v
    # GPS IFD (pointer tag 0x8825): its value is an inline LONG holding the GPS-IFD offset, so
    # dereference it (read_ifd wants the offset, not the pointer's own location).
    if 0x8825 in ifd0:
        gps, _ = read_ifd(u32(ifd0[0x8825][2]))
        def _deg(tag_ref, tag_val):
            if tag_val not in gps:
                return None
            dms = rationals(gps[tag_val][2], gps[tag_val][1])
            if len(dms) < 3:
                return None
            dec = dms[0] + dms[1] / 60 + dms[2] / 3600
            ref = ""
            if tag_ref in gps:
                ref = tiff[gps[tag_ref][2]:gps[tag_ref][2] + 1].decode("latin-1", "replace")
            return -dec if ref in ("S", "W") else dec
        lat, lon = _deg(0x0001, 0x0002), _deg(0x0003, 0x0004)
        if lat is not None and lon is not None:
            out["gps"] = f"{lat:.6f},{lon:.6f}"
    return out


def parse_jpeg(data: bytes) -> dict:
    """Find the APP1 EXIF segment in a JPEG and parse it (pure)."""

    i = 2
    n = len(data)
    while i + 4 <= n and data[i] == 0xFF:
        marker = data[i + 1]
        if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7:
            i += 2
            continue
        seg_len = struct.unpack(">H", data[i + 2:i + 4])[0]
        seg = data[i + 4:i + 2 + seg_len]
        if marker == 0xE1 and seg[:6] == b"Exif\x00\x00":
            return _exif_from_tiff(seg[6:])
        if marker == 0xDA:                            # start of scan — no metadata past here
            break
        i += 2 + seg_len
    return {}


def parse_png(data: bytes) -> dict:
    """Extract PNG textual chunks (tEXt/iTXt keywords) + an embedded eXIf chunk (pure)."""

    out: dict[str, str] = {}
    key_map = {"Software": "software", "Author": "author", "Artist": "artist",
               "Comment": "comment", "Creation Time": "created", "Source": "source"}
    i = 8
    n = len(data)
    while i + 8 <= n:
        length = struct.unpack(">I", data[i:i + 4])[0]
        ctype = data[i + 4:i + 8]
        payload = data[i + 8:i + 8 + length]
        if ctype in (b"tEXt", b"iTXt"):
            kw = payload.split(b"\x00", 1)
            if len(kw) == 2:
                key = kw[0].decode("latin-1", "replace")
                val = kw[1].lstrip(b"\x00").decode("latin-1", "replace").strip()
                norm = key_map.get(key)
                if norm and val and norm not in out:
                    out[norm] = val
        elif ctype == b"eXIf":
            out.update(_exif_from_tiff(payload))
        elif ctype == b"IEND":
            break
        i += 12 + length                              # length + type(4) + data + crc(4)
    return out


# --------------------------------------------------------------------------- #
# classification (pure)
# --------------------------------------------------------------------------- #
def classify(meta: dict) -> dict:
    """Turn a flat metadata dict into OSINT categories: authors, software, usernames, internal
    paths, emails, gps, timestamps (pure)."""

    authors, software, paths, emails, users = [], [], [], [], []
    for key, val in meta.items():
        if key.startswith("_") or not isinstance(val, str) or not val.strip():
            continue
        if key in _AUTHOR_KEYS:
            authors.append(val)
        if key in _SOFTWARE_KEYS or (key == "app_version"):
            software.append(val)
        for m in _PATH_RE.findall(val):
            paths.append(m)
        emails += _EMAIL_RE.findall(val)
        for m in _USER_IN_PATH.findall(val):
            users.append(m)
    # last_modified_by / author are usernames too.
    for k in ("last_modified_by", "author"):
        if meta.get(k):
            users.append(meta[k])
    application = " ".join(x for x in (meta.get("application"), meta.get("app_version")) if x)
    if application.strip():
        software.append(application.strip())

    def _uniq(seq):
        seen: dict[str, None] = {}
        for x in seq:
            if x and x.strip():
                seen.setdefault(x.strip(), None)
        return list(seen)

    return {
        "authors": _uniq(authors),
        "usernames": _uniq(users),
        "software": _uniq(software),
        "internal_paths": _uniq(paths),
        "emails": _uniq(emails),
        "gps": meta.get("gps"),
        "timestamps": {k: meta[k] for k in ("created", "modified", "last_printed", "datetime")
                       if meta.get(k)},
    }


_PARSERS = {"pdf": parse_pdf, "ooxml": parse_ooxml, "jpeg": parse_jpeg, "png": parse_png}


def extract(data: bytes) -> dict:
    """Detect the document type and extract + classify its metadata (pure)."""

    kind = detect_kind(data)
    parser = _PARSERS.get(kind)
    meta = parser(data) if parser else {}
    findings = classify(meta)
    has = any(findings[k] for k in ("authors", "usernames", "software", "internal_paths", "emails")) \
        or bool(findings["gps"]) or bool(findings["timestamps"])
    return {"kind": kind, "subtype": meta.get("_subtype"),
            "metadata": {k: v for k, v in meta.items() if not k.startswith("_")},
            "findings": findings,
            "verdict": "metadata_found" if has else "no_metadata"}


async def fetch_and_extract(http_client, url: str, *, max_bytes: int = 8_000_000) -> dict:
    """Fetch a public document (not target-scoped; block-private SSRF still applies, auth
    suppressed) and extract its metadata."""

    raw = (url or "").strip()
    if "://" not in raw:
        raw = "https://" + raw
    try:
        r = await http_client.fetch(raw, method="GET", follow_redirects=True, suppress_auth=True)
    except Exception as exc:  # noqa: BLE001 - surface any transport failure as JSON
        return {"url": raw, "error": f"{type(exc).__name__}: {exc}"}
    if getattr(r, "blocked_reason", None):
        return {"url": raw, "error": f"blocked: {r.blocked_reason}"}
    if r.status is None:
        return {"url": raw, "error": r.error or "request failed (outbound network blocked?)"}
    body = (r.body or b"")[:max_bytes]
    out = extract(body)
    out.update({"url": raw, "final_url": getattr(r, "final_url", None), "status": r.status,
                "bytes": len(body)})
    return out
