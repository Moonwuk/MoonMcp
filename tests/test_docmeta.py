"""Document-metadata OSINT — PDF / OOXML / JPEG-EXIF / PNG extraction + classification."""

import io
import struct
import zipfile

import pytest

from moonmcp import server as srv
from moonmcp.web import docmeta as dm


# -- builders for synthetic documents --------------------------------------
def _docx(core_fields, app_fields, subtype_part="word/document.xml"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr(subtype_part, "<x/>")
        core = ('<?xml version="1.0"?>'
                '<cp:coreProperties'
                ' xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"'
                ' xmlns:dc="http://purl.org/dc/elements/1.1/"'
                ' xmlns:dcterms="http://purl.org/dc/terms/">'
                + "".join(core_fields) + "</cp:coreProperties>")
        z.writestr("docProps/core.xml", core)
        app = ('<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/'
               'extended-properties">' + "".join(app_fields) + "</Properties>")
        z.writestr("docProps/app.xml", app)
    return buf.getvalue()


def _rational(n, d):
    return struct.pack("<II", n, d)


def _exif_tiff():
    software = b"MoonCam\x00"
    ifd0_start = 8
    ifd0_size = 2 + 2 * 12 + 4
    software_off = ifd0_start + ifd0_size
    gps_ifd_start = software_off + len(software)
    gps_ifd_size = 2 + 4 * 12 + 4
    lat_off = gps_ifd_start + gps_ifd_size
    lon_off = lat_off + 24

    header = b"II" + struct.pack("<HI", 0x2A, ifd0_start)
    e_sw = struct.pack("<HHI", 0x0131, 2, len(software)) + struct.pack("<I", software_off)
    e_gps = struct.pack("<HHI", 0x8825, 4, 1) + struct.pack("<I", gps_ifd_start)
    ifd0 = struct.pack("<H", 2) + e_sw + e_gps + struct.pack("<I", 0)

    def ascii4(s):
        b = s.encode()
        return b + b"\x00" * (4 - len(b))

    g_latref = struct.pack("<HHI", 0x0001, 2, 2) + ascii4("N")
    g_lat = struct.pack("<HHI", 0x0002, 5, 3) + struct.pack("<I", lat_off)
    g_lonref = struct.pack("<HHI", 0x0003, 2, 2) + ascii4("E")
    g_lon = struct.pack("<HHI", 0x0004, 5, 3) + struct.pack("<I", lon_off)
    gps_ifd = struct.pack("<H", 4) + g_latref + g_lat + g_lonref + g_lon + struct.pack("<I", 0)
    lat_data = _rational(37, 1) + _rational(25, 1) + _rational(0, 1)
    lon_data = _rational(122, 1) + _rational(5, 1) + _rational(0, 1)
    return header + ifd0 + software + gps_ifd + lat_data + lon_data


def _jpeg(tiff):
    app1 = b"Exif\x00\x00" + tiff
    return b"\xff\xd8\xff\xe1" + struct.pack(">H", len(app1) + 2) + app1 + b"\xff\xd9"


def _png_text(key, val):
    def chunk(ctype, payload):
        return struct.pack(">I", len(payload)) + ctype + payload + struct.pack(">I", 0)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", b"\x00" * 13)
            + chunk(b"tEXt", key.encode() + b"\x00" + val.encode()) + chunk(b"IEND", b""))


# -- type detection ---------------------------------------------------------
def test_detect_kind():
    assert dm.detect_kind(b"%PDF-1.7\n...") == "pdf"
    assert dm.detect_kind(b"\xff\xd8\xff\xe0rest") == "jpeg"
    assert dm.detect_kind(b"\x89PNG\r\n\x1a\nrest") == "png"
    assert dm.detect_kind(_docx(["<dc:title>t</dc:title>"], [])) == "ooxml"
    assert dm.detect_kind(b"<html>") == "unknown"


# -- PDF --------------------------------------------------------------------
def test_pdf_string_hex_and_utf16():
    assert dm._pdf_string("4A6F686E") == "John"
    assert dm._pdf_string("FEFF004A006F0068006E") == "John"
    assert dm._pdf_string(r"a \(b\) c") == "a (b) c"


def test_parse_pdf_info_and_path():
    pdf = (b"%PDF-1.4\n1 0 obj\n<< /Author (John Smith) /Creator (Microsoft Word) "
           b"/Producer (macOS 12 Quartz PDFContext) /CreationDate (D:20230101120000Z) "
           b"/Title (C:\\\\Users\\\\jsmith\\\\q3.docx) >>\nendobj\ntrailer<< /Info 1 0 R >>\n%%EOF")
    meta = dm.parse_pdf(pdf)
    assert meta["author"] == "John Smith" and meta["creator"] == "Microsoft Word"
    assert "Quartz" in meta["producer"] and meta["created"].startswith("D:2023")
    out = dm.classify(meta)
    assert r"C:\Users\jsmith\q3.docx" in out["internal_paths"]
    assert "jsmith" in out["usernames"] and "John Smith" in out["authors"]


def test_parse_pdf_xmp_fallback():
    pdf = (b"%PDF-1.5\n<x:xmpmeta xmlns:x='adobe:ns:meta/'>"
           b"<xmp:CreatorTool>Scribus 1.5.8</xmp:CreatorTool>"
           b"<dc:creator><rdf:Seq><rdf:li>Alice Ng</rdf:li></rdf:Seq></dc:creator>"
           b"</x:xmpmeta>\n%%EOF")
    meta = dm.parse_pdf(pdf)
    assert meta["creator_tool"] == "Scribus 1.5.8" and meta["author"] == "Alice Ng"


# -- OOXML ------------------------------------------------------------------
def test_parse_ooxml_core_and_app():
    docx = _docx(
        ["<dc:creator>Jane Doe</dc:creator>",
         "<cp:lastModifiedBy>jsmith</cp:lastModifiedBy>",
         "<dcterms:created>2023-01-01T00:00:00Z</dcterms:created>",
         "<dc:title>Quarterly</dc:title>"],
        ["<Application>Microsoft Office Word</Application>",
         "<AppVersion>16.0000</AppVersion>",
         "<Company>Acme Corp</Company>",
         "<Template>\\\\fileserver\\templates\\corp.dotx</Template>"])
    out = dm.extract(docx)
    assert out["kind"] == "ooxml" and out["subtype"] == "docx"
    md = out["metadata"]
    assert md["author"] == "Jane Doe" and md["last_modified_by"] == "jsmith"
    assert md["application"] == "Microsoft Office Word" and md["company"] == "Acme Corp"
    f = out["findings"]
    assert "Jane Doe" in f["authors"] and "jsmith" in f["usernames"]
    assert any("fileserver" in p for p in f["internal_paths"])
    assert out["verdict"] == "metadata_found"


def test_ooxml_subtype_xlsx():
    xlsx = _docx(["<dc:creator>x</dc:creator>"], [], subtype_part="xl/workbook.xml")
    assert dm.extract(xlsx)["subtype"] == "xlsx"


def test_ooxml_rejects_doctype_xxe():
    # a metadata part carrying a DOCTYPE (XXE / billion-laughs) must be refused, not parsed
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", "<x/>")
        z.writestr("docProps/core.xml",
                   '<!DOCTYPE x [<!ENTITY e "boom">]>'
                   '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/'
                   'metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/">'
                   '<dc:creator>&e;</dc:creator></cp:coreProperties>')
        z.writestr("docProps/app.xml", '<Properties xmlns="http://schemas.openxmlformats.org/'
                   'officeDocument/2006/extended-properties"><Company>Acme</Company></Properties>')
    out = dm.extract(buf.getvalue())
    assert "author" not in out["metadata"]                 # DOCTYPE part refused
    assert out["metadata"].get("company") == "Acme"        # clean part still parsed


# -- JPEG / PNG -------------------------------------------------------------
def test_parse_jpeg_exif_gps():
    meta = dm.parse_jpeg(_jpeg(_exif_tiff()))
    assert meta["software"] == "MoonCam"
    assert meta["gps"].startswith("37.41") and "," in meta["gps"]
    out = dm.classify(meta)
    assert out["gps"] and "MoonCam" in out["software"]


def test_parse_png_text():
    meta = dm.parse_png(_png_text("Software", "GIMP 2.10"))
    assert meta["software"] == "GIMP 2.10"


# -- classify robustness ----------------------------------------------------
def test_classify_emails_and_empty():
    out = dm.classify({"description": "contact bob@acme.example for the report"})
    assert "bob@acme.example" in out["emails"]
    empty = dm.classify({})
    assert empty["authors"] == [] and empty["gps"] is None


def test_extract_unknown_is_no_metadata():
    assert dm.extract(b"just some text, not a document")["verdict"] == "no_metadata"


# -- fetch + registration ---------------------------------------------------
class _Resp:
    def __init__(self, body):
        self.body = body
        self.status = 200
        self.final_url = "https://x.test/report.docx"
        self.blocked_reason = None
        self.error = None


class _FakeHttp:
    def __init__(self, body):
        self.body = body

    async def fetch(self, url, **kw):
        return _Resp(self.body)


@pytest.mark.asyncio
async def test_fetch_and_extract():
    docx = _docx(["<dc:creator>Jane Doe</dc:creator>"], ["<Company>Acme</Company>"])
    out = await dm.fetch_and_extract(_FakeHttp(docx), "x.test/report.docx")
    assert out["verdict"] == "metadata_found" and out["status"] == 200
    assert "Jane Doe" in out["findings"]["authors"]


@pytest.mark.asyncio
async def test_fetch_blocked_ssrf():
    class _Blocked:
        async def fetch(self, url, **kw):
            class _R:
                status = None
                blocked_reason = "private-ip"
                body = b""
                error = None
                final_url = None
            return _R()
    out = await dm.fetch_and_extract(_Blocked(), "http://169.254.169.254/x.pdf")
    assert "blocked" in out["error"]


@pytest.mark.asyncio
async def test_document_metadata_osint_registered():
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "document_metadata_osint" in tools
