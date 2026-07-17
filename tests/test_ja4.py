"""JA4+ (JA4S server-TLS + JA4X certificate) fingerprinting."""

import datetime
import hashlib
import socket
import ssl
import struct
import threading

import pytest

from moonmcp import server as srv
from moonmcp.net import ja4


# -- pure: OID DER-hex encoding --------------------------------------------
def test_oid_to_hex():
    assert ja4._oid_to_hex("2.5.4.6") == "550406"           # countryName
    assert ja4._oid_to_hex("2.5.4.3") == "550403"           # commonName
    assert ja4._oid_to_hex("2.5.29.19") == "551d13"         # basicConstraints
    assert ja4._oid_to_hex("1.2.840.113549.1.1.11") == "2a864886f70d01010b"  # sha256WithRSA (multibyte)


# -- pure: ServerHello parse + JA4S string ----------------------------------
def _server_hello(cipher=b"\x13\x01", version_ext=b"\x03\x04", alpn=b"h2", sid_len=0):
    body = b"\x03\x03" + b"\x00" * 32                        # legacy_version + random
    body += bytes([sid_len]) + b"\x00" * sid_len            # session_id
    body += cipher + b"\x00"                                # cipher + compression
    ext = b""
    if version_ext is not None:
        ext += b"\x00\x2b\x00\x02" + version_ext            # supported_versions (chosen)
    if alpn is not None:
        proto = bytes([len(alpn)]) + alpn
        lst = struct.pack(">H", len(proto)) + proto
        ext += b"\x00\x10" + struct.pack(">H", len(lst)) + lst
    body += struct.pack(">H", len(ext)) + ext
    hs = b"\x02\x00" + struct.pack(">H", len(body)) + body
    return b"\x16\x03\x03" + struct.pack(">H", len(hs)) + hs


def test_parse_server_hello_and_ja4s():
    parsed = ja4.parse_server_hello(_server_hello())
    assert parsed == {"version": "13", "cipher": "1301", "ext_types": ["002b", "0010"], "alpn": "h2"}
    exp = hashlib.sha256(b"002b,0010").hexdigest()[:12]
    assert ja4.ja4s_string(parsed) == f"t1302h2_1301_{exp}"


def test_parse_server_hello_tls12_no_alpn_with_sid():
    # TLS 1.2 (no supported_versions ext → legacy 0x0303 → "12"), no ALPN, non-empty sid
    sh = _server_hello(cipher=b"\xc0\x2f", version_ext=None, alpn=None, sid_len=32)
    parsed = ja4.parse_server_hello(sh)
    assert parsed["version"] == "12" and parsed["cipher"] == "c02f"
    assert parsed["alpn"] == "" and parsed["ext_types"] == []
    assert ja4.ja4s_string(parsed) == "t120000_c02f_000000000000"   # no exts → zero hash, 00 alpn


def test_parse_server_hello_rejects_non_serverhello():
    assert ja4.parse_server_hello(b"\x15\x03\x03\x00\x02\x02\x00") is None   # alert record
    assert ja4.parse_server_hello(b"") is None
    assert ja4.parse_server_hello(b"garbage") is None


def test_alpn_and_version_codes():
    assert ja4._alpn_code("h2") == "h2"
    assert ja4._alpn_code("http/1.1") == "h1"
    assert ja4._alpn_code("") == "00"
    assert ja4._alpn_code("\x00x") == "00"           # non-alnum end → 00
    assert ja4._version_code(b"\x03\x03") == "12" and ja4._version_code(b"\x99\x99") == "00"


# -- pure: JA4X over a real certificate -------------------------------------
def _self_signed_der(cn="moon.test"):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(datetime.datetime(2020, 1, 1))
            .not_valid_after(datetime.datetime(2035, 1, 1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER), key, cert


def test_ja4x_from_der():
    der, _key, _cert = _self_signed_der()
    jx = ja4.ja4x_from_der(der)
    assert jx["issuer_oids"] == ["550406", "550403"]        # C, CN in cert order
    assert jx["subject_oids"] == ["550406", "550403"]       # self-signed → issuer == subject
    assert "551d13" in jx["extension_oids"]                 # basicConstraints
    a, b, c = jx["ja4x"].split("_")
    assert a == b and all(len(seg) == 12 for seg in (a, b, c))   # self-signed a==b
    assert ja4.ja4x_from_der(b"not a cert") is None


# -- end-to-end against a loopback TLS server -------------------------------
def _serve_tls(der_key_cert, n_conns=4):
    """A tiny threaded TLS server on an ephemeral loopback port. Returns (port, stop)."""

    import tempfile

    from cryptography.hazmat.primitives import serialization
    _der, key, cert = der_key_cert
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    with tempfile.NamedTemporaryFile("wb", suffix=".pem", delete=False) as cf:
        cf.write(cert.public_bytes(serialization.Encoding.PEM))
        cf.write(key.private_bytes(serialization.Encoding.PEM,
                                   serialization.PrivateFormat.TraditionalOpenSSL,
                                   serialization.NoEncryption()))
        pem_path = cf.name
    ctx.load_cert_chain(pem_path)
    srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv_sock.bind(("127.0.0.1", 0))
    srv_sock.listen(n_conns + 2)
    port = srv_sock.getsockname()[1]
    stop = threading.Event()

    def loop():
        srv_sock.settimeout(1.0)
        while not stop.is_set():
            try:
                conn, _ = srv_sock.accept()
            except (TimeoutError, OSError):
                continue
            try:
                with ctx.wrap_socket(conn, server_side=True) as tls:
                    tls.recv(64)   # complete handshake; a raw-JA4S client closes early (that's fine)
            except (OSError, ssl.SSLError):
                pass
        srv_sock.close()

    threading.Thread(target=loop, daemon=True).start()
    return port, stop


@pytest.mark.asyncio
async def test_compute_ja4_against_loopback_server():
    dkc = _self_signed_der(cn="moon.test")
    port, stop = _serve_tls(dkc)
    try:
        res = await ja4.compute_ja4("127.0.0.1", port, timeout=8.0)
    finally:
        stop.set()
    # JA4S from the real ServerHello: well-formed (t1x / t12 …), three underscore fields
    assert res.ja4s is not None, res
    assert res.ja4s[0] == "t" and len(res.ja4s.split("_")) == 3
    # JA4X from the presented cert equals the direct computation over the same DER
    assert res.ja4x == ja4.ja4x_from_der(dkc[0])["ja4x"]


@pytest.mark.asyncio
async def test_ja4_fingerprint_tool_registered():
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "ja4_fingerprint" in tools
