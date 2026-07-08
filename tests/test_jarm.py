"""JARM tests: golden vectors validated against the Salesforce reference, plus a
local TLS round-trip. The golden values were produced from an implementation
verified byte-for-byte against salesforce/jarm."""

import hashlib
import subprocess

import pytest

from moonmcp.net import jarm

# jarm_hash values verified equal to the Salesforce reference jarm_hash().
_H1 = "29d29d29d29d29d29d29d29d29d2abb629ffa9df9c9ebc7c1f08527269ec21"
_H2 = "41e27d000000000000000000000000bc09c45b03a174e4088ee88a06348688"

# sha256(build_client_hello(d))[:16] for the 10 probes, with randomness pinned.
_PKT_GOLDEN = [
    "08257032416f38d5", "bc7031f22e7e78ed", "f17aca1eadecc92c", "5337742276386af2",
    "4c57a5043740f540", "c68f1b4a2d62d55e", "860c3781d99620ad", "dc60552bdb7da541",
    "de2a7c5d90e8d870", "b2e5ef295d31c428",
]


def test_jarm_hash_matches_reference_vectors():
    assert jarm.jarm_hash("c02f|0303|h2|0017-ff01," * 9 + "c030|0301||0017") == _H1
    assert jarm.jarm_hash("1301|0304|h2|002b-0033,c02b|0303||0017-000b," + "|||," * 7 + "|||") == _H2
    assert len(_H1) == 62 and len(_H2) == 62


def test_jarm_null_fingerprint():
    assert jarm.jarm_hash("|||," * 9 + "|||") == "0" * 62


def test_version_and_cipher_bytes():
    # TLS version → letter (1.0→b, 1.1→c, 1.2→d, 1.3→e), matching the reference.
    assert jarm._version_byte("0301") == "b"
    assert jarm._version_byte("0303") == "d"
    assert jarm._version_byte("0304") == "e"
    assert jarm._version_byte("") == "0"
    assert jarm._cipher_byte("") == "00"
    # Reference-verified index of c02f in the JARM cipher table.
    assert jarm._cipher_byte("c02f") == "29"


def test_client_hello_packets_are_byte_stable(monkeypatch):
    monkeypatch.setattr(jarm.os, "urandom", lambda n: b"\xAB" * n)
    monkeypatch.setattr(jarm, "_choose_grease", lambda: b"\x0a\x0a")
    digs = [hashlib.sha256(jarm.build_client_hello(d)).hexdigest()[:16]
            for d in jarm._queue("example.com", 443)]
    assert digs == _PKT_GOLDEN


def test_client_hello_is_valid_tls_record():
    d = jarm._queue("example.com", 443)[0]
    pkt = jarm.build_client_hello(d)
    assert pkt[0] == 0x16  # TLS handshake record
    assert pkt[5] == 0x01  # ClientHello


def _have_openssl():
    try:
        subprocess.run(["openssl", "version"], check=True, capture_output=True)
        return True
    except (OSError, subprocess.CalledProcessError):
        return False


@pytest.mark.asyncio
async def test_jarm_roundtrip_against_local_tls(tmp_path):
    if not _have_openssl():
        pytest.skip("openssl not available")
    import socket
    import ssl
    import threading

    cert, key = str(tmp_path / "c.pem"), str(tmp_path / "k.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key,
                    "-out", cert, "-days", "1", "-nodes", "-subj", "/CN=localhost"],
                   check=True, capture_output=True)
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(cert, key)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.listen(20)
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            listener.settimeout(0.5)
            try:
                conn, _ = listener.accept()
            except (OSError, TimeoutError):
                continue
            try:
                ssock = sctx.wrap_socket(conn, server_side=True)
                ssock.close()
            except (ssl.SSLError, OSError):
                try:
                    conn.close()
                except OSError:
                    pass

    threading.Thread(target=serve, daemon=True).start()
    try:
        res = await jarm.compute_jarm("127.0.0.1", port, timeout=8.0)
        assert len(res.fingerprint) == 62
        # A real TLS server yields a non-null JARM (some handshakes succeed).
        assert res.is_null is False
    finally:
        stop.set()
        listener.close()
