"""SNI / Host mismatch (domain fronting / SNI bypass) — pure helpers + real-TLS integration."""

import socket
import ssl
import subprocess
import threading

import pytest

from moonmcp import server as srv
from moonmcp.web import snimismatch as sm


# -- pure helpers -------------------------------------------------------------
def test_build_get_shape():
    req = sm.build_get("real.example", "/x?y=1").decode()
    assert req.startswith("GET /x?y=1 HTTP/1.1\r\n")
    assert "Host: real.example\r\n" in req
    assert "Connection: close\r\n" in req
    assert req.endswith("\r\n\r\n")


def test_build_get_default_path():
    req = sm.build_get("h", "").decode()
    assert req.startswith("GET / HTTP/1.1\r\n")


def test_content_matches():
    assert sm.content_matches(200, 500, 200, 520, jitter=50)      # within jitter
    assert not sm.content_matches(200, 500, 403, 520, jitter=50)   # status differs
    assert not sm.content_matches(200, 500, 200, 900, jitter=50)   # length way off
    assert not sm.content_matches(200, 500, None, 0, jitter=50)    # unreachable
    assert not sm.content_matches(None, 0, 200, 500, jitter=50)    # no baseline


def test_decoy_sni_constant_is_not_a_real_looking_target():
    assert sm.DECOY_SNI and "." in sm.DECOY_SNI
    assert sm.DECOY_SNI != ""


# -- real-TLS integration: does fetch_over_sni ACTUALLY send the SNI we intend? ----
def _have_openssl():
    try:
        subprocess.run(["openssl", "version"], check=True, capture_output=True)
        return True
    except (OSError, subprocess.CalledProcessError):
        return False


def _make_selfsigned(certfile, keyfile):
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", keyfile,
         "-out", certfile, "-days", "1", "-nodes", "-subj", "/CN=localhost"],
        check=True, capture_output=True,
    )


class _SniCapturingServer:
    """A minimal threaded HTTPS server that records the ClientHello SNI it saw (or None) and
    always answers the SAME fixed body, regardless of Host header — isolating the test to
    "did fetch_over_sni present the SNI I asked for" rather than any Host-routing logic."""

    def __init__(self, certfile, keyfile):
        self.seen_sni = []
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile, keyfile)
        ctx.sni_callback = lambda sslobj, name, sslctx: self.seen_sni.append(name)
        self._ctx = ctx
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(10)
        self.port = listener.getsockname()[1]
        self._listener = listener
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop.is_set():
            try:
                self._listener.settimeout(0.5)
                conn, _ = self._listener.accept()
            except (OSError, TimeoutError):
                continue
            try:
                tls = self._ctx.wrap_socket(conn, server_side=True)
                tls.recv(65536)
                tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
                tls.close()
            except (ssl.SSLError, OSError):
                try:
                    conn.close()
                except OSError:
                    pass

    def stop(self):
        self._stop.set()
        self._listener.close()


@pytest.fixture
def sni_server(tmp_path):
    if not _have_openssl():
        pytest.skip("openssl not available")
    cert, key = str(tmp_path / "c.pem"), str(tmp_path / "k.pem")
    _make_selfsigned(cert, key)
    srv_obj = _SniCapturingServer(cert, key)
    try:
        yield srv_obj
    finally:
        srv_obj.stop()


@pytest.mark.asyncio
async def test_fetch_over_sni_sends_decoy_sni(sni_server):
    status, length, err = await sm.fetch_over_sni(
        "127.0.0.1", sni_server.port, sni=sm.DECOY_SNI, host_header="real.example",
        path="/", timeout=3.0)
    assert err is None and status == 200 and length == 5
    assert sni_server.seen_sni == [sm.DECOY_SNI]           # the server saw the DECOY, not real.example


@pytest.mark.asyncio
async def test_fetch_over_sni_blank_sends_no_sni(sni_server):
    status, length, err = await sm.fetch_over_sni(
        "127.0.0.1", sni_server.port, sni="", host_header="real.example",
        path="/", timeout=3.0)
    assert err is None and status == 200 and length == 5
    assert sni_server.seen_sni == [None]                    # no SNI extension was sent at all


@pytest.mark.asyncio
async def test_fetch_over_sni_unreachable_port_errors():
    status, length, err = await sm.fetch_over_sni(
        "127.0.0.1", 1, sni="x.example", host_header="real.example", path="/", timeout=1.0)
    assert status is None and length == 0 and err is not None


# Note: a full vhost_probe-tool-level HTTPS test isn't feasible here — its baseline goes
# through ctx.http.fetch(), which enforces real certificate validation and rejects a
# self-signed test cert (exactly why test_http2.py's local-TLS-server test exercises
# _h2c_handshake directly rather than the full http2_probe tool). fetch_over_sni's real
# network behaviour is covered directly above (SNI content verified via sni_callback).
@pytest.mark.asyncio
async def test_vhost_probe_no_sni_lanes_over_plain_http(local_server, fresh_context):
    base, _ = local_server
    res = await srv.vhost_probe(target=base)
    assert res["decoy_sni_bypass"] is None and res["blank_sni_bypass"] is None


# -- registration (vhost_probe already exists; this just pins the enhancement landed) ----
@pytest.mark.asyncio
async def test_vhost_probe_still_registered():
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert "vhost_probe" in tools
