"""Bounded local-Docker adapter for the two trusted research recipes."""

from __future__ import annotations

import json
import os
import re
import selectors
import socket
import socketserver
import stat
import subprocess
import threading
import time
from pathlib import Path

from .research_recipes import DEFAULT_RECIPE, IMAGE, recipe
from .strix_adapted import DockerSandbox

APP = recipe().app  # compatibility for the original builtin recipe
LABEL = "moonmcp.research"
PROXY_KEYS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "FTP_PROXY",
              "http_proxy", "https_proxy", "all_proxy", "no_proxy", "ftp_proxy")


def bounded_command(args: list[str], *, timeout: float = 30, capture_output=True,
                    limit: int = 32_768, cancelled: threading.Event | None = None) -> subprocess.CompletedProcess:
    """Drain both pipes with a hard combined byte cap; kill/reap the CLI on failure.

    Killing Docker CLI is NOT proof of child termination. The caller must remove
    and independently confirm absence of the recorded container afterwards.
    """
    env = {k: v for k, v in os.environ.items() if k not in {
        "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"}}
    command = [args[0], "--host=unix:///var/run/docker.sock", *args[1:]]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    assert process.stdout is not None and process.stderr is not None
    output = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            for name in output:
                stream = getattr(process, name)
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)
            while selector.get_map():
                if cancelled is not None and cancelled.is_set():
                    raise InterruptedError("Research worker stopped; reconcile resources")
                left = deadline - time.monotonic()
                if left <= 0:
                    raise subprocess.TimeoutExpired(command, timeout)
                for key, _ in selector.select(min(left, .1)):
                    chunk = os.read(key.fd, 4096)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    if sum(len(v) for v in output.values()) + len(chunk) > limit:
                        raise RuntimeError("Docker command output limit exceeded; reconcile resources")
                    output[key.data].extend(chunk)
            process.wait(timeout=max(.01, deadline - time.monotonic()))
        return subprocess.CompletedProcess(command, process.returncode,
                                           bytes(output["stdout"]), bytes(output["stderr"]))
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()
        process.stderr.close()


class HTTPRelay:
    """A byte-preserving loopback HTTP relay to this recipe's Unix socket only."""

    def __init__(self, socket_path: Path):
        connections: set[socket.socket] = set()
        lock = threading.Lock()
        slots = threading.BoundedSemaphore(8)

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                if not slots.acquire(blocking=False):
                    return
                peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    peer.settimeout(5)
                    # Linux Unix socket paths are limited to ~108 bytes. Keep
                    # persistent state usable under long workspace/pytest paths.
                    directory_fd = os.open(socket_path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                    try:
                        peer.connect(f"/proc/self/fd/{directory_fd}/{socket_path.name}")
                    finally:
                        os.close(directory_fd)
                    self.request.settimeout(5)
                    with lock:
                        connections.update((self.request, peer))
                    with selectors.DefaultSelector() as selector:
                        selector.register(self.request, selectors.EVENT_READ, peer)
                        selector.register(peer, selectors.EVENT_READ, self.request)
                        while True:
                            events = selector.select(5)
                            if not events:
                                break
                            for key, _ in events:
                                data = key.fileobj.recv(16_384)
                                if not data:
                                    return
                                key.data.sendall(data)
                except OSError:
                    pass
                finally:
                    with lock:
                        connections.discard(self.request)
                        connections.discard(peer)
                    peer.close()
                    slots.release()

        class Server(socketserver.ThreadingTCPServer):
            daemon_threads = True
        self.server = Server(("127.0.0.1", 0), Handler)
        self.connections, self.lock = connections, lock
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        with self.lock:
            for connection in list(self.connections):
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        self.thread.join(timeout=2)


class ResearchSandbox(DockerSandbox):
    """Fixed admission around the existing exec/quarantine/removal lifecycle.

    A private Unix socket is the only host connection. The caller persists the
    resource record before start. No image, command or mount path comes from a
    portable capsule. The local Docker endpoint is pinned by bounded_command.
    """

    def __init__(self, resource: dict, socket_root: Path):
        ident = resource.get("id", "")
        if (not isinstance(ident, str) or not re.fullmatch(r"[a-f0-9]{32}", ident)
                or resource.get("container") != f"moonmcp-lab-{ident}"
                or resource.get("variant") not in {"fixed", "vulnerable"}):
            raise ValueError("Invalid research resource record")
        super().__init__(image=IMAGE, network="none")
        self.definition = recipe(resource.get("recipe", DEFAULT_RECIPE))
        self.resource = resource
        self._container_id = resource["container"]
        self.directory = socket_root / ident
        self.cancelled = threading.Event()

    def _run(self, args, **kwargs):
        if self.cancelled.is_set():
            raise InterruptedError("Research worker stopped")
        return bounded_command(args, cancelled=self.cancelled, **kwargs)

    def checked(self, args, *, timeout=30) -> bytes:
        result = self._run(["docker", *args], timeout=timeout)
        if result.returncode:
            raise RuntimeError(f"Docker {args[0]} failed with exit status {result.returncode}")
        return result.stdout

    def start(self) -> dict:
        self.checked(["image", "inspect", IMAGE, "--format", "{{.Id}}"])
        self.directory.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.directory.mkdir(mode=0o777)  # do not adopt a previous directory
        self.directory.chmod(0o777)
        self.checked(["run", "-d", "--pull=never", "--name", self._container_id,
                      "--label", f"{LABEL}={self.resource['id']}", "--network", "none",
                      "--user", "65532:65532", "--read-only", "--cap-drop", "ALL",
                      "--security-opt", "no-new-privileges", "--pids-limit", "32",
                      "--memory", "128m", "--cpus", "0.5", "--log-driver", "none",
                      # Docker CLI can inject proxy credentials from config.json
                      # even without explicit env forwarding. Override all forms.
                      *[arg for key in PROXY_KEYS for arg in ("--env", key + "=")],
                      "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m,mode=1777",
                      "--mount", f"type=bind,src={self.definition.app.resolve()},dst=/app.py,readonly",
                      "--mount", f"type=bind,src={self.directory.resolve()},dst=/exchange",
                      IMAGE, "python", "-I", "/app.py", "--variant", self.resource["variant"],
                      "--socket", "/exchange/app.sock"], timeout=45)
        template = ('{"user":{{json .Config.User}},"readonly":{{json .HostConfig.ReadonlyRootfs}},'
                    '"privileged":{{json .HostConfig.Privileged}},"caps":{{json .HostConfig.CapDrop}},'
                    '"network":{{json .HostConfig.NetworkMode}},"pids":{{.HostConfig.PidsLimit}},'
                    '"memory":{{.HostConfig.Memory}},"cpus":{{.HostConfig.NanoCpus}},'
                    '"security":{{json .HostConfig.SecurityOpt}}}')
        settings = json.loads(self.checked(["inspect", self._container_id, "--format", template]))
        if settings != {"user": "65532:65532", "readonly": True, "privileged": False,
                        "caps": ["ALL"], "network": "none", "pids": 32,
                        "memory": 134217728, "cpus": 500000000, "security": ["no-new-privileges"]}:
            raise RuntimeError("Docker runtime settings differ from the admitted recipe")
        return {"settings": settings}

    def cleanup(self) -> dict:
        """Successful queries must prove absence; an inspect error proves nothing."""
        remaining = []
        try:
            args = ["container", "ls", "-a", "--no-trunc", "--filter",
                    f"name=^/{self.resource['container']}$", "--format", "{{.ID}}"]
            present = self.checked(args).strip()
            owned = self.checked([*args, "--filter", f"label={LABEL}={self.resource['id']}"]).strip()
            if present != owned:
                remaining.append("container_ownership_mismatch")
            elif present and not re.fullmatch(rb"[a-f0-9]{64}", present):
                remaining.append("container_identity_unconfirmed")
            else:
                if present:
                    # A container name can be reused after the ownership query.
                    # Only delete the immutable ID that passed both queries.
                    self._container_id = present.decode("ascii")
                    self.stop()
                    if self.checked(["container", "ls", "-a", "--no-trunc", "--filter",
                                     f"id={present.decode('ascii')}", "--format", "{{.ID}}"]
                                    ).strip():
                        remaining.append("container_still_exists")
                # Also refuse to clean host files if another container acquired
                # the name while the verified container was being removed.
                current = self.checked(args).strip()
                if current:
                    issue = "container_replaced" if current != present else "container_still_exists"
                    if issue not in remaining:
                        remaining.append(issue)
        except Exception:
            remaining.append("container_cleanup_unconfirmed")
        if not remaining:
            try:
                if self.directory.is_symlink():
                    raise ValueError("Socket directory was replaced")
                path = self.directory / "app.sock"
                if path.exists():
                    if not stat.S_ISSOCK(path.lstat().st_mode):
                        raise ValueError("Unexpected socket entry")
                    path.unlink()
                if self.directory.exists():
                    self.directory.rmdir()  # refuse unexpected files; never recursively delete
            except (OSError, ValueError):
                remaining.append("socket_cleanup_unconfirmed")
        return {"ok": not remaining, "state": "completed" if not remaining else "unknown",
                "error": None if not remaining else "cleanup_unconfirmed",
                "remaining": remaining, "retryable": False}
