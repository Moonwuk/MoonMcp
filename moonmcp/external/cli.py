"""Detection and safe invocation of external security CLIs.

Every wrapper follows the same contract: if the binary is missing, return a
result with ``available=False`` and a ``fallback`` hint rather than raising, so
the LLM can transparently fall back to MoonMCP's native capability.
"""

from __future__ import annotations

import asyncio
import json
import math
import os
import shutil
import signal
from collections.abc import Callable
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ToolSpec:
    """Metadata for a known external CLI.

    ``intrusive`` marks scanners that send payloads / heavy traffic (fuzzers,
    active vuln scanners, aggressive port scanners); ``run_scanner`` gates those
    behind ``MOONMCP_ALLOW_INTRUSIVE`` on top of the scope check, mirroring the
    native intrusive tools.
    """

    fallback: str       # the native MoonMCP tool to use when this CLI is absent
    description: str
    install: str
    category: str       # subdomain / dns / http / crawl / content / port / vuln / tls / cms / url / decompile
    intrusive: bool = False


# Known tools MoonMCP can detect and drive. Curated for what actually ships on
# Kali (and the ProjectDiscovery/Go toolbox), each mapped to a native fallback so
# recon still works when the CLI is missing.
KNOWN_TOOLS: dict[str, ToolSpec] = {
    # --- subdomain / attack-surface ---
    "subfinder": ToolSpec("enumerate_subdomains", "Passive subdomain enumeration",
                          "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
                          "subdomain"),
    "amass": ToolSpec("enumerate_subdomains", "In-depth attack-surface mapping",
                      "go install github.com/owasp-amass/amass/v4/...@master", "subdomain"),
    "assetfinder": ToolSpec("enumerate_subdomains", "Find domains/subdomains",
                            "go install github.com/tomnomnom/assetfinder@latest", "subdomain"),
    "subjack": ToolSpec("takeover_check", "Subdomain-takeover checker",
                        "go install github.com/haccer/subjack@latest", "subdomain"),
    # --- dns ---
    "dnsx": ToolSpec("dns_lookup", "Fast DNS toolkit",
                     "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest", "dns"),
    "dnsrecon": ToolSpec("dns_lookup", "DNS enumeration/recon", "apt install dnsrecon", "dns"),
    "dnsenum": ToolSpec("dns_lookup", "DNS enumeration", "apt install dnsenum", "dns"),
    "asnmap": ToolSpec("host_intel", "ASN → CIDR mapping",
                       "go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest", "dns"),
    # --- http probe / fingerprint ---
    "httpx": ToolSpec("http_probe", "Fast HTTP prober/fingerprinter",
                      "go install github.com/projectdiscovery/httpx/cmd/httpx@latest", "http"),
    "whatweb": ToolSpec("fingerprint", "Web technology fingerprinter",
                        "apt install whatweb", "http"),
    "wafw00f": ToolSpec("waf_detect", "WAF/CDN fingerprinter", "pip install wafw00f", "http"),
    # --- crawl / url discovery ---
    "katana": ToolSpec("crawl", "Web crawler",
                       "go install github.com/projectdiscovery/katana/cmd/katana@latest", "crawl"),
    "hakrawler": ToolSpec("crawl", "Fast web crawler",
                          "go install github.com/hakluke/hakrawler@latest", "crawl"),
    "gospider": ToolSpec("crawl", "Web spider",
                         "go install github.com/jaeles-project/gospider@latest", "crawl"),
    "gau": ToolSpec("wayback_urls", "Fetch known URLs (getallurls)",
                    "go install github.com/lc/gau/v2/cmd/gau@latest", "url"),
    "waybackurls": ToolSpec("wayback_urls", "Fetch Wayback Machine URLs",
                            "go install github.com/tomnomnom/waybackurls@latest", "url"),
    "gowitness": ToolSpec("screenshot", "Web screenshot utility",
                          "go install github.com/sensepost/gowitness@latest", "http"),
    # --- content discovery / fuzzing (intrusive) ---
    "ffuf": ToolSpec("content_discovery", "Web fuzzer / content discovery",
                     "go install github.com/ffuf/ffuf/v2@latest", "content", intrusive=True),
    "feroxbuster": ToolSpec("content_discovery", "Recursive content discovery",
                            "apt install feroxbuster", "content", intrusive=True),
    "gobuster": ToolSpec("content_discovery", "Directory/DNS/vhost brute-forcer",
                         "apt install gobuster", "content", intrusive=True),
    "dirb": ToolSpec("content_discovery", "Web content scanner", "apt install dirb",
                     "content", intrusive=True),
    "arjun": ToolSpec("discover_parameters", "HTTP parameter discovery",
                      "pipx install arjun", "content", intrusive=True),
    # --- port / network (intrusive) ---
    "naabu": ToolSpec("port_scan", "SYN/CONNECT port scanner",
                      "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
                      "port", intrusive=True),
    "nmap": ToolSpec("port_scan", "Network mapper / port + service scanner",
                     "apt install nmap", "port", intrusive=True),
    "masscan": ToolSpec("port_scan", "Mass IP/port scanner", "apt install masscan",
                        "port", intrusive=True),
    # --- vulnerability scanners (intrusive) ---
    "nuclei": ToolSpec("(no native equivalent — template-based vuln scanner)",
                       "Template-based vulnerability scanner",
                       "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
                       "vuln", intrusive=True),
    "nikto": ToolSpec("(no native equivalent — web server scanner)", "Web-server vulnerability scanner",
                      "apt install nikto", "vuln", intrusive=True),
    "wpscan": ToolSpec("(no native equivalent — WordPress scanner)", "WordPress security scanner",
                       "gem install wpscan", "cms", intrusive=True),
    "sqlmap": ToolSpec("(no native equivalent — SQLi tool)", "Automatic SQL-injection tool",
                       "apt install sqlmap", "vuln", intrusive=True),
    "dalfox": ToolSpec("(no native equivalent — XSS scanner)", "XSS scanning/parameter analysis",
                       "go install github.com/hahwul/dalfox/v2@latest", "vuln", intrusive=True),
    # --- tls ---
    "sslscan": ToolSpec("tls_inspect", "TLS/SSL configuration scanner", "apt install sslscan", "tls"),
    "sslyze": ToolSpec("tls_inspect", "TLS/SSL analyzer", "pipx install sslyze", "tls"),
    "testssl.sh": ToolSpec("tls_inspect", "TLS/SSL tester", "apt install testssl.sh", "tls"),
    "tlsx": ToolSpec("tls_inspect", "TLS grabber/analyzer",
                     "go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest", "tls"),
    # --- binary / decompile ---
    "ilspycmd": ToolSpec("analyze_binary", "Headless .NET decompiler (ILSpy CLI)",
                         "dotnet tool install -g ilspycmd", "decompile"),
    "monodis": ToolSpec("analyze_binary", "Mono CIL disassembler", "apt install mono-utils",
                        "decompile"),
    # --- password / hash cracking (intrusive — brute-force) ---
    "hydra": ToolSpec("(no native equivalent — online password brute-forcer)",
                      "Online network password brute-forcer (SSH, FTP, HTTP, SMB…)",
                      "apt install hydra", "password", intrusive=True),
    "john": ToolSpec("jwt_crack", "Offline password hash cracker (John the Ripper)",
                     "apt install john", "password", intrusive=True),
    "hashcat": ToolSpec("jwt_crack", "GPU-accelerated hash cracker",
                        "apt install hashcat", "password", intrusive=True),
    "patator": ToolSpec("(no native equivalent — multi-protocol brute-forcer)",
                        "Multi-protocol brute-forcer framework",
                        "pipx install patator", "password", intrusive=True),
    "hash-identifier": ToolSpec("(no native equivalent — hash type identifier)",
                                 "Identify hash/credential type from a string",
                                 "apt install hash-identifier", "password"),
    # --- binary analysis / reverse engineering ---
    "radare2": ToolSpec("analyze_binary", "Reverse-engineering framework (disasm, decomp, debug)",
                        "apt install radare2", "binary"),
    "gdb": ToolSpec("analyze_binary", "GNU Debugger for dynamic binary analysis",
                    "apt install gdb", "binary"),
    "checksec": ToolSpec("analyze_binary", "Check binary hardening (NX, PIE, RELRO, stack canary)",
                         "apt install checksec", "binary"),
    "ghidra": ToolSpec("analyze_binary", "NSA reverse-engineering suite (decompiler)",
                       "apt install ghidra", "binary"),
    # --- forensics ---
    "binwalk": ToolSpec("analyze_binary", "Firmware/binary analysis & extraction",
                        "pipx install binwalk", "forensics"),
    "volatility3": ToolSpec("(no native equivalent — memory forensics)",
                            "Memory dump analysis framework (Volatility 3)",
                            "pipx install volatility3", "forensics"),
    "foremost": ToolSpec("(no native equivalent — file carver)",
                         "File carving & recovery from disk images",
                         "apt install foremost", "forensics"),
    "steghide": ToolSpec("(no native equivalent — steganography tool)",
                         "Steganography: embed/extract data in image/audio",
                         "apt install steghide", "forensics"),
    "exiftool": ToolSpec("(no native equivalent — metadata reader)",
                         "Read/write EXIF/metadata from files",
                         "apt install libimage-exiftool-perl", "forensics"),
    # --- network attack / post-exploitation (intrusive) ---
    "metasploit": ToolSpec("(no native equivalent — exploitation framework)",
                           "Metasploit exploitation framework (msfconsole)",
                           "apt install metasploit-framework", "post-ex", intrusive=True),
    "responder": ToolSpec("(no native equivalent — LLMNR/NBT-NS poisoner)",
                          "LLMNR/NBT-NS/mDNS poisoner for credential capture",
                          "apt install responder", "network", intrusive=True),
    "netexec": ToolSpec("(no native equivalent — network execution)",
                        "Network execution framework (successor to CrackMapExec)",
                        "pipx install netexec", "network", intrusive=True),
    "crackmapexec": ToolSpec("(no native equivalent — network execution)",
                             "Swiss-army-knife network execution (predecessor of netexec)",
                             "pipx install crackmapexec", "network", intrusive=True),
    "enum4linux": ToolSpec("(no native equivalent — SMB/NetBIOS enumerator)",
                           "Enumerate SMB/NetBIOS/RPC info from Windows hosts",
                           "apt install enum4linux", "network", intrusive=True),
    "enum4linux-ng": ToolSpec("(no native equivalent — SMB/NetBIOS enumerator)",
                              "enum4linux rewrite in Python (enhanced SMB enumeration)",
                              "pipx install enum4linux-ng", "network", intrusive=True),
    "evil-winrm": ToolSpec("(no native equivalent — WinRM shell)",
                           "PowerShell remoting shell for Windows targets",
                           "gem install evil-winrm", "post-ex", intrusive=True),
}


@dataclass
class CliResult:
    tool: str
    available: bool
    command: list[str] = field(default_factory=list)
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    parsed: object = None
    error: str | None = None
    fallback: str | None = None
    duration_ms: float = 0.0
    truncated: bool = False
    cleanup_confirmed: bool = True


# Tool names that commonly collide with a same-named Python console script.
# The real security tools are compiled Go binaries; the Python shims are text
# scripts with a ``#!.../python`` shebang.  We reject the shim to avoid a false
# "installed" reading (e.g. the ``httpx`` HTTP library vs ProjectDiscovery httpx).
_COLLIDING = {"httpx", "gau"}


def _is_python_shim(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            head = fh.read(128)
    except OSError:
        return False
    if head.startswith(b"\x7fELF"):
        return False  # a real compiled binary
    return head.startswith(b"#!") and b"python" in head.split(b"\n", 1)[0]


def tool_path(tool: str) -> str | None:
    path = shutil.which(tool)
    if path and tool in _COLLIDING and _is_python_shim(path):
        return None
    return path


def detect_tools() -> dict[str, dict]:
    """Return availability + metadata for every known tool."""

    out: dict[str, dict] = {}
    for name, spec in KNOWN_TOOLS.items():
        path = tool_path(name)
        out[name] = {
            "available": path is not None,
            "path": path,
            "description": spec.description,
            "native_fallback": spec.fallback,
            "install": spec.install,
            "category": spec.category,
            "intrusive": spec.intrusive,
        }
    return out


class _OutputLimitExceeded(Exception):
    """The combined raw stdout/stderr prefix is full."""


async def _settle_owned(task: asyncio.Future) -> bool:
    """Join an owned operation despite repeated caller cancellation.

    Subprocess acquisition must finish before we can recover its handle. This
    can exceed the requested timeout if the OS subprocess API itself stalls.
    We never abandon a possibly created child just to meet a return deadline.
    """

    cancelled = False
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            cancelled = True
        except Exception:
            # The owner retrieves the exception after joining the operation.
            break
    return cancelled


async def _cleanup_process(proc: asyncio.subprocess.Process,
                           tasks: list[asyncio.Task]) -> bool:
    """Kill the owned process group, then reap and drain within a 2s reserve."""

    loop = asyncio.get_running_loop()
    deadline = loop.time() + 2.0
    confirmed = True
    if proc.stdin is not None:
        try:
            proc.stdin.close()
        except (OSError, RuntimeError):
            confirmed = False
    try:
        if os.name == "posix":
            # The leader may already have exited while descendants retain its
            # pipes. Kill the session's group even when returncode is known.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError:
                confirmed = False
                if proc.returncode is None:
                    proc.kill()
        elif proc.returncode is None:
            proc.kill()
    except (OSError, RuntimeError):
        confirmed = False

    for task in tasks:
        if not task.done():
            task.cancel()
    # These are only our cancellable pipe readers/writer/waiter. Settling them
    # first avoids simultaneous reads when replacing capture with discard.
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)

    async def discard(stream: asyncio.StreamReader | None) -> None:
        if stream is not None:
            while await stream.read(16384):
                pass

    drains = [
        asyncio.create_task(discard(proc.stdout)),
        asyncio.create_task(discard(proc.stderr)),
        asyncio.create_task(proc.wait()),
    ]
    pending: set[asyncio.Task] = set()
    try:
        done, pending = await asyncio.wait(
            drains, timeout=max(0.0, deadline - loop.time()),
        )
        confirmed = confirmed and not pending
        for task in done:
            if task.cancelled() or task.exception() is not None:
                confirmed = False
    finally:
        if pending or not confirmed:
            # Last-resort release of asyncio's pipes/transport. This does not
            # count as confirmed process cleanup or descendant containment.
            transport = getattr(proc, "_transport", None)
            if transport is not None:
                try:
                    transport.close()
                except Exception:
                    pass
        for task in drains:
            if not task.done():
                task.cancel()
        await asyncio.gather(*drains, return_exceptions=True)
    return confirmed and proc.returncode is not None


async def run_tool(
    tool: str,
    args: list[str],
    *,
    stdin: str | None = None,
    timeout: float = 300.0,
    allow: bool = True,
    max_output_bytes: int = 1048576,
    scope_check: Callable[[str], bool] | None = None,
    targets: list[str] | None = None,
) -> CliResult:
    """Run a known CLI with scope, raw output and monotonic time bounds.

    Network-capable categories require explicit targets and a scope callback
    even for direct Python callers. This checks declared targets before lookup
    or spawn; it does not sandbox a CLI's redirects, plugins or other network
    behavior. Caller cancellation is re-raised only after owned startup and
    cleanup settle. Startup settlement can exceed timeout; execution otherwise
    has one deadline, followed by at most a 2s kill/reap/drain reserve.
    """

    spec = KNOWN_TOOLS.get(tool)
    fallback = spec.fallback if spec else None
    if not allow:
        return CliResult(tool=tool, available=False,
                         error="external tools disabled (MOONMCP_ALLOW_EXTERNAL_TOOLS=0)",
                         fallback=fallback)
    if spec is None:
        return CliResult(tool=tool, available=False, error="unknown_tool")
    try:
        valid_timeout = (not isinstance(timeout, bool) and isinstance(timeout, (int, float))
                         and math.isfinite(timeout) and timeout > 0)
    except OverflowError:
        valid_timeout = False
    if not valid_timeout:
        return CliResult(tool=tool, available=False, error="invalid_timeout", fallback=fallback)
    if (isinstance(max_output_bytes, bool) or not isinstance(max_output_bytes, int)
            or not 1 <= max_output_bytes <= 16 * 1024 * 1024):
        return CliResult(tool=tool, available=False, error="invalid_output_limit", fallback=fallback)
    if spec.category not in {"binary", "decompile"}:
        if scope_check is None or not targets:
            return CliResult(tool=tool, available=False, error="scope_required", fallback=fallback)
        try:
            allowed = all(isinstance(t, str) and bool(t.strip()) and scope_check(t)
                          for t in targets)
        except Exception:
            allowed = False
        if not allowed:
            return CliResult(tool=tool, available=False, error="out_of_scope", fallback=fallback)
    path = tool_path(tool)
    if path is None:
        return CliResult(tool=tool, available=False,
                         error=f"{tool} is not installed. Install with: {spec.install}",
                         fallback=fallback)

    cmd = [path, *args]
    loop = asyncio.get_running_loop()
    start = loop.time()
    deadline = start + timeout
    cancelled = False
    error: str | None = None
    truncated = False
    cleanup_confirmed = True
    out_b = bytearray()
    err_b = bytearray()
    retained = 0
    tasks: list[asyncio.Task] = []
    proc: asyncio.subprocess.Process | None = None
    spawn = asyncio.create_task(asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=os.name == "posix",
    ))
    try:
        proc = await asyncio.wait_for(
            asyncio.shield(spawn), timeout=max(0.0, deadline - loop.time()),
        )
    except asyncio.TimeoutError:
        error = f"timed out after {timeout:g}s"
    except asyncio.CancelledError:
        cancelled = True
    except Exception as exc:
        error = str(exc)

    # Neither timeout nor repeated cancellation may orphan a late spawn result.
    cancelled = await _settle_owned(spawn) or cancelled
    try:
        proc = spawn.result()
    except asyncio.CancelledError:
        cancelled = True
    except Exception as exc:
        error = error or str(exc)

    if proc is not None and error is None and not cancelled:
        async def capture(stream: asyncio.StreamReader | None, buf: bytearray) -> None:
            nonlocal retained
            if stream is None:
                return
            while True:
                chunk = await stream.read(16384)
                if not chunk:
                    return
                room = max_output_bytes - retained
                buf.extend(chunk[:room])
                retained += min(len(chunk), room)
                if len(chunk) > room:
                    raise _OutputLimitExceeded

        async def feed() -> None:
            if proc is None or proc.stdin is None:
                return
            try:
                payload = stdin.encode() if stdin is not None else b""
                for offset in range(0, len(payload), 16384):
                    proc.stdin.write(payload[offset:offset + 16384])
                    await proc.stdin.drain()
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                proc.stdin.close()

        tasks = [
            asyncio.create_task(capture(proc.stdout, out_b)),
            asyncio.create_task(capture(proc.stderr, err_b)),
            asyncio.create_task(feed()),
            asyncio.create_task(proc.wait()),
        ]
        work = asyncio.gather(*tasks)
        # If caller cancellation leaves this gather pending, cleanup still
        # owns every member; consume its eventual error to avoid lost warnings.

        def consume(future: asyncio.Future) -> None:
            if not future.cancelled():
                future.exception()

        work.add_done_callback(consume)
        try:
            await asyncio.wait_for(
                asyncio.shield(work), timeout=max(0.0, deadline - loop.time()),
            )
        except _OutputLimitExceeded:
            truncated = True
            error = "output_limit_exceeded"
        except asyncio.TimeoutError:
            error = f"timed out after {timeout:g}s"
        except asyncio.CancelledError:
            cancelled = True
        except Exception as exc:
            error = str(exc)

    if proc is not None:
        cleanup = asyncio.create_task(_cleanup_process(proc, tasks))
        cancelled = await _settle_owned(cleanup) or cancelled
        try:
            cleanup_confirmed = cleanup.result()
        except Exception:
            cleanup_confirmed = False
        if not cleanup_confirmed:
            error = error or "cleanup_unconfirmed"
        if error is None and proc.returncode != 0:
            error = "command_failed"

    if cancelled:
        raise asyncio.CancelledError
    return CliResult(
        tool=tool, available=True, command=cmd,
        exit_code=proc.returncode if proc is not None else None,
        stdout=out_b.decode("utf-8", errors="replace"),
        stderr=err_b.decode("utf-8", errors="replace"),
        error=error, fallback=fallback, truncated=truncated,
        cleanup_confirmed=cleanup_confirmed,
        duration_ms=round((loop.time() - start) * 1000, 1),
    )


def is_intrusive(tool: str) -> bool:
    """True if *tool* is a known intrusive scanner (gated like native intrusive tools)."""

    spec = KNOWN_TOOLS.get(tool)
    return bool(spec and spec.intrusive)


def tools_by_category() -> dict[str, list[dict]]:
    """Detected tools grouped by category (installed ones first within a group)."""

    detected = detect_tools()
    grouped: dict[str, list[dict]] = {}
    for name, meta in detected.items():
        grouped.setdefault(meta["category"], []).append({"name": name, **meta})
    for items in grouped.values():
        items.sort(key=lambda t: (not t["available"], t["name"]))
    return dict(sorted(grouped.items()))


def parse_jsonl(text: str) -> list[dict]:
    """Parse newline-delimited JSON (the output format of most PD tools)."""

    rows: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows
