"""Detection and safe invocation of external security CLIs.

Every wrapper follows the same contract: if the binary is missing, return a
result with ``available=False`` and a ``fallback`` hint rather than raising, so
the LLM can transparently fall back to MoonMCP's native capability.
"""

from __future__ import annotations

import asyncio
import json
import shutil
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


async def run_tool(
    tool: str,
    args: list[str],
    *,
    stdin: str | None = None,
    timeout: float = 300.0,
    allow: bool = True,
) -> CliResult:
    """Run ``tool args...`` capturing stdout/stderr with a hard timeout."""

    spec = KNOWN_TOOLS.get(tool)
    fallback = spec.fallback if spec else None
    if not allow:
        return CliResult(tool=tool, available=False,
                         error="external tools disabled (MOONMCP_ALLOW_EXTERNAL_TOOLS=0)",
                         fallback=fallback)
    path = tool_path(tool)
    if path is None:
        install = spec.install if spec else "(unknown)"
        return CliResult(tool=tool, available=False,
                         error=f"{tool} is not installed. Install with: {install}",
                         fallback=fallback)

    cmd = [path, *args]
    loop = asyncio.get_event_loop()
    start = loop.time()
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE if stdin is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except OSError as exc:
        return CliResult(tool=tool, available=True, command=cmd, error=str(exc), fallback=fallback)
    try:
        out_b, err_b = await asyncio.wait_for(
            proc.communicate(stdin.encode() if stdin is not None else None),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        try:
            proc.kill()
            await proc.wait()  # reap the killed child so no zombie/pipe leak
        except ProcessLookupError:
            pass
        return CliResult(tool=tool, available=True, command=cmd,
                         error=f"timed out after {timeout:.0f}s", fallback=fallback,
                         duration_ms=round((loop.time() - start) * 1000, 1))
    return CliResult(
        tool=tool,
        available=True,
        command=cmd,
        exit_code=proc.returncode,
        stdout=out_b.decode("utf-8", errors="replace"),
        stderr=err_b.decode("utf-8", errors="replace"),
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
