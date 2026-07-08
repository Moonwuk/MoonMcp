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

# Known tools -> (native MoonMCP fallback tool, one-line description, install hint)
KNOWN_TOOLS: dict[str, tuple[str, str, str]] = {
    "subfinder": ("subdomains", "Passive subdomain enumeration",
                  "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    "httpx": ("http_probe", "Fast HTTP prober/fingerprinter",
              "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"),
    "nuclei": ("(no native equivalent — template-based vuln scanner)", "Template-based vulnerability scanner",
               "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
    "naabu": ("port_scan", "SYN/CONNECT port scanner",
              "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"),
    "nmap": ("port_scan", "Network mapper / port + service scanner", "apt install nmap"),
    "katana": ("well_known / wayback_urls", "Web crawler",
               "go install github.com/projectdiscovery/katana/cmd/katana@latest"),
    "ffuf": ("content_discovery", "Web fuzzer / content discovery",
             "go install github.com/ffuf/ffuf/v2@latest"),
    "gau": ("wayback_urls", "Fetch known URLs (getallurls)",
            "go install github.com/lc/gau/v2/cmd/gau@latest"),
    "dnsx": ("dns_lookup", "Fast DNS toolkit",
             "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest"),
    "amass": ("subdomains", "In-depth attack-surface mapping",
              "go install github.com/owasp-amass/amass/v4/...@master"),
    "waybackurls": ("wayback_urls", "Fetch Wayback Machine URLs",
                    "go install github.com/tomnomnom/waybackurls@latest"),
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
    for name, (fallback, desc, install) in KNOWN_TOOLS.items():
        path = tool_path(name)
        out[name] = {
            "available": path is not None,
            "path": path,
            "description": desc,
            "native_fallback": fallback,
            "install": install,
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

    fallback = KNOWN_TOOLS.get(tool, (None, "", ""))[0]
    if not allow:
        return CliResult(tool=tool, available=False,
                         error="external tools disabled (MOONMCP_ALLOW_EXTERNAL_TOOLS=0)",
                         fallback=fallback)
    path = tool_path(tool)
    if path is None:
        install = KNOWN_TOOLS.get(tool, (None, "", "(unknown)"))[2]
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
