"""MoonMCP — a scope-aware bug-bounty & reconnaissance MCP server.

MoonMCP exposes a curated set of reconnaissance and OSINT capabilities over the
Model Context Protocol.  Its guiding principles:

* **Works out of the box.**  Every core tool is implemented on the Python
  standard library, so the server is useful the moment it starts — no
  ``nuclei``/``httpx``/``subfinder`` binaries required.
* **Augments, never depends.**  When popular CLI tools *are* installed, MoonMCP
  detects and wraps them; when they are absent it degrades gracefully instead of
  erroring out.
* **Scope-first & safe by default.**  Every packet-sending tool is gated by an
  authorization scope.  Intrusive scans are opt-in and rate-limited.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
