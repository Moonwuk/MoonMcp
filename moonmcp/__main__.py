"""``python -m moonmcp`` / ``moonmcp`` console entry point."""

from __future__ import annotations

import argparse
import sys

from . import __version__


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="moonmcp",
        description="MoonMCP — a scope-aware bug-bounty & reconnaissance MCP server.",
    )
    parser.add_argument("--version", action="version", version=f"MoonMCP {__version__}")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Print detected capabilities and exit (does not start the server).",
    )
    args = parser.parse_args(argv)

    if args.check:
        import json

        from .context import build_context
        from .external import cli
        from .net import dns as dnsmod

        ctx = build_context()
        report = {
            "version": __version__,
            "scope": ctx.scope.entries(),
            "scope_enforced": ctx.settings.enforce_scope,
            "intrusive_allowed": ctx.settings.allow_intrusive,
            "dnspython": dnsmod.dnspython_available(),
            "external_tools": {k: v["available"] for k, v in cli.detect_tools().items()},
        }
        print(json.dumps(report, indent=2))
        return 0

    # Import lazily so --version/--check stay fast and dependency-light.
    from .server import run

    run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
