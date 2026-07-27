"""``python -m moonmcp`` / ``moonmcp`` console entry point.

Besides serving over stdio (the default), this exposes two subcommands so a
**shell-based agent** (e.g. Strix's command-execution tool, a CI step, or any
tool without an MCP client) can drive MoonMCP's tools and get JSON back:

* ``moonmcp tools``            — list the exposed tools (respects MOONMCP_PROFILE).
* ``moonmcp call <tool> …``    — invoke one tool non-interactively, print JSON.
"""

from __future__ import annotations

import argparse
import sys

from . import __version__


def _coerce(v: str) -> object:
    """Best-effort scalar coercion for ``--arg k=v`` values."""

    import json

    low = v.strip().lower()
    if low in ("true", "false"):
        return low == "true"
    if low in ("null", "none"):
        return None
    try:
        return int(v)
    except ValueError:
        pass
    try:
        return float(v)
    except ValueError:
        pass
    if v[:1] in "[{":  # inline JSON list/object
        try:
            return json.loads(v)
        except json.JSONDecodeError:
            pass
    return v


def _cmd_tools(as_json: bool) -> int:
    import json

    from .server import mcp

    tools = sorted(mcp._tool_manager.list_tools(), key=lambda t: t.name)
    if as_json:
        print(json.dumps([{"name": t.name,
                           "description": " ".join((t.description or "").split())[:200]}
                          for t in tools], indent=2))
    else:
        for t in tools:
            first = " ".join((t.description or "").split())[:96]
            print(f"{t.name:28} {first}")
        print(f"\n{len(tools)} tools exposed.", file=sys.stderr)
    return 0


def _cmd_call(tool: str, json_args: str | None, kv_args: list[str]) -> int:
    import asyncio
    import json

    from .server import mcp

    registry = {t.name: t for t in mcp._tool_manager.list_tools()}
    if tool not in registry:
        print(json.dumps({"error": "unknown_tool",
                          "detail": f"{tool!r} is not exposed (check MOONMCP_PROFILE)",
                          "known": sorted(registry)}, indent=2))
        return 2

    kwargs: dict = {}
    if json_args:
        try:
            parsed = json.loads(json_args)
        except json.JSONDecodeError as exc:
            print(json.dumps({"error": "bad_json", "detail": str(exc)}))
            return 2
        if not isinstance(parsed, dict):
            print(json.dumps({"error": "bad_json", "detail": "--json must be a JSON object"}))
            return 2
        kwargs.update(parsed)
    for kv in kv_args:
        if "=" not in kv:
            print(json.dumps({"error": "bad_arg", "detail": f"expected K=V, got {kv!r}"}))
            return 2
        k, v = kv.split("=", 1)
        kwargs[k] = _coerce(v)

    fn = registry[tool].fn
    try:
        result = asyncio.run(fn(**kwargs))
    except TypeError as exc:  # bad argument names/shape
        print(json.dumps({"error": "bad_args", "detail": str(exc)}))
        return 2
    except Exception as exc:  # noqa: BLE001 - surface, don't crash the shell caller
        print(json.dumps({"error": "call_failed", "detail": f"{type(exc).__name__}: {exc}"}))
        return 1
    print(json.dumps(result, default=str, indent=2))
    # A structured error from the tool itself is still exit 0 (the call ran).
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="moonmcp",
        description="MoonMCP — a scope-aware bug-bounty & reconnaissance MCP server.",
    )
    parser.add_argument("--version", action="version", version=f"MoonMCP {__version__}")
    parser.add_argument(
        "--check", action="store_true",
        help="Print detected capabilities and exit (does not start the server).",
    )
    sub = parser.add_subparsers(dest="cmd")
    p_tools = sub.add_parser("tools", help="List the exposed MCP tools (respects MOONMCP_PROFILE).")
    p_tools.add_argument("--json", action="store_true", help="Emit JSON.")
    p_call = sub.add_parser("call", help="Invoke one tool non-interactively and print JSON.")
    p_call.add_argument("tool", help="Tool name (see `moonmcp tools`).")
    p_call.add_argument("--json", dest="json_args", metavar="OBJ",
                        help="JSON object of arguments, e.g. '{\"target\":\"x\"}'.")
    p_call.add_argument("--arg", action="append", default=[], metavar="K=V",
                        help="A single argument as key=value (repeatable).")
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

    if args.cmd == "tools":
        return _cmd_tools(args.json)
    if args.cmd == "call":
        return _cmd_call(args.tool, args.json_args, args.arg)

    # Default: serve over stdio. Import lazily so --version/--check/tools stay fast.
    from .server import run

    run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
