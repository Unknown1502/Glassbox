"""FastMCP server exposing the typed read-only forensic tool surface.

This is the externally-attachable face of ``tools.py``. An MCP client (Claude
Desktop, Cline, an SDK agent) sees *only* the typed read-only tools — there is
no ``execute_shell`` and no write/delete tool to register, because none exist.
The surface a model can reach is exactly the surface defined here, and that is
the Criterion-4 guarantee, demonstrable by listing the tools.

Run:  ``python -m glassbox.mcp_server --case cases/case01``

If the ``mcp`` package is not installed, the module still runs in
``--list`` mode (printing the surface) so the guarantee is inspectable without
any dependency.
"""

from __future__ import annotations

import argparse
import json
import os

from .claimchain import ClaimChain
from .tools import ForensicTools, TOOL_SPECS


def list_surface() -> dict:
    return {
        "server": "glassbox-readonly-forensics",
        "write_tools": [],
        "shell_tools": [],
        "tools": TOOL_SPECS,
        "guarantee": "typed, read-only; no write/delete/shell primitive exists",
    }


def build_server(case_dir: str, ledger_path: str):
    """Construct a FastMCP server. Requires the `mcp` package."""
    from mcp.server.fastmcp import FastMCP  # type: ignore

    ledger = ClaimChain(ledger_path)
    tools = ForensicTools(case_dir, ledger)
    server = FastMCP("glassbox-readonly-forensics")

    def _register(spec):
        name = spec["name"]

        def _handler(**kwargs):
            # Every call is provenance-logged and returns a parsed summary.
            return tools.call(name, **kwargs)

        _handler.__name__ = name
        _handler.__doc__ = spec["desc"]
        server.tool(name=name, description=spec["desc"])(_handler)

    for spec in TOOL_SPECS:
        _register(spec)
    return server


def main(argv: list[str] | None = None) -> int:
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    p = argparse.ArgumentParser(prog="glassbox.mcp_server")
    p.add_argument("--case", default=os.path.join(here, "cases", "case01"))
    p.add_argument("--ledger", default=os.path.join(here, "out", "mcp_ledger.jsonl"))
    p.add_argument("--list", action="store_true", help="print the tool surface and exit")
    args = p.parse_args(argv)

    if args.list:
        print(json.dumps(list_surface(), indent=2))
        return 0

    try:
        server = build_server(args.case, args.ledger)
    except Exception as e:
        print(f"[mcp] FastMCP not available ({e}); printing surface instead.\n")
        print(json.dumps(list_surface(), indent=2))
        return 0
    print("[mcp] glassbox-readonly-forensics serving typed read-only tools "
          f"({len(TOOL_SPECS)} tools, 0 write/shell). Ctrl-C to stop.")
    server.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
