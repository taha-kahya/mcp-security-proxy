"""Re-approve tool definitions by forgetting their approved versions (plan MR T2).

    python -m mcp_security_proxy.app.approve_definitions --config config.yaml server_a/read_record
    python -m mcp_security_proxy.app.approve_definitions --config config.yaml --all

The next time the proxy discovers a forgotten tool, the definition the server
lists then becomes its approved version, so `temporal_definition_drift`
stops reporting the change. Run it with the proxy stopped: the SQLite state
file allows one process at a time. With the in-memory backend there is
nothing to forget; every start approves what it sees.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from mcp_security_proxy.app.config import ConfigError, load_config
from mcp_security_proxy.app.security import open_state
from mcp_security_proxy.sdk import ToolId
from mcp_security_proxy.services.registry import DefinitionBaselines


async def _forget(config_path: Path, tool_ids: list[ToolId] | None) -> list[str]:
    config = load_config(config_path)
    state = open_state(config.state)
    try:
        return await DefinitionBaselines(state).forget(tool_ids)
    finally:
        await state.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Forget approved tool definitions")
    parser.add_argument("--config", type=Path, required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("tools", nargs="*", default=[], metavar="SERVER/TOOL")
    group.add_argument("--all", action="store_true")
    args = parser.parse_args(argv)
    if not args.all and not args.tools:
        parser.error("name at least one SERVER/TOOL, or --all")
    try:
        tool_ids = None if args.all else [ToolId.parse(text) for text in args.tools]
        forgotten = asyncio.run(_forget(args.config, tool_ids))
    except (ConfigError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    for key in forgotten:
        print(f"forgot {key}")
    if not forgotten:
        print("nothing to forget")
    return 0


if __name__ == "__main__":
    sys.exit(main())
