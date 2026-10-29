from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

from mcp_security_proxy.app.config import load_config
from mcp_security_proxy.app.wiring import build_app


async def _run(config_path: Path) -> None:
    config = load_config(config_path)
    async with build_app(config) as app:
        await app.serve()


def main() -> None:
    parser = argparse.ArgumentParser(description="MCP security proxy")
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    asyncio.run(_run(args.config))


if __name__ == "__main__":
    main()
