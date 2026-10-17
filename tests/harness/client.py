"""Scripted, deterministic MCP client used to drive proxy acceptance tests.

Spawns the real proxy process over stdio (Config A), exactly as a real agent
would, rather than importing proxy internals directly. No LLM is involved:
call sequences are exact and assertions are on exact responses/errors.
"""

from __future__ import annotations

import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import yaml
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

REPO_ROOT = Path(__file__).resolve().parents[2]


def build_stdio_proxy_config(servers: list[dict[str, Any]]) -> dict[str, Any]:
    return {"agent_transport": "stdio", "servers": servers}


def mock_server_entry(server_id: str, audit_log_path: Path) -> dict[str, Any]:
    module = f"mock_servers.{server_id}"
    return {
        "id": server_id,
        "command": sys.executable,
        "args": ["-m", module, "--audit-log", str(audit_log_path)],
    }


@asynccontextmanager
async def proxy_session(config: dict[str, Any], config_path: Path) -> AsyncIterator[ClientSession]:
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "mcp_security_proxy.app.main", "--config", str(config_path)],
        cwd=str(REPO_ROOT),
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield session
