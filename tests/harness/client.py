"""Scripted, deterministic MCP client used to drive proxy acceptance tests.

Spawns the real proxy process (over stdio or Streamable HTTP, matching
Config A/B), exactly as a real agent would, rather than importing proxy
internals directly. No LLM is involved: call sequences are exact and
assertions are on exact responses/errors.
"""

from __future__ import annotations

import asyncio
import socket
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import yaml
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.client.streamable_http import streamable_http_client

from mcp_security_proxy.core.proxy.transport.streamable_http_client import wait_until_listening

REPO_ROOT = Path(__file__).resolve().parents[2]


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def mock_server_entry(server_id: str, audit_log_path: Path, transport: str) -> dict[str, Any]:
    module = f"mock_servers.{server_id}"
    if transport == "stdio":
        return {
            "id": server_id,
            "command": sys.executable,
            "args": ["-m", module, "--audit-log", str(audit_log_path)],
        }

    port = free_port()
    return {
        "id": server_id,
        "transport": "streamable-http",
        "command": sys.executable,
        "args": [
            "-m",
            module,
            "--transport",
            "streamable-http",
            "--port",
            str(port),
            "--audit-log",
            str(audit_log_path),
        ],
        "host": "127.0.0.1",
        "port": port,
        "url": f"http://127.0.0.1:{port}/mcp",
    }


def build_proxy_config(servers: list[dict[str, Any]], agent_transport: str) -> dict[str, Any]:
    config: dict[str, Any] = {"agent_transport": agent_transport, "servers": servers}
    if agent_transport == "streamable-http":
        config["agent_host"] = "127.0.0.1"
        config["agent_port"] = free_port()
    return config


@asynccontextmanager
async def proxy_session(config: dict[str, Any], config_path: Path) -> AsyncIterator[ClientSession]:
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")

    if config["agent_transport"] == "stdio":
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "mcp_security_proxy.app.main", "--config", str(config_path)],
            cwd=str(REPO_ROOT),
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                yield session
        return

    host, port = config["agent_host"], config["agent_port"]
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "mcp_security_proxy.app.main",
        "--config",
        str(config_path),
        cwd=str(REPO_ROOT),
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        await asyncio.to_thread(wait_until_listening, host, port)
        url = f"http://{host}:{port}/mcp"
        async with streamable_http_client(url) as streams:
            read, write = streams[0], streams[1]
            async with ClientSession(read, write) as session:
                await session.initialize()
                yield session
    finally:
        process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=5)
        except TimeoutError:
            process.kill()
            await process.wait()
