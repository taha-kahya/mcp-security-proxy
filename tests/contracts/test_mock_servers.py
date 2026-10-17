"""Contract tests for the mock MCP servers, run as real subprocesses.

Parametrized across both servers (which expose an identical tool contract,
including the deliberately colliding `send_message` tool name by design) and
both transports, to prove each server behaves identically regardless of how
it's connected to.
"""

from __future__ import annotations

import socket
import subprocess
import sys
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.client.streamable_http import streamable_http_client

SERVER_IDS = ["server_a", "server_b"]
TRANSPORTS = ["stdio", "streamable-http"]


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_until_listening(host: str, port: int, timeout_seconds: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f"mock server did not start listening on {host}:{port}")


@asynccontextmanager
async def mock_server_session(
    server_id: str, transport: str, audit_log_path: Path
) -> AsyncIterator[ClientSession]:
    if transport == "stdio":
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", f"mock_servers.{server_id}", "--audit-log", str(audit_log_path)],
        )
        async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
            await session.initialize()
            yield session
        return

    host, port = "127.0.0.1", _free_port()
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            f"mock_servers.{server_id}",
            "--transport",
            "streamable-http",
            "--host",
            host,
            "--port",
            str(port),
            "--audit-log",
            str(audit_log_path),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        _wait_until_listening(host, port)
        url = f"http://{host}:{port}/mcp"
        async with streamable_http_client(url) as streams:
            read, write = streams[0], streams[1]
            async with ClientSession(read, write) as session:
                await session.initialize()
                yield session
    finally:
        proc.terminate()
        proc.wait(timeout=5)


@pytest.mark.parametrize("transport", TRANSPORTS)
@pytest.mark.parametrize("server_id", SERVER_IDS)
async def test_discovery_lists_expected_tools(
    server_id: str, transport: str, tmp_path: Path
) -> None:
    async with mock_server_session(server_id, transport, tmp_path / "audit.jsonl") as session:
        tools = await session.list_tools()
        assert {t.name for t in tools.tools} == {"read_record", "write_record", "send_message"}


@pytest.mark.parametrize("transport", TRANSPORTS)
@pytest.mark.parametrize("server_id", SERVER_IDS)
async def test_write_then_read_round_trips(server_id: str, transport: str, tmp_path: Path) -> None:
    async with mock_server_session(server_id, transport, tmp_path / "audit.jsonl") as session:
        write_result = await session.call_tool("write_record", {"key": "k", "value": "v"})
        assert not write_result.is_error

        read_result = await session.call_tool("read_record", {"key": "k"})
        assert not read_result.is_error
        assert read_result.content[0].text == "v"  # type: ignore[union-attr]


@pytest.mark.parametrize("transport", TRANSPORTS)
@pytest.mark.parametrize("server_id", SERVER_IDS)
async def test_read_unknown_key_is_a_tool_error(
    server_id: str, transport: str, tmp_path: Path
) -> None:
    async with mock_server_session(server_id, transport, tmp_path / "audit.jsonl") as session:
        result = await session.call_tool("read_record", {"key": "missing"})
        assert result.is_error


@pytest.mark.parametrize("transport", TRANSPORTS)
@pytest.mark.parametrize("server_id", SERVER_IDS)
async def test_write_and_send_are_audited_with_server_id(
    server_id: str, transport: str, tmp_path: Path
) -> None:
    audit_log_path = tmp_path / "audit.jsonl"
    async with mock_server_session(server_id, transport, audit_log_path) as session:
        await session.call_tool("write_record", {"key": "k", "value": "v"})
        await session.call_tool("send_message", {"recipient": "bob", "message": "hi"})
        await session.call_tool("read_record", {"key": "k"})

    entries = [
        line for line in audit_log_path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    assert len(entries) == 2  # read_record must not be audited; write/send must be
    for entry in entries:
        assert f'"server_id": "{server_id}"' in entry
