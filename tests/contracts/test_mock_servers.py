"""Contract tests for the mock MCP servers, run over stdio as real subprocesses.

Parametrized across both servers since they expose an identical tool contract
(including the deliberately colliding `send_message` tool name) by design.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

SERVER_IDS = ["server_a", "server_b"]


def _server_params(server_id: str, audit_log_path: Path) -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", f"mock_servers.{server_id}", "--audit-log", str(audit_log_path)],
    )


@pytest.mark.parametrize("server_id", SERVER_IDS)
async def test_discovery_lists_expected_tools(server_id: str, tmp_path: Path) -> None:
    params = _server_params(server_id, tmp_path / "audit.jsonl")
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        tools = await session.list_tools()
        assert {t.name for t in tools.tools} == {"read_record", "write_record", "send_message"}


@pytest.mark.parametrize("server_id", SERVER_IDS)
async def test_write_then_read_round_trips(server_id: str, tmp_path: Path) -> None:
    params = _server_params(server_id, tmp_path / "audit.jsonl")
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        write_result = await session.call_tool("write_record", {"key": "k", "value": "v"})
        assert not write_result.is_error

        read_result = await session.call_tool("read_record", {"key": "k"})
        assert not read_result.is_error
        assert read_result.content[0].text == "v"  # type: ignore[union-attr]


@pytest.mark.parametrize("server_id", SERVER_IDS)
async def test_read_unknown_key_is_a_tool_error(server_id: str, tmp_path: Path) -> None:
    params = _server_params(server_id, tmp_path / "audit.jsonl")
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        result = await session.call_tool("read_record", {"key": "missing"})
        assert result.is_error


@pytest.mark.parametrize("server_id", SERVER_IDS)
async def test_write_and_send_are_audited_with_server_id(server_id: str, tmp_path: Path) -> None:
    audit_log_path = tmp_path / "audit.jsonl"
    params = _server_params(server_id, audit_log_path)
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        await session.call_tool("write_record", {"key": "k", "value": "v"})
        await session.call_tool("send_message", {"recipient": "bob", "message": "hi"})
        await session.call_tool("read_record", {"key": "k"})

    entries = [
        line for line in audit_log_path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    assert len(entries) == 2  # read_record must not be audited; write/send must be
    for entry in entries:
        assert f'"server_id": "{server_id}"' in entry
