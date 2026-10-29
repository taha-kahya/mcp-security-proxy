"""End-to-end tests for the V2 acceptance criteria (Identity + Policy -> Guard,
and Log), against the real proxy process and both mock servers.

- A denied call never reaches the mock server: checked against the mock
  server's own audit log, not the proxy's claims.
- Hidden tools cannot be called by guessing their names, and answer exactly
  like nonexistent tools.
- Identity boundaries hold: principals only see and call their own tools,
  unauthenticated HTTP requests are rejected, and a principal claimed in the
  payload is ignored.
- Decision records are correct, masked, and the proxy fails closed when they
  cannot be written.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

import httpx2
import pytest
from mcp import types
from mcp.shared.exceptions import MCPError

from mcp_security_proxy.services.policy import load_policy
from tests.harness.client import (
    DEFAULT_PRINCIPAL,
    PROXY_AUDIT_LOG,
    PROXY_MODULE_ARGS,
    REPO_ROOT,
    build_proxy_config,
    mock_server_entry,
    proxy_session,
    running_http_proxy,
    write_config,
)

CONFIGS = ["stdio", "streamable-http"]
SYNTHETIC_SECRET = "sk-test-0000-synthetic-secret-do-not-log"

# server_a fully allowed; server_b partly visible, send_message needs approval,
# and server_b/slow_write is hidden.
MIXED_POLICY: dict[str, Any] = {
    "schema_version": 1,
    "principals": {
        DEFAULT_PRINCIPAL: [
            {"tool": "server_a/*", "effect": "allow"},
            {"tool": "server_b/read_record", "effect": "allow"},
            {"tool": "server_b/send_message", "effect": "require_approval"},
        ]
    },
}


def _mock_servers(tmp_path: Path, transport: str) -> list[dict[str, Any]]:
    return [
        mock_server_entry("server_a", tmp_path / "a.jsonl", transport),
        mock_server_entry("server_b", tmp_path / "b.jsonl", transport),
    ]


def _mock_audit_entries(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _proxy_audit_records(tmp_path: Path) -> list[dict[str, Any]]:
    return _mock_audit_entries(tmp_path / PROXY_AUDIT_LOG)


@pytest.mark.parametrize("transport", CONFIGS)
async def test_discovery_shows_only_permitted_tools(transport: str, tmp_path: Path) -> None:
    config = build_proxy_config(
        _mock_servers(tmp_path, transport), transport, tmp_path, policy=MIXED_POLICY
    )
    async with proxy_session(config, tmp_path / "config.yaml") as session:
        names = {tool.name for tool in (await session.list_tools()).tools}

    assert names == {
        "server_a__read_record",
        "server_a__write_record",
        "server_a__send_message",
        "server_a__slow_write",
        "server_b__read_record",
        "server_b__send_message",
    }


@pytest.mark.parametrize("transport", CONFIGS)
async def test_hidden_tool_answers_exactly_like_a_nonexistent_tool_and_never_runs(
    transport: str, tmp_path: Path
) -> None:
    b_log = tmp_path / "b.jsonl"
    config = build_proxy_config(
        _mock_servers(tmp_path, transport), transport, tmp_path, policy=MIXED_POLICY
    )
    async with proxy_session(config, tmp_path / "config.yaml") as session:
        with pytest.raises(MCPError) as hidden:
            await session.call_tool("server_b__write_record", {"key": "k", "value": "v"})
        with pytest.raises(MCPError) as nonexistent:
            await session.call_tool("server_b__no_such_tool", {"key": "k", "value": "v"})

    assert hidden.value.error.code == nonexistent.value.error.code == types.INVALID_PARAMS
    assert hidden.value.error.message == "Unknown tool: server_b__write_record"
    assert nonexistent.value.error.message == "Unknown tool: server_b__no_such_tool"
    assert _mock_audit_entries(b_log) == []


@pytest.mark.parametrize("transport", CONFIGS)
async def test_approval_required_tool_is_blocked_without_side_effects(
    transport: str, tmp_path: Path
) -> None:
    b_log = tmp_path / "b.jsonl"
    config = build_proxy_config(
        _mock_servers(tmp_path, transport), transport, tmp_path, policy=MIXED_POLICY
    )
    async with proxy_session(config, tmp_path / "config.yaml") as session:
        result = await session.call_tool(
            "server_b__send_message", {"recipient": "bob", "message": "hi"}
        )

    assert result.is_error
    assert isinstance(result.content[0], types.TextContent)
    assert "requires approval" in result.content[0].text
    assert _mock_audit_entries(b_log) == []


@pytest.mark.parametrize("transport", CONFIGS)
async def test_decision_and_outcome_records_are_correct_and_masked(
    transport: str, tmp_path: Path
) -> None:
    config = build_proxy_config(
        _mock_servers(tmp_path, transport), transport, tmp_path, policy=MIXED_POLICY
    )
    async with proxy_session(config, tmp_path / "config.yaml") as session:
        await session.list_tools()
        await session.call_tool("server_a__write_record", {"key": "k", "value": SYNTHETIC_SECRET})
        with pytest.raises(MCPError):
            await session.call_tool("server_b__slow_write", {"key": "k", "value": "v"})

    records = _proxy_audit_records(tmp_path)
    assert [r["kind"] for r in records] == ["discovery", "decision", "outcome", "decision"]
    discovery, allowed, outcome, blocked = records

    expected_auth = "static_config" if transport == "stdio" else "bearer_token"
    policy_version = load_policy(tmp_path / "policy.yaml").version
    assert {r["principal_id"] for r in records} == {DEFAULT_PRINCIPAL}
    assert {r["authenticated_by"] for r in records} == {expected_auth}
    assert discovery["visible_tool_count"] == 6

    assert allowed["outcome"] == "allow"
    assert allowed["tool_id"] == "server_a/write_record"
    assert allowed["rule_refs"] == [f"policy:{DEFAULT_PRINCIPAL}:server_a/*"]
    assert allowed["policy_version"] == policy_version
    assert allowed["arguments"]["keys"] == ["key", "value"]

    assert outcome["status"] == "completed"
    assert outcome["correlation_id"] == allowed["correlation_id"]
    assert outcome["decision_id"] == allowed["decision_id"]

    assert blocked["outcome"] == "block"
    assert blocked["rule_refs"] == ["policy:default_deny"]

    assert SYNTHETIC_SECRET not in (tmp_path / PROXY_AUDIT_LOG).read_text(encoding="utf-8")


@pytest.mark.parametrize("transport", CONFIGS)
@pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0, reason="root ignores file permissions"
)
async def test_unwritable_audit_log_blocks_calls_before_dispatch(
    transport: str, tmp_path: Path
) -> None:
    a_log = tmp_path / "a.jsonl"
    config = build_proxy_config(_mock_servers(tmp_path, transport), transport, tmp_path)
    async with proxy_session(config, tmp_path / "config.yaml") as session:
        (tmp_path / PROXY_AUDIT_LOG).chmod(0o444)
        with pytest.raises(MCPError) as exc_info:
            await session.call_tool("server_a__write_record", {"key": "k", "value": "v"})

    assert exc_info.value.error.code == types.INTERNAL_ERROR
    assert _mock_audit_entries(a_log) == []


async def test_principals_only_see_and_call_their_own_tools(tmp_path: Path) -> None:
    """HTTP only: stdio has exactly one configured principal per process (0011)."""
    a_log, b_log = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    policy = {
        "schema_version": 1,
        "principals": {
            "alice": [{"tool": "server_a/*", "effect": "allow"}],
            "bob": [{"tool": "server_b/*", "effect": "allow"}],
        },
    }
    config = build_proxy_config(
        _mock_servers(tmp_path, "streamable-http"),
        "streamable-http",
        tmp_path,
        policy=policy,
        principals_by_token={"alice-token": "alice", "bob-token": "bob"},
    )
    config_path = tmp_path / "config.yaml"

    async with proxy_session(config, config_path, bearer_token="alice-token") as alice:
        alice_tools = {tool.name for tool in (await alice.list_tools()).tools}
        with pytest.raises(MCPError) as crossing:
            await alice.call_tool("server_b__write_record", {"key": "k", "value": "alice"})
        own = await alice.call_tool("server_a__write_record", {"key": "k", "value": "alice"})

    assert {name.split("__")[0] for name in alice_tools} == {"server_a"}
    assert crossing.value.error.code == types.INVALID_PARAMS
    assert not own.is_error
    assert _mock_audit_entries(b_log) == []
    assert len(_mock_audit_entries(a_log)) == 1

    principals = {r["principal_id"] for r in _proxy_audit_records(tmp_path)}
    assert principals == {"alice"}


async def test_principal_claimed_in_the_payload_is_ignored(tmp_path: Path) -> None:
    b_log = tmp_path / "b.jsonl"
    policy = {
        "schema_version": 1,
        "principals": {
            "alice": [{"tool": "server_a/*", "effect": "allow"}],
            "admin": [{"tool": "server_b/*", "effect": "allow"}],
        },
    }
    config = build_proxy_config(
        _mock_servers(tmp_path, "streamable-http"),
        "streamable-http",
        tmp_path,
        policy=policy,
        principals_by_token={"alice-token": "alice", "admin-token": "admin"},
    )
    async with proxy_session(config, tmp_path / "config.yaml", bearer_token="alice-token") as s:
        with pytest.raises(MCPError):
            await s.call_tool(
                "server_b__write_record",
                {"key": "k", "value": "v"},
                meta={"principal": "admin", "client_id": "admin"},  # type: ignore[typeddict-unknown-key]
            )

    assert _mock_audit_entries(b_log) == []
    assert {r["principal_id"] for r in _proxy_audit_records(tmp_path)} == {"alice"}


@pytest.mark.parametrize(
    ("headers", "expected_status"),
    [
        ({}, 401),
        ({"Authorization": "Bearer wrong-token"}, 401),
        ({"Authorization": "Basic dGVzdDp0ZXN0"}, 401),
        ({"Authorization": "Bearer test-agent-token"}, 200),
    ],
)
async def test_http_listener_requires_a_valid_bearer_token(
    headers: dict[str, str], expected_status: int, tmp_path: Path
) -> None:
    config = build_proxy_config(
        _mock_servers(tmp_path, "streamable-http"), "streamable-http", tmp_path
    )
    initialize = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": types.LATEST_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "raw-http-probe", "version": "0"},
        },
    }
    async with running_http_proxy(config, tmp_path / "config.yaml") as url:
        async with httpx2.AsyncClient(timeout=10) as client:
            response = await client.post(
                url,
                json=initialize,
                headers={"Accept": "application/json, text/event-stream", **headers},
            )

    assert response.status_code == expected_status


async def test_proxy_refuses_to_start_with_a_policy_naming_unknown_tools(
    tmp_path: Path,
) -> None:
    policy = {
        "schema_version": 1,
        "principals": {DEFAULT_PRINCIPAL: [{"tool": "server_z/*", "effect": "allow"}]},
    }
    config = build_proxy_config(_mock_servers(tmp_path, "stdio"), "stdio", tmp_path, policy=policy)
    config_path = tmp_path / "config.yaml"
    write_config(config, config_path)

    process = await asyncio.create_subprocess_exec(
        sys.executable,
        *PROXY_MODULE_ARGS,
        str(config_path),
        cwd=str(REPO_ROOT),
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await asyncio.wait_for(process.communicate(), timeout=30)

    assert process.returncode != 0
    assert b"policy rules match no discovered tool: server_z/*" in stderr
