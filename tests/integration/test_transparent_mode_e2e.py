"""End-to-end tests for transparent mode (0023), against the real proxy
process fronting one mock server.

- The agent sees the upstream's bare tool names, tool order, and JSON
  definitions, and the upstream's own server name and version.
- Request `_meta` reaches the upstream unchanged, and the audit record holds
  only a masked view of it plus the allowlisted keys.
- Policy still applies, under the bare name.
- The default mode is unchanged: prefixed names, the proxy's own name, and no
  `_meta` forwarded.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest
from mcp import ClientSession, types
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.shared.exceptions import MCPError

from tests.harness.client import (
    DEFAULT_PRINCIPAL,
    PROXY_AUDIT_LOG,
    REPO_ROOT,
    build_proxy_config,
    mock_server_entry,
    proxy_session,
)

SERVER_ID = "server_probe"
CONFIGS = ["stdio", "streamable-http"]
SYNTHETIC_SECRET = "sk-test-0000-synthetic-secret-do-not-log"


def _config(tmp_path: Path, transport: str = "stdio", **options: Any) -> dict[str, Any]:
    transparent = options.pop("transparent", True)
    allowlist = options.pop("audit_meta_allowlist", None)
    config = build_proxy_config(
        [mock_server_entry(SERVER_ID, tmp_path / "upstream.jsonl", transport)],
        transport,
        tmp_path,
        **options,
    )
    if transparent:
        config["transparent"] = True
    if allowlist:
        config["audit_meta_allowlist"] = allowlist
    return config


def _jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _tool_json(tools: list[types.Tool]) -> list[str]:
    """Each definition as the JSON text a client would see, in list order."""
    return [json.dumps(t.model_dump(by_alias=True, exclude_none=True)) for t in tools]


async def _upstream_tools(tmp_path: Path) -> list[types.Tool]:
    """The tool list the mock server sends when no proxy is in front of it."""
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", f"fixtures.mock_servers.{SERVER_ID}", "--audit-log", str(tmp_path / "x.jsonl")],
        cwd=str(REPO_ROOT),
    )
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        return (await session.list_tools()).tools


@pytest.mark.parametrize("transport", CONFIGS)
async def test_tools_keep_their_bare_names_and_order(transport: str, tmp_path: Path) -> None:
    async with proxy_session(_config(tmp_path, transport), tmp_path / "config.yaml") as session:
        names = [tool.name for tool in (await session.list_tools()).tools]
        result = await session.call_tool("alpha_note", {"text": "hello"})

    assert names == ["zeta_search", "alpha_note", "observe_meta"]
    assert not result.is_error
    assert _jsonl(tmp_path / "upstream.jsonl")[0]["tool_name"] == "alpha_note"


async def test_tool_definitions_match_the_upstream_json_exactly(tmp_path: Path) -> None:
    upstream = await _upstream_tools(tmp_path)
    async with proxy_session(_config(tmp_path), tmp_path / "config.yaml") as session:
        proxied = (await session.list_tools()).tools

    assert _tool_json(proxied) == _tool_json(upstream)
    # The nested schema is not alphabetical, so a sorted rewrite would differ.
    search = next(tool for tool in proxied if tool.name == "zeta_search")
    assert list(search.input_schema["$defs"]["Scope"]["properties"]) == [
        "zone",
        "limits",
        "labels",
    ]


async def test_initialize_reports_the_upstream_name_and_version(tmp_path: Path) -> None:
    async with proxy_session(_config(tmp_path), tmp_path / "config.yaml") as session:
        initialized = session.initialize_result

    assert initialized is not None
    assert (initialized.server_info.name, initialized.server_info.version) == (SERVER_ID, "3.4.5")
    assert initialized.instructions is None


async def test_default_mode_keeps_prefixed_names_and_the_proxy_identity(tmp_path: Path) -> None:
    config = _config(tmp_path, transparent=False)
    async with proxy_session(config, tmp_path / "config.yaml") as session:
        names = [tool.name for tool in (await session.list_tools()).tools]
        initialized = session.initialize_result

    assert names == [
        f"{SERVER_ID}__{name}" for name in ("zeta_search", "alpha_note", "observe_meta")
    ]
    assert initialized is not None
    assert initialized.server_info.name == "mcp-security-proxy"


async def test_request_meta_reaches_the_upstream_unchanged(tmp_path: Path) -> None:
    meta = {"eval_id": "run-7", "nested": {"b": 1, "a": [1, 2]}, "flag": True}
    async with proxy_session(_config(tmp_path), tmp_path / "config.yaml") as session:
        result = await session.call_tool("observe_meta", {}, meta=meta)

    assert not result.is_error
    (entry,) = _jsonl(tmp_path / "upstream.jsonl")
    assert entry["arguments"]["meta"] == meta


async def test_default_mode_does_not_forward_request_meta(tmp_path: Path) -> None:
    config = _config(tmp_path, transparent=False)
    async with proxy_session(config, tmp_path / "config.yaml") as session:
        await session.call_tool(f"{SERVER_ID}__observe_meta", {}, meta={"eval_id": "run-7"})

    (entry,) = _jsonl(tmp_path / "upstream.jsonl")
    assert "eval_id" not in entry["arguments"]["meta"]
    assert "meta" not in _decision(tmp_path)


def _decision(tmp_path: Path) -> dict[str, Any]:
    (record,) = [r for r in _jsonl(tmp_path / PROXY_AUDIT_LOG) if r["kind"] == "decision"]
    return record


async def test_audit_record_masks_meta_except_allowlisted_keys(tmp_path: Path) -> None:
    config = _config(tmp_path, audit_meta_allowlist=["eval_id"])
    meta = {"eval_id": "run-7", "token": SYNTHETIC_SECRET}
    async with proxy_session(config, tmp_path / "config.yaml") as session:
        await session.call_tool("observe_meta", {}, meta=meta)

    record = _decision(tmp_path)
    assert record["meta"]["keys"] == ["eval_id", "token"]
    assert record["meta"]["values"] == {"eval_id": "run-7"}
    assert SYNTHETIC_SECRET not in (tmp_path / PROXY_AUDIT_LOG).read_text(encoding="utf-8")


async def test_audit_log_names_the_progress_token_by_its_wire_key(tmp_path: Path) -> None:
    config = _config(tmp_path, audit_meta_allowlist=["progressToken"])
    async with proxy_session(config, tmp_path / "config.yaml") as session:
        await session.call_tool("observe_meta", {}, meta={"progress_token": "tok-1"})

    record = _decision(tmp_path)
    assert record["meta"]["keys"] == ["progressToken"]
    assert record["meta"]["values"] == {"progressToken": "tok-1"}


async def test_audit_record_masks_all_meta_by_default(tmp_path: Path) -> None:
    async with proxy_session(_config(tmp_path), tmp_path / "config.yaml") as session:
        await session.call_tool("observe_meta", {}, meta={"eval_id": "run-7"})

    record = _decision(tmp_path)
    assert record["meta"]["keys"] == ["eval_id"]
    assert record["meta"]["values"] == {}
    assert "run-7" not in (tmp_path / PROXY_AUDIT_LOG).read_text(encoding="utf-8")


async def test_a_call_without_meta_leaves_the_decision_record_unchanged(tmp_path: Path) -> None:
    async with proxy_session(_config(tmp_path), tmp_path / "config.yaml") as session:
        await session.call_tool("alpha_note", {"text": "hi"})

    assert "meta" not in _decision(tmp_path)


async def test_policy_still_blocks_a_tool_under_its_bare_name(tmp_path: Path) -> None:
    policy: dict[str, Any] = {
        "schema_version": 1,
        "principals": {
            DEFAULT_PRINCIPAL: [
                {"tool": f"{SERVER_ID}/alpha_note", "effect": "require_approval"},
                {"tool": f"{SERVER_ID}/observe_meta", "effect": "allow"},
            ]
        },
    }
    async with proxy_session(_config(tmp_path, policy=policy), tmp_path / "config.yaml") as session:
        names = {tool.name for tool in (await session.list_tools()).tools}
        blocked = await session.call_tool("alpha_note", {"text": "hi"})
        with pytest.raises(MCPError) as hidden:
            await session.call_tool("zeta_search", {"query": "q", "scope": {}})

    assert names == {"alpha_note", "observe_meta"}
    assert blocked.is_error
    assert isinstance(blocked.content[0], types.TextContent)
    assert "requires approval" in blocked.content[0].text
    assert hidden.value.error.message == "Unknown tool: zeta_search"
    assert _jsonl(tmp_path / "upstream.jsonl") == []

    decisions = [r for r in _jsonl(tmp_path / PROXY_AUDIT_LOG) if r["kind"] == "decision"]
    assert [(r["requested_tool"], r["tool_id"], r["outcome"]) for r in decisions] == [
        ("alpha_note", f"{SERVER_ID}/alpha_note", "require_approval"),
        ("zeta_search", f"{SERVER_ID}/zeta_search", "block"),
    ]
