"""End-to-end tests for the V3 acceptance criteria, against the real proxy
process and both mock servers.

- The sample defense is added and enabled through its entry point and a
  config file alone: nothing in core names it.
- Concurrent calls cannot bypass the sample history rule: the mock
  server's own audit log shows exactly the budgeted number of writes.
- History survives a restart with SQLite state.
- A failed inspection is distinguishable from a clean one in the audit log.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest
from mcp import types

from tests.harness.client import (
    PROXY_AUDIT_LOG,
    build_proxy_config,
    mock_server_entry,
    proxy_session,
)

CONFIGS = ["stdio", "streamable-http"]
BUDGET = 3
TOOL_OPERATIONS = {
    "server_a/read_record": "read",
    "server_a/write_record": "write",
    "server_b/write_record": "write",
}


def _budget(max_operations: int = BUDGET) -> dict[str, Any]:
    return {"id": "call_budget", "settings": {"max_operations": max_operations}}


def _config(tmp_path: Path, transport: str, **options: Any) -> dict[str, Any]:
    servers = [
        mock_server_entry("server_a", tmp_path / "a.jsonl", transport),
        mock_server_entry("server_b", tmp_path / "b.jsonl", transport),
    ]
    options.setdefault("defenses", [_budget()])
    options.setdefault("tool_operations", TOOL_OPERATIONS)
    return build_proxy_config(servers, transport, tmp_path, **options)


def _jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _decisions(tmp_path: Path) -> list[dict[str, Any]]:
    return [r for r in _jsonl(tmp_path / PROXY_AUDIT_LOG) if r["kind"] == "decision"]


async def _write(session: Any, n: int) -> types.CallToolResult:
    result: types.CallToolResult = await session.call_tool(
        "server_a__write_record", {"key": f"k{n}", "value": "v"}
    )
    return result


@pytest.mark.parametrize("transport", CONFIGS)
async def test_budget_blocks_writes_beyond_the_cap_across_servers(
    transport: str, tmp_path: Path
) -> None:
    async with proxy_session(_config(tmp_path, transport), tmp_path / "config.yaml") as session:
        allowed = [await _write(session, n) for n in range(BUDGET - 1)]
        on_b = await session.call_tool("server_b__write_record", {"key": "b", "value": "v"})
        reads = [await session.call_tool("server_a__read_record", {"key": "k0"})]
        blocked = await _write(session, 99)

    assert not any(r.is_error for r in [*allowed, on_b, *reads])
    assert blocked.is_error
    assert len(_jsonl(tmp_path / "a.jsonl")) == BUDGET - 1
    assert len(_jsonl(tmp_path / "b.jsonl")) == 1
    last = _decisions(tmp_path)[-1]
    assert last["outcome"] == "block"
    assert last["rule_refs"] == ["defense:call_budget:call_budget.exceeded"]


@pytest.mark.parametrize("transport", CONFIGS)
async def test_concurrent_calls_cannot_exceed_the_budget(transport: str, tmp_path: Path) -> None:
    async with proxy_session(_config(tmp_path, transport), tmp_path / "config.yaml") as session:
        results = await asyncio.gather(*(_write(session, n) for n in range(10)))

    assert sum(not r.is_error for r in results) == BUDGET
    assert len(_jsonl(tmp_path / "a.jsonl")) == BUDGET
    outcomes = [d["outcome"] for d in _decisions(tmp_path)]
    assert outcomes.count("allow") == BUDGET and outcomes.count("block") == 10 - BUDGET


async def test_budget_survives_a_restart_with_sqlite_state(tmp_path: Path) -> None:
    config = _config(tmp_path, "stdio", state_path=tmp_path / "state.sqlite3")
    async with proxy_session(config, tmp_path / "config.yaml") as session:
        for n in range(BUDGET):
            assert not (await _write(session, n)).is_error

    async with proxy_session(config, tmp_path / "config.yaml") as session:
        assert (await _write(session, 99)).is_error

    assert len(_jsonl(tmp_path / "a.jsonl")) == BUDGET


async def test_disabled_defense_does_not_run(tmp_path: Path) -> None:
    disabled = _budget(max_operations=0) | {"enabled": False}
    async with proxy_session(
        _config(tmp_path, "stdio", defenses=[disabled]), tmp_path / "config.yaml"
    ) as session:
        assert not (await _write(session, 0)).is_error

    assert _decisions(tmp_path)[0]["inspections"] == []


async def test_unclassified_tools_count_against_the_budget(tmp_path: Path) -> None:
    async with proxy_session(
        _config(tmp_path, "stdio", tool_operations=None, defenses=[_budget(1)]),
        tmp_path / "config.yaml",
    ) as session:
        first = await session.call_tool("server_a__read_record", {"key": "missing"})
        second = await session.call_tool("server_a__read_record", {"key": "missing"})

    [d1, d2] = _decisions(tmp_path)
    assert d1["operation"] == "unknown" and d1["outcome"] == "allow"
    assert first.is_error  # the mock tool's own error: the call reached the server
    assert second.is_error and d2["outcome"] == "block"


async def test_audit_distinguishes_clean_and_not_applicable_inspections(tmp_path: Path) -> None:
    async with proxy_session(_config(tmp_path, "stdio"), tmp_path / "config.yaml") as session:
        await _write(session, 0)
        await session.call_tool("server_a__read_record", {"key": "k0"})

    write, read = _decisions(tmp_path)
    assert write["inspections"][0]["status"] == "completed"
    assert read["inspections"][0]["status"] == "not_applicable"
    assert {d["inspections"][0]["defense_id"] for d in (write, read)} == {"call_budget"}
