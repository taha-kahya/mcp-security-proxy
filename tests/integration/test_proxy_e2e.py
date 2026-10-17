"""End-to-end integration tests for the proxy over stdio (Config A).

Verifies the V1 acceptance criteria: discovery and calls work across both
mock servers, errors and cancellations behave correctly, and no request is
ever routed to the wrong server -- verified against each server's independent
audit log, not just the proxy's own responses.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from tests.harness.client import build_stdio_proxy_config, mock_server_entry, proxy_session


def _read_audit_entries(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


async def test_discovery_merges_both_servers_with_disambiguated_names(tmp_path: Path) -> None:
    config = build_stdio_proxy_config(
        [
            mock_server_entry("server_a", tmp_path / "a.jsonl"),
            mock_server_entry("server_b", tmp_path / "b.jsonl"),
        ]
    )
    async with proxy_session(config, tmp_path / "config.yaml") as session:
        tools = await session.list_tools()
        names = {t.name for t in tools.tools}

    for server_id in ("server_a", "server_b"):
        for bare_name in ("read_record", "write_record", "send_message", "slow_write"):
            assert f"{server_id}__{bare_name}" in names


async def test_calls_route_to_correct_server_despite_name_collision(tmp_path: Path) -> None:
    a_log, b_log = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    config = build_stdio_proxy_config(
        [mock_server_entry("server_a", a_log), mock_server_entry("server_b", b_log)]
    )
    async with proxy_session(config, tmp_path / "config.yaml") as session:
        r_a = await session.call_tool(
            "server_a__send_message", {"recipient": "bob", "message": "hi"}
        )
        r_b = await session.call_tool(
            "server_b__send_message", {"recipient": "carol", "message": "yo"}
        )

    assert not r_a.is_error
    assert not r_b.is_error

    a_entries = _read_audit_entries(a_log)
    b_entries = _read_audit_entries(b_log)
    assert len(a_entries) == 1
    assert len(b_entries) == 1
    assert '"server_id": "server_a"' in a_entries[0]
    assert '"recipient": "bob"' in a_entries[0]
    assert '"server_id": "server_b"' in b_entries[0]
    assert '"recipient": "carol"' in b_entries[0]


async def test_unknown_tool_name_errors_without_touching_either_server(tmp_path: Path) -> None:
    a_log, b_log = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    config = build_stdio_proxy_config(
        [mock_server_entry("server_a", a_log), mock_server_entry("server_b", b_log)]
    )
    async with proxy_session(config, tmp_path / "config.yaml") as session:
        try:
            await session.call_tool("server_a__nonexistent", {})
            raised = False
        except Exception:
            raised = True

    assert raised
    assert _read_audit_entries(a_log) == []
    assert _read_audit_entries(b_log) == []


async def test_tool_level_error_passes_through_unchanged(tmp_path: Path) -> None:
    config = build_stdio_proxy_config(
        [
            mock_server_entry("server_a", tmp_path / "a.jsonl"),
            mock_server_entry("server_b", tmp_path / "b.jsonl"),
        ]
    )
    async with proxy_session(config, tmp_path / "config.yaml") as session:
        result = await session.call_tool("server_a__read_record", {"key": "missing"})

    assert result.is_error


async def test_cancellation_mid_call_does_not_complete_the_write(tmp_path: Path) -> None:
    a_log = tmp_path / "a.jsonl"
    config = build_stdio_proxy_config(
        [mock_server_entry("server_a", a_log), mock_server_entry("server_b", tmp_path / "b.jsonl")]
    )
    async with proxy_session(config, tmp_path / "config.yaml") as session:
        task = asyncio.create_task(
            session.call_tool(
                "server_a__slow_write", {"key": "k", "value": "v", "delay_seconds": 5.0}
            )
        )
        await asyncio.sleep(0.3)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

        # the proxy and its connection to server_a must still be usable afterward
        result = await session.call_tool("server_a__write_record", {"key": "k2", "value": "v2"})
        assert not result.is_error

    await asyncio.sleep(0.2)
    assert _read_audit_entries(a_log) == [
        entry for entry in _read_audit_entries(a_log) if "slow_write" not in entry
    ]


async def test_dead_upstream_connection_fails_cleanly_without_affecting_other_server(
    tmp_path: Path,
) -> None:
    flaky_log = tmp_path / "flaky.jsonl"
    a_log = tmp_path / "a.jsonl"
    config = build_stdio_proxy_config(
        [
            mock_server_entry("server_a", a_log),
            {
                "id": "flaky",
                "command": sys.executable,
                "args": [
                    "-m",
                    "tests.integration.flaky_server_script",
                    "--audit-log",
                    str(flaky_log),
                ],
            },
        ]
    )
    async with proxy_session(config, tmp_path / "config.yaml") as session:
        first = await session.call_tool("flaky__crash_after_response", {"key": "k", "value": "v"})
        assert not first.is_error

        await asyncio.sleep(0.3)  # let the flaky server actually exit

        raised = False
        try:
            await session.call_tool("flaky__crash_after_response", {"key": "k2", "value": "v2"})
        except Exception:
            raised = True
        assert raised

        # server_a's connection must be entirely unaffected
        still_ok = await session.call_tool("server_a__write_record", {"key": "kk", "value": "vv"})
        assert not still_ok.is_error
