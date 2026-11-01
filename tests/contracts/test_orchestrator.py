"""Lifecycle tests for the proxy orchestrator, using in-memory fakes.

No subprocesses: a fake upstream records whether it was ever called, so
"never dispatched" is asserted directly rather than inferred.
"""

from __future__ import annotations

import asyncio

import pytest
from mcp import types
from mcp.shared.exceptions import MCPError

from mcp_security_proxy.core.proxy.codec.jsonrpc import unknown_tool_error
from mcp_security_proxy.core.proxy.orchestrator import ProxyOrchestrator
from mcp_security_proxy.core.proxy.routing.correlation import CorrelationTracker
from mcp_security_proxy.sdk import Principal
from mcp_security_proxy.services.log import (
    DecisionRecord,
    OutcomeRecord,
)
from tests.harness.control import build_proxy, routing_for
from tests.harness.fakes import FakeUpstream, MemorySink

ALICE = Principal(id="alice", authenticated_by="test")


POLICY = {
    "schema_version": 1,
    "principals": {
        "alice": [
            {"tool": "server_a/read", "effect": "allow"},
            {"tool": "server_a/send", "effect": "require_approval"},
        ]
    },
}


def _orchestrator(
    upstream: FakeUpstream, sink: MemorySink
) -> tuple[ProxyOrchestrator, CorrelationTracker]:
    proxy = build_proxy(
        routing=routing_for({"server_a": ["read", "send", "hidden"]}),
        upstreams={"server_a": upstream},
        policy=POLICY,
        audit=sink,
    )
    return proxy.orchestrator, proxy.correlation


async def test_discovery_lists_only_tools_the_principal_may_discover() -> None:
    sink = MemorySink()
    orchestrator, _ = _orchestrator(FakeUpstream(), sink)

    tools = await orchestrator.list_tools(ALICE)

    assert sorted(t.name for t in tools) == ["server_a__read", "server_a__send"]
    assert len(sink.records) == 1


async def test_allowed_call_is_dispatched_and_both_records_share_a_correlation_id() -> None:
    upstream, sink = FakeUpstream(), MemorySink()
    orchestrator, correlation = _orchestrator(upstream, sink)

    result = await orchestrator.call_tool(ALICE, "server_a__read", {"key": "k"})

    assert not result.is_error
    assert upstream.calls == [("read", {"key": "k"})]
    [decision] = sink.of_kind(DecisionRecord)
    [outcome] = sink.of_kind(OutcomeRecord)
    assert decision.outcome == "allow"
    assert outcome.status == "completed" and outcome.tool_error is False
    assert outcome.correlation_id == decision.correlation_id
    assert outcome.decision_id == decision.decision_id
    assert correlation.in_flight_for_server("server_a") == []


async def test_hidden_tool_error_is_identical_to_nonexistent_tool_error() -> None:
    upstream, sink = FakeUpstream(), MemorySink()
    orchestrator, _ = _orchestrator(upstream, sink)

    with pytest.raises(MCPError) as hidden:
        await orchestrator.call_tool(ALICE, "server_a__hidden", {})
    with pytest.raises(MCPError) as missing:
        await orchestrator.call_tool(ALICE, "server_a__missing", {})

    assert hidden.value.error == unknown_tool_error("server_a__hidden").error
    assert missing.value.error == unknown_tool_error("server_a__missing").error
    assert upstream.calls == []
    assert [r.outcome for r in sink.of_kind(DecisionRecord)] == ["block", "block"]
    assert sink.of_kind(OutcomeRecord) == []


async def test_require_approval_returns_a_tool_error_without_dispatching() -> None:
    upstream, sink = FakeUpstream(), MemorySink()
    orchestrator, _ = _orchestrator(upstream, sink)

    result = await orchestrator.call_tool(ALICE, "server_a__send", {})

    assert result.is_error
    assert upstream.calls == []
    [decision] = sink.of_kind(DecisionRecord)
    assert decision.outcome == "require_approval"
    assert isinstance(result.content[0], types.TextContent)
    assert decision.decision_id in result.content[0].text


async def test_unwritable_audit_refuses_the_call_before_dispatch() -> None:
    upstream, sink = FakeUpstream(), MemorySink()
    sink.failing = True
    orchestrator, _ = _orchestrator(upstream, sink)

    with pytest.raises(MCPError) as exc_info:
        await orchestrator.call_tool(ALICE, "server_a__read", {})
    with pytest.raises(MCPError):
        await orchestrator.list_tools(ALICE)

    assert exc_info.value.error.code == types.INTERNAL_ERROR
    assert upstream.calls == []


async def test_tool_level_error_is_a_completed_outcome_flagged_as_tool_error() -> None:
    async def tool_error() -> types.CallToolResult:
        return types.CallToolResult(content=[], is_error=True)

    sink = MemorySink()
    orchestrator, _ = _orchestrator(FakeUpstream(tool_error), sink)

    await orchestrator.call_tool(ALICE, "server_a__read", {})

    [outcome] = sink.of_kind(OutcomeRecord)
    assert outcome.status == "completed" and outcome.tool_error is True


@pytest.mark.parametrize(
    ("code", "expected_status"),
    [
        (types.CONNECTION_CLOSED, "unknown"),
        (types.REQUEST_TIMEOUT, "unknown"),
        (types.INVALID_PARAMS, "failed"),
    ],
)
async def test_upstream_protocol_errors_map_to_outcome_status(
    code: int, expected_status: str
) -> None:
    sink = MemorySink()
    orchestrator, correlation = _orchestrator(FakeUpstream(MCPError(code=code, message="x")), sink)

    with pytest.raises(MCPError):
        await orchestrator.call_tool(ALICE, "server_a__read", {})

    [outcome] = sink.of_kind(OutcomeRecord)
    assert outcome.status == expected_status
    assert correlation.in_flight_for_server("server_a") == []


async def test_cancelled_call_still_records_an_unknown_outcome() -> None:
    started = asyncio.Event()

    async def hang() -> types.CallToolResult:
        started.set()
        await asyncio.sleep(10)
        raise AssertionError("unreachable")

    sink = MemorySink()
    orchestrator, _ = _orchestrator(FakeUpstream(hang), sink)

    task = asyncio.create_task(orchestrator.call_tool(ALICE, "server_a__read", {}))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    [outcome] = sink.of_kind(OutcomeRecord)
    assert outcome.status == "unknown"


async def test_outcome_write_failure_does_not_hide_the_upstream_result() -> None:
    sink = MemorySink()
    upstream_calls = 0

    async def succeed_then_break_audit() -> types.CallToolResult:
        nonlocal upstream_calls
        upstream_calls += 1
        sink.failing = True
        return types.CallToolResult(content=[])

    orchestrator, _ = _orchestrator(FakeUpstream(succeed_then_break_audit), sink)

    result = await orchestrator.call_tool(ALICE, "server_a__read", {})

    assert not result.is_error
    assert upstream_calls == 1
