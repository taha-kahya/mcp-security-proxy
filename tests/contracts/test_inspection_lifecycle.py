"""The proxy lifecycle with defenses enabled: discovery, execution, and delivery.

In-process, with a fake upstream that records whether it was ever called, so
"never dispatched" is asserted directly.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from mcp import types
from mcp.shared.exceptions import MCPError

from mcp_security_proxy.defenses.samples.call_budget import create
from mcp_security_proxy.sdk import (
    Capability,
    Context,
    Defense,
    Event,
    Operation,
    OperationStatus,
    Principal,
    Result,
    Signal,
    Stage,
    StateChange,
)
from mcp_security_proxy.services.log import DecisionRecord, DeliveryRecord, DiscoveryRecord
from mcp_security_proxy.services.state import (
    InMemoryStateStore,
    Scope,
    StateUnavailableError,
    TaskRef,
)
from tests.harness.control import ProxyUnderTest, build_proxy, routing_for
from tests.harness.defenses import ScriptedDefense, finds, raises
from tests.harness.fakes import FakeUpstream, MemorySink

POLICY: dict[str, Any] = {
    "schema_version": 1,
    "principals": {"alice": [{"tool": "server_a/*", "effect": "allow"}]},
}
ALICE = Principal(id="alice", authenticated_by="test")
ALICE_TASK = TaskRef("alice", "alice")


def _proxy(
    upstream: FakeUpstream, sink: MemorySink, *defenses: Defense, **options: Any
) -> ProxyUnderTest:
    return build_proxy(
        routing=routing_for({"server_a": ["read", "write"]}),
        upstreams={"server_a": upstream},
        policy=POLICY,
        audit=sink,
        defenses=defenses,
        tool_operations={"server_a/write": "write", "server_a/read": "read"},
        **options,
    )


async def test_execution_finding_blocks_before_dispatch_and_is_recorded() -> None:
    upstream, sink = FakeUpstream(), MemorySink()
    proxy = _proxy(upstream, sink, ScriptedDefense("check", finds("check.bad")))

    result = await proxy.orchestrator.call_tool(ALICE, "server_a__write", {"k": "v"})

    assert result.is_error and upstream.calls == []
    [decision] = sink.of_kind(DecisionRecord)
    assert decision.outcome == "block"
    assert decision.rule_refs == ("defense:check:check.bad",)
    assert decision.operation == "write"
    [inspection] = decision.inspections
    assert inspection.defense_id == "check" and inspection.finding_rule_ids == ("check.bad",)
    assert (await proxy.history.snapshot(ALICE_TASK)).operations == ()


async def test_failed_inspection_blocks_and_is_distinguishable_from_clean() -> None:
    upstream, sink = FakeUpstream(), MemorySink()
    proxy = _proxy(upstream, sink, ScriptedDefense("clean"), ScriptedDefense("broken", raises))

    result = await proxy.orchestrator.call_tool(ALICE, "server_a__read", {})

    assert result.is_error and upstream.calls == []
    [decision] = sink.of_kind(DecisionRecord)
    statuses = {i.defense_id: (i.status, i.detail) for i in decision.inspections}
    assert statuses == {
        "clean": ("completed", None),
        "broken": ("failed", "raised RuntimeError"),
    }


async def test_defense_sees_the_trusted_action_and_arguments() -> None:
    defense = ScriptedDefense("check")
    proxy = _proxy(FakeUpstream(), MemorySink(), defense)

    await proxy.orchestrator.call_tool(ALICE, "server_a__write", {"key": "k"})

    [event] = defense.seen_events
    assert event.action is not None and event.action.operation is Operation.WRITE
    assert event.payload["arguments"]["key"] == "k"
    assert defense.seen_contexts[0].principal == ALICE


async def test_allowed_calls_are_reserved_then_finished_in_history() -> None:
    proxy = _proxy(FakeUpstream(), MemorySink(), ScriptedDefense("check"))

    await proxy.orchestrator.call_tool(ALICE, "server_a__write", {})

    [record] = (await proxy.history.snapshot(ALICE_TASK)).operations
    assert record.status is OperationStatus.COMPLETED
    assert record.action.operation is Operation.WRITE


async def test_discovery_finding_hides_the_tool_from_listing_and_calling() -> None:
    async def flags_write(event: Event, context: Context) -> Result:
        if event.payload["name"] == "write":
            return await finds("direct.suspicious")(event, context)
        return Result.completed()

    upstream, sink = FakeUpstream(), MemorySink()
    discovery = ScriptedDefense("direct", flags_write, stages=frozenset({Stage.DISCOVERY}))
    proxy = _proxy(upstream, sink, discovery)

    tools = await proxy.orchestrator.list_tools(ALICE)
    with pytest.raises(MCPError) as hidden:
        await proxy.orchestrator.call_tool(ALICE, "server_a__write", {})

    assert [t.name for t in tools] == ["server_a__read"]
    [listing] = sink.of_kind(DiscoveryRecord)
    assert listing.hidden_by_inspection == ("server_a/write",)
    assert hidden.value.error.message == "Unknown tool: server_a__write"
    assert upstream.calls == []
    [decision] = sink.of_kind(DecisionRecord)
    assert decision.rule_refs == ("defense:direct:direct.suspicious",)


async def test_discovery_inspection_is_committed_once_per_tool_version_and_policy() -> None:
    """A repeat listing, and a call to a tool already seen in a listing,
    reuse that result instead of re-running the defense and re-committing a
    duplicate signal to History."""

    async def flags(event: Event, context: Context) -> Result:
        return Result.completed(signals=[Signal("seen", 1, "direct", event.payload["name"])])

    discovery = ScriptedDefense(
        "direct", flags, stages=frozenset({Stage.DISCOVERY}), produces=frozenset({"seen"})
    )
    proxy = _proxy(FakeUpstream(), MemorySink(), discovery)

    await proxy.orchestrator.list_tools(ALICE)
    await proxy.orchestrator.list_tools(ALICE)
    await proxy.orchestrator.call_tool(ALICE, "server_a__read", {})

    assert len(discovery.seen_events) == 2  # once each for "read" and "write", never again
    assert len((await proxy.history.snapshot(ALICE_TASK)).signals) == 2


async def test_delivery_finding_withholds_the_result_but_reports_that_the_call_ran() -> None:
    upstream, sink = FakeUpstream(), MemorySink()
    delivery = ScriptedDefense(
        "indirect", finds("indirect.injection"), stages=frozenset({Stage.BEFORE_DELIVERY})
    )
    proxy = _proxy(upstream, sink, delivery)

    result = await proxy.orchestrator.call_tool(ALICE, "server_a__write", {})

    assert upstream.calls == [("write", {})]
    assert result.is_error
    assert isinstance(result.content[0], types.TextContent)
    assert "The call was executed" in result.content[0].text
    [record] = sink.of_kind(DeliveryRecord)
    assert record.outcome == "block"
    assert record.rule_refs == ("defense:indirect:indirect.injection",)
    [event] = delivery.seen_events
    assert [block.type for block in event.content] == ["text"]


async def test_no_delivery_record_when_no_defense_inspects_results() -> None:
    sink = MemorySink()
    await _proxy(FakeUpstream(), sink).orchestrator.call_tool(ALICE, "server_a__read", {})
    assert sink.of_kind(DeliveryRecord) == []


async def test_private_state_changes_are_committed_for_the_next_call() -> None:
    async def counts(event: Event, context: Context) -> Result:
        seen = context.private_state.get("calls")
        return Result.completed(
            state_changes=[StateChange("calls", seen.version, (seen.value or 0) + 1)]
        )

    counter = ScriptedDefense("counter", counts, capabilities=frozenset({Capability.PRIVATE_STATE}))
    proxy = _proxy(FakeUpstream(), MemorySink(), counter)

    for _ in range(3):
        await proxy.orchestrator.call_tool(ALICE, "server_a__read", {})

    assert [c.private_state.get("calls").value for c in counter.seen_contexts] == [None, 1, 2]


class _BrokenState(InMemoryStateStore):
    async def read(self, scope: Scope, key: str) -> Any:
        raise StateUnavailableError("disk gone")


async def test_unavailable_state_refuses_the_call_before_dispatch() -> None:
    upstream = FakeUpstream()
    proxy = _proxy(upstream, MemorySink(), state=_BrokenState())

    with pytest.raises(MCPError) as exc_info:
        await proxy.orchestrator.call_tool(ALICE, "server_a__read", {})

    assert exc_info.value.error.code == types.INTERNAL_ERROR
    assert upstream.calls == []


async def test_in_flight_calls_count_against_the_budget_while_still_pending() -> None:
    release = asyncio.Event()

    async def slow() -> types.CallToolResult:
        await release.wait()
        return types.CallToolResult(content=[])

    upstream = FakeUpstream(slow)
    proxy = _proxy(upstream, MemorySink(), create({"max_operations": 2}))

    calls = [
        asyncio.create_task(proxy.orchestrator.call_tool(ALICE, "server_a__write", {}))
        for _ in range(5)
    ]
    while len(upstream.calls) < 2:
        await asyncio.sleep(0.01)
    blocked = [await call for call in calls[2:]]
    release.set()
    allowed = [await call for call in calls[:2]]

    assert all(r.is_error for r in blocked) and not any(r.is_error for r in allowed)
    assert len(upstream.calls) == 2
