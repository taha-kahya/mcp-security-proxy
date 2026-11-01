"""Test helpers for defense developers: build an Event and a Context with fake
capabilities, then call `evaluate` directly, without running the proxy.

`make_context` grants exactly the capabilities the manifest declares, the
same way the Runner does, so a test fails if a defense uses a capability it
forgot to declare.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from mcp_security_proxy.sdk.actions import Action, Operation
from mcp_security_proxy.sdk.capabilities import (
    HistorySnapshot,
    OperationRecord,
    OperationStatus,
    PolicyView,
    PrivateState,
    RegistryView,
    ToolDefinition,
)
from mcp_security_proxy.sdk.context import Context, Grants
from mcp_security_proxy.sdk.events import ContentBlock, Direction, Event, Stage
from mcp_security_proxy.sdk.manifest import Capability, Manifest
from mcp_security_proxy.sdk.results import Signal
from mcp_security_proxy.sdk.types import Principal, ToolId

TEST_PRINCIPAL = Principal(id="test-principal", authenticated_by="test")
TEST_TASK = "test-task"
TEST_TOOL = ToolId("test_server", "test_tool")
TEST_ADAPTER = "test"

_DIRECTION_BY_STAGE = {
    Stage.DISCOVERY: Direction.SERVER_TO_CLIENT,
    Stage.BEFORE_EXECUTION: Direction.CLIENT_TO_SERVER,
    Stage.BEFORE_DELIVERY: Direction.SERVER_TO_CLIENT,
    Stage.LIFECYCLE: Direction.INTERNAL,
}


def action(operation: Operation) -> Action:
    return Action(operation, adapter_id=TEST_ADAPTER, adapter_version="1")


def make_event(
    stage: Stage = Stage.BEFORE_EXECUTION,
    *,
    tool_id: ToolId = TEST_TOOL,
    action: Action | None = None,
    payload: Mapping[str, Any] | None = None,
    content: Iterable[ContentBlock] = (),
    method: str = "tools/call",
) -> Event:
    return Event(
        event_id=uuid4().hex,
        correlation_id=uuid4().hex,
        stage=stage,
        direction=_DIRECTION_BY_STAGE[stage],
        method=method,
        server_id=tool_id.server_id,
        payload=payload or {},
        timestamp=datetime.now(UTC),
        content=tuple(content),
        tool_id=tool_id,
        action=action,
    )


@dataclass
class FakeRegistry:
    definitions: dict[ToolId, ToolDefinition] = field(default_factory=dict)
    actions: dict[ToolId, Action] = field(default_factory=dict)

    def current(self, tool_id: ToolId) -> ToolDefinition | None:
        return self.definitions.get(tool_id)

    def action(self, tool_id: ToolId, arguments: Mapping[str, Any]) -> Action:
        return self.actions.get(tool_id, Action.unknown(TEST_ADAPTER, "1"))


@dataclass
class FakePolicy:
    discoverable: frozenset[ToolId] = frozenset()
    version: str = "test-policy"

    def can_discover(self, tool_id: ToolId) -> bool:
        return tool_id in self.discoverable


def operation(
    tool_id: ToolId = TEST_TOOL,
    op: Operation = Operation.WRITE,
    status: OperationStatus = OperationStatus.COMPLETED,
) -> OperationRecord:
    return OperationRecord(
        operation_id=uuid4().hex,
        correlation_id=uuid4().hex,
        tool_id=tool_id,
        action=action(op),
        status=status,
        started_at=datetime.now(UTC),
    )


def history(*operations: OperationRecord, signals: Iterable[Signal] = ()) -> HistorySnapshot:
    return HistorySnapshot(
        task_id=TEST_TASK,
        version=len(operations),
        operations=operations,
        signals=tuple(signals),
    )


def make_context(
    manifest: Manifest,
    *,
    principal: Principal = TEST_PRINCIPAL,
    registry: RegistryView | None = None,
    history: HistorySnapshot | None = None,
    policy: PolicyView | None = None,
    private_state: PrivateState | None = None,
    signals: Iterable[Signal] = (),
    tool_version: str | None = None,
) -> Context:
    """Undeclared capabilities are not granted; passing one is a test bug."""
    supplied = {
        Capability.REGISTRY: registry,
        Capability.HISTORY: history,
        Capability.POLICY: policy,
        Capability.PRIVATE_STATE: private_state,
    }
    undeclared = {
        name
        for name, value in supplied.items()
        if value is not None and name not in manifest.required_capabilities
    }
    if undeclared:
        raise ValueError(f"manifest {manifest.id!r} does not declare {sorted(undeclared)}")

    granted = manifest.required_capabilities
    task_history = history or HistorySnapshot(task_id=TEST_TASK, version=0)
    return Context(
        principal=principal,
        task_id=TEST_TASK,
        policy_version=policy.version if policy else "test-policy",
        state_version=task_history.version,
        tool_version=tool_version,
        signals=tuple(s for s in signals if s.type in manifest.required_signals),
        grants=Grants(
            registry=(registry or FakeRegistry()) if Capability.REGISTRY in granted else None,
            history=task_history if Capability.HISTORY in granted else None,
            policy=(policy or FakePolicy()) if Capability.POLICY in granted else None,
            private_state=(
                (private_state or PrivateState()) if Capability.PRIVATE_STATE in granted else None
            ),
        ),
    )
