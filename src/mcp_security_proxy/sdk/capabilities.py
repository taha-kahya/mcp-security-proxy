"""Read-only capability interfaces and the snapshots they expose to defenses.

Defenses never receive administrative access: they can look up tool
definitions and semantics, read their task's history, and query policy, but
not change any of them. Every view is already bound to the caller's
principal and task.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any, Protocol

from mcp_security_proxy.sdk.actions import Action
from mcp_security_proxy.sdk.frozen import freeze
from mcp_security_proxy.sdk.results import Signal
from mcp_security_proxy.sdk.types import ToolId


@dataclass(frozen=True)
class ToolDefinition:
    """A tool definition as the server sent it. `version` is a hash of its
    canonical form, so any change to the definition changes the version."""

    tool_id: ToolId
    version: str
    definition: Mapping[str, Any]

    def __post_init__(self) -> None:
        object.__setattr__(self, "definition", freeze(self.definition))


class RegistryView(Protocol):
    def current(self, tool_id: ToolId) -> ToolDefinition | None: ...

    def action(self, tool_id: ToolId, arguments: Mapping[str, Any]) -> Action: ...


class PolicyView(Protocol):
    @property
    def version(self) -> str: ...

    def can_discover(self, tool_id: ToolId) -> bool: ...


class OperationStatus(StrEnum):
    """`unknown` means the call may have taken effect upstream, but no
    definitive response arrived."""

    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class OperationRecord:
    operation_id: str
    correlation_id: str
    tool_id: ToolId
    action: Action
    status: OperationStatus
    started_at: datetime


@dataclass(frozen=True)
class HistorySnapshot:
    """A consistent view of one task's operations and committed signals.

    Pending operations are included: they were authorized and may already be
    running, so rules about "what has happened" must count them.
    """

    task_id: str
    version: int
    operations: tuple[OperationRecord, ...] = ()
    signals: tuple[Signal, ...] = ()

    def signals_of(self, signal_type: str) -> tuple[Signal, ...]:
        return tuple(signal for signal in self.signals if signal.type == signal_type)


@dataclass(frozen=True)
class VersionedValue:
    """A stored value and its version. Version 0 means the key does not exist."""

    version: int
    value: Any = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", freeze(self.value))

    @property
    def exists(self) -> bool:
        return self.version > 0


ABSENT = VersionedValue(version=0)


@dataclass(frozen=True)
class PrivateState:
    """Snapshot of the calling defense's own state for the current task."""

    entries: Mapping[str, VersionedValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "entries", freeze(self.entries))

    def get(self, key: str) -> VersionedValue:
        return self.entries.get(key, ABSENT)
