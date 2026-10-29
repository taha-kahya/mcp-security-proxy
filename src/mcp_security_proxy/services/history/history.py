"""History: task-scoped operation history and committed security signals.

Each task's history is one State record, so a snapshot is always internally
consistent and its version identifies exactly what a decision was based on.
Operations move from `pending` (reserved before dispatch) to `completed`,
`failed`, or `unknown`. History records what was authorized and what
happened; it is not a free-form log and does not infer intent.

Updates retry on version conflicts. Callers that must decide and reserve
against the same snapshot serialize per task themselves (the proxy does),
because a retry here re-applies the change to newer history without
re-deciding.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from mcp_security_proxy.sdk import (
    Action,
    HistorySnapshot,
    OperationRecord,
    OperationStatus,
    Signal,
    ToolId,
)
from mcp_security_proxy.services.history.codec import (
    operation_from_json,
    operation_to_json,
    signal_from_json,
    signal_to_json,
)
from mcp_security_proxy.services.state import StateStore, StateUnavailableError, TaskRef

HISTORY_OWNER = "history"
_KEY = "task"
_MAX_ATTEMPTS = 50

Clock = Callable[[], datetime]


class UnknownOperationError(KeyError):
    """No operation with that id exists in the task's history."""


@dataclass(frozen=True)
class _TaskDocument:
    operations: tuple[OperationRecord, ...] = ()
    signals: tuple[Signal, ...] = ()

    @classmethod
    def from_json(cls, data: Mapping[str, Any] | None) -> _TaskDocument:
        if data is None:
            return cls()
        return cls(
            operations=tuple(operation_from_json(item) for item in data["operations"]),
            signals=tuple(signal_from_json(item) for item in data["signals"]),
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "operations": [operation_to_json(record) for record in self.operations],
            "signals": [signal_to_json(signal) for signal in self.signals],
        }

    def with_operation(self, record: OperationRecord) -> _TaskDocument:
        return replace(self, operations=(*self.operations, record))

    def with_status(self, operation_id: str, status: OperationStatus) -> _TaskDocument:
        if all(record.operation_id != operation_id for record in self.operations):
            raise UnknownOperationError(operation_id)
        return replace(
            self,
            operations=tuple(
                replace(record, status=status) if record.operation_id == operation_id else record
                for record in self.operations
            ),
        )

    def with_signals(self, signals: Iterable[Signal]) -> _TaskDocument:
        return replace(self, signals=(*self.signals, *signals))

    def with_pending_marked_unknown(self) -> _TaskDocument:
        return replace(
            self,
            operations=tuple(
                replace(record, status=OperationStatus.UNKNOWN)
                if record.status is OperationStatus.PENDING
                else record
                for record in self.operations
            ),
        )


class History:
    def __init__(self, state: StateStore, clock: Clock = lambda: datetime.now(UTC)) -> None:
        self._state = state
        self._clock = clock

    async def snapshot(self, task: TaskRef) -> HistorySnapshot:
        stored = await self._state.read(task.scope(HISTORY_OWNER), _KEY)
        document = _TaskDocument.from_json(stored.value)
        return HistorySnapshot(
            task_id=task.task_id,
            version=stored.version,
            operations=document.operations,
            signals=document.signals,
        )

    async def reserve(
        self, task: TaskRef, *, correlation_id: str, tool_id: ToolId, action: Action
    ) -> OperationRecord:
        """Record an authorized operation as pending, before it is dispatched."""
        record = OperationRecord(
            operation_id=uuid4().hex,
            correlation_id=correlation_id,
            tool_id=tool_id,
            action=action,
            status=OperationStatus.PENDING,
            started_at=self._clock(),
        )
        await self._update(task, lambda document: document.with_operation(record))
        return record

    async def finish(self, task: TaskRef, operation_id: str, status: OperationStatus) -> None:
        await self._update(task, lambda document: document.with_status(operation_id, status))

    async def record_signals(self, task: TaskRef, signals: Iterable[Signal]) -> None:
        signals = tuple(signals)
        if signals:
            await self._update(task, lambda document: document.with_signals(signals))

    async def recover_interrupted(self) -> int:
        """At startup: operations still pending were cut off by a restart, so
        whether they took effect is unknown. Returns how many tasks had any."""
        recovered = 0
        for scope in await self._state.scopes(HISTORY_OWNER):
            task = TaskRef(scope.principal_id, scope.task_id)
            snapshot = await self.snapshot(task)
            if any(op.status is OperationStatus.PENDING for op in snapshot.operations):
                await self._update(task, _TaskDocument.with_pending_marked_unknown)
                recovered += 1
        return recovered

    async def _update(
        self, task: TaskRef, mutate: Callable[[_TaskDocument], _TaskDocument]
    ) -> None:
        scope = task.scope(HISTORY_OWNER)
        for _ in range(_MAX_ATTEMPTS):
            stored = await self._state.read(scope, _KEY)
            updated = mutate(_TaskDocument.from_json(stored.value))
            result = await self._state.compare_and_set(
                scope, _KEY, stored.version, updated.to_json()
            )
            if result.applied:
                return
        raise StateUnavailableError(f"history for {task} stayed contended; update abandoned")
