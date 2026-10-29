"""History behavior, run against both State adapters."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from mcp_security_proxy.sdk import Operation, OperationStatus, Signal, ToolId
from mcp_security_proxy.sdk.testing import action
from mcp_security_proxy.services.history import History, UnknownOperationError
from mcp_security_proxy.services.state import (
    InMemoryStateStore,
    SqliteStateStore,
    StateStore,
    TaskRef,
)

ALICE = TaskRef("alice", "alice")
BOB = TaskRef("bob", "bob")
WRITE_TOOL = ToolId("server_a", "write_record")


@pytest.fixture(params=["memory", "sqlite"])
async def state(request: pytest.FixtureRequest, tmp_path: Path) -> AsyncIterator[StateStore]:
    store: StateStore = (
        InMemoryStateStore()
        if request.param == "memory"
        else SqliteStateStore.open(tmp_path / "state.sqlite3")
    )
    yield store
    await store.close()


async def _reserve(history: History, task: TaskRef = ALICE) -> str:
    record = await history.reserve(
        task, correlation_id="c", tool_id=WRITE_TOOL, action=action(Operation.WRITE)
    )
    return record.operation_id


async def test_empty_history_has_version_zero(state: StateStore) -> None:
    snapshot = await History(state).snapshot(ALICE)
    assert snapshot.version == 0 and snapshot.operations == () and snapshot.task_id == "alice"


async def test_reserved_operations_are_pending_until_finished(state: StateStore) -> None:
    history = History(state)
    operation_id = await _reserve(history)

    [pending] = (await history.snapshot(ALICE)).operations
    assert pending.status is OperationStatus.PENDING and pending.tool_id == WRITE_TOOL

    await history.finish(ALICE, operation_id, OperationStatus.COMPLETED)
    snapshot = await history.snapshot(ALICE)
    assert snapshot.operations[0].status is OperationStatus.COMPLETED
    assert snapshot.version == 2


async def test_finishing_an_unknown_operation_raises(state: StateStore) -> None:
    with pytest.raises(UnknownOperationError):
        await History(state).finish(ALICE, "missing", OperationStatus.COMPLETED)


async def test_tasks_are_isolated(state: StateStore) -> None:
    history = History(state)
    await _reserve(history, ALICE)

    assert (await history.snapshot(BOB)).operations == ()


async def test_signals_are_committed_with_provenance(state: StateStore) -> None:
    history = History(state)
    await history.record_signals(ALICE, [Signal("sensitivity", 1, "scanner", {"level": "high"})])

    [signal] = (await history.snapshot(ALICE)).signals_of("sensitivity")
    assert signal.producer == "scanner" and signal.value["level"] == "high"


async def test_concurrent_reservations_are_all_kept(state: StateStore) -> None:
    history = History(state)
    await asyncio.gather(*(_reserve(history) for _ in range(15)))

    assert len((await history.snapshot(ALICE)).operations) == 15


async def test_recovery_marks_interrupted_operations_unknown(state: StateStore) -> None:
    history = History(state)
    finished = await _reserve(history, ALICE)
    await history.finish(ALICE, finished, OperationStatus.COMPLETED)
    await _reserve(history, ALICE)
    await _reserve(history, BOB)

    assert await History(state).recover_interrupted() == 2

    statuses = [op.status for op in (await history.snapshot(ALICE)).operations]
    assert statuses == [OperationStatus.COMPLETED, OperationStatus.UNKNOWN]
    assert (await history.snapshot(BOB)).operations[0].status is OperationStatus.UNKNOWN
