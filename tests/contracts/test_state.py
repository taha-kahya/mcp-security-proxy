"""Behavioral contract for every State adapter.

Each test runs against the in-memory and the SQLite adapter, so a
replacement adapter must behave the same way to pass.
"""

from __future__ import annotations

import asyncio
import sqlite3
import subprocess
import sys
from collections.abc import AsyncIterator, Callable
from pathlib import Path

import pytest

from mcp_security_proxy.services.state import (
    Change,
    InMemoryStateStore,
    Scope,
    SqliteStateStore,
    StateInUseError,
    StateStore,
    StateUnavailableError,
)

ALICE_TASK = Scope("history", "alice", "task-1")
BOB_TASK = Scope("history", "bob", "task-1")
DEFENSE_SCOPE = Scope("defense:sample", "alice", "task-1")

StoreFactory = Callable[[Path], StateStore]
ADAPTERS: dict[str, StoreFactory] = {
    "memory": lambda _: InMemoryStateStore(),
    "sqlite": lambda tmp_path: SqliteStateStore.open(tmp_path / "state.sqlite3"),
}


@pytest.fixture(params=list(ADAPTERS))
async def store(request: pytest.FixtureRequest, tmp_path: Path) -> AsyncIterator[StateStore]:
    adapter = ADAPTERS[request.param](tmp_path)
    yield adapter
    await adapter.close()


async def test_missing_key_reads_as_version_zero(store: StateStore) -> None:
    value = await store.read(ALICE_TASK, "operations")
    assert value.version == 0 and value.value is None and not value.exists


async def test_compare_and_set_creates_then_bumps_the_version(store: StateStore) -> None:
    assert (await store.compare_and_set(ALICE_TASK, "k", 0, {"n": 1})).applied
    assert (await store.compare_and_set(ALICE_TASK, "k", 1, {"n": 2})).applied

    stored = await store.read(ALICE_TASK, "k")
    assert stored.version == 2 and stored.value["n"] == 2


async def test_stale_version_is_rejected_and_nothing_changes(store: StateStore) -> None:
    await store.compare_and_set(ALICE_TASK, "k", 0, "first")

    result = await store.compare_and_set(ALICE_TASK, "k", 0, "second")

    assert not result.applied
    assert [c.key for c in result.conflicts] == ["k"]
    assert (await store.read(ALICE_TASK, "k")).value == "first"


async def test_apply_is_all_or_nothing(store: StateStore) -> None:
    await store.compare_and_set(ALICE_TASK, "taken", 0, "x")

    result = await store.apply(
        [Change(ALICE_TASK, "fresh", 0, "y"), Change(ALICE_TASK, "taken", 0, "z")]
    )

    assert not result.applied
    assert not (await store.read(ALICE_TASK, "fresh")).exists
    assert (await store.read(ALICE_TASK, "taken")).value == "x"


async def test_apply_rejects_duplicate_keys_in_one_batch(store: StateStore) -> None:
    """Conflicts are checked against the stored version before any write, so
    two changes to the same key would both appear to apply otherwise, and
    the batch's compare-and-set guarantee would not hold for that key."""
    with pytest.raises(ValueError, match="more than one change"):
        await store.apply(
            [Change(ALICE_TASK, "k", 0, "first"), Change(ALICE_TASK, "k", 0, "second")]
        )

    assert not (await store.read(ALICE_TASK, "k")).exists


async def test_scopes_are_isolated(store: StateStore) -> None:
    await store.compare_and_set(ALICE_TASK, "k", 0, "alice")
    await store.compare_and_set(BOB_TASK, "k", 0, "bob")
    await store.compare_and_set(DEFENSE_SCOPE, "k", 0, "defense")

    assert (await store.read(ALICE_TASK, "k")).value == "alice"
    assert dict(await store.read_scope(BOB_TASK)).keys() == {"k"}
    assert await store.scopes("history") == [ALICE_TASK, BOB_TASK]
    assert await store.scopes("defense:sample") == [DEFENSE_SCOPE]


async def test_stored_values_are_frozen(store: StateStore) -> None:
    await store.compare_and_set(ALICE_TASK, "k", 0, {"items": [1, 2]})
    assert (await store.read(ALICE_TASK, "k")).value["items"] == (1, 2)


async def test_concurrent_read_modify_write_loses_no_update(store: StateStore) -> None:
    async def increment() -> None:
        while True:
            current = await store.read(ALICE_TASK, "counter")
            result = await store.compare_and_set(
                ALICE_TASK, "counter", current.version, (current.value or 0) + 1
            )
            if result.applied:
                return

    await asyncio.gather(*(increment() for _ in range(20)))

    assert (await store.read(ALICE_TASK, "counter")).value == 20


async def test_sqlite_records_survive_reopening(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    first = SqliteStateStore.open(path)
    await first.compare_and_set(ALICE_TASK, "k", 0, ["kept"])
    await first.close()

    reopened = SqliteStateStore.open(path)
    stored = await reopened.read(ALICE_TASK, "k")
    await reopened.close()

    assert stored.version == 1 and stored.value == ("kept",)


def test_sqlite_refuses_an_unknown_schema(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA user_version = 99")

    with pytest.raises(StateUnavailableError):
        SqliteStateStore.open(path)


async def test_sqlite_refuses_a_second_owner_until_the_first_closes(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    first = SqliteStateStore.open(path)

    with pytest.raises(StateInUseError):
        SqliteStateStore.open(path)

    await first.close()
    await SqliteStateStore.open(path).close()


_OPEN_IN_ANOTHER_PROCESS = """
import sys
from pathlib import Path
from mcp_security_proxy.services.state import SqliteStateStore, StateInUseError
try:
    SqliteStateStore.open(Path(sys.argv[1]))
except StateInUseError:
    sys.exit(3)
"""


async def test_sqlite_refuses_another_process_while_held(tmp_path: Path) -> None:
    """Task locks are in-process, so a second writer process could let calls
    through a history rule; it must not be able to open the state at all."""
    path = tmp_path / "state.sqlite3"
    held = SqliteStateStore.open(path)
    await held.compare_and_set(ALICE_TASK, "k", 0, 1)

    other = subprocess.run(
        [sys.executable, "-c", _OPEN_IN_ANOTHER_PROCESS, str(path)], check=False, timeout=30
    )
    await held.close()

    assert other.returncode == 3
