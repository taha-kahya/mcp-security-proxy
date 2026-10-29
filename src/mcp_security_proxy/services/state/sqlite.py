"""SQLite-backed State, so history and defense state survive a restart.

Uses the standard library's `sqlite3`. Every operation runs in a worker
thread under one lock, and `apply` runs inside a `BEGIN IMMEDIATE`
transaction, so a multi-record update is atomic. One proxy process per
database file: other processes are not coordinated with.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import threading
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import TypeVar

from mcp_security_proxy.sdk import ABSENT, VersionedValue, thaw
from mcp_security_proxy.services.state.store import (
    Change,
    Scope,
    StateStore,
    StateUnavailableError,
    UpdateResult,
)

_SCHEMA_VERSION = 1
_SCHEMA = """
CREATE TABLE IF NOT EXISTS records (
    owner TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    key TEXT NOT NULL,
    version INTEGER NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (owner, principal_id, task_id, key)
)
"""
_SCOPE_WHERE = "owner = ? AND principal_id = ? AND task_id = ?"

_T = TypeVar("_T")


def _scope_params(scope: Scope) -> tuple[str, str, str]:
    return (scope.owner, scope.principal_id, scope.task_id)


class SqliteStateStore(StateStore):
    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection
        self._lock = threading.Lock()

    @classmethod
    def open(cls, path: Path) -> SqliteStateStore:
        """Create or open the database, refusing one with an unknown schema."""
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            connection = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
            found = connection.execute("PRAGMA user_version").fetchone()[0]
            if found not in (0, _SCHEMA_VERSION):
                connection.close()
                raise StateUnavailableError(f"state database {path} has unknown schema {found}")
            connection.execute(_SCHEMA)
            connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
        except sqlite3.Error as exc:
            raise StateUnavailableError(f"cannot open state database {path}: {exc}") from exc
        return cls(connection)

    async def read(self, scope: Scope, key: str) -> VersionedValue:
        def query() -> VersionedValue:
            row = self._connection.execute(
                f"SELECT version, value FROM records WHERE {_SCOPE_WHERE} AND key = ?",
                (*_scope_params(scope), key),
            ).fetchone()
            return ABSENT if row is None else VersionedValue(row[0], json.loads(row[1]))

        return await self._run(query)

    async def read_scope(self, scope: Scope) -> Mapping[str, VersionedValue]:
        def query() -> Mapping[str, VersionedValue]:
            rows = self._connection.execute(
                f"SELECT key, version, value FROM records WHERE {_SCOPE_WHERE}",
                _scope_params(scope),
            ).fetchall()
            return {key: VersionedValue(version, json.loads(value)) for key, version, value in rows}

        return await self._run(query)

    async def scopes(self, owner: str) -> list[Scope]:
        def query() -> list[Scope]:
            rows = self._connection.execute(
                "SELECT DISTINCT principal_id, task_id FROM records WHERE owner = ? "
                "ORDER BY principal_id, task_id",
                (owner,),
            ).fetchall()
            return [Scope(owner, principal_id, task_id) for principal_id, task_id in rows]

        return await self._run(query)

    async def apply(self, changes: Sequence[Change]) -> UpdateResult:
        return await self._run(lambda: self._apply_in_transaction(changes))

    async def close(self) -> None:
        await self._run(self._connection.close)

    def _apply_in_transaction(self, changes: Sequence[Change]) -> UpdateResult:
        connection = self._connection
        connection.execute("BEGIN IMMEDIATE")
        try:
            conflicts = tuple(c for c in changes if self._stored_version(c) != c.expected_version)
            if not conflicts:
                for change in changes:
                    self._write(change)
        except BaseException:
            connection.execute("ROLLBACK")
            raise
        connection.execute("ROLLBACK" if conflicts else "COMMIT")
        return UpdateResult(applied=not conflicts, conflicts=conflicts)

    def _stored_version(self, change: Change) -> int:
        row = self._connection.execute(
            f"SELECT version FROM records WHERE {_SCOPE_WHERE} AND key = ?",
            (*_scope_params(change.scope), change.key),
        ).fetchone()
        return 0 if row is None else int(row[0])

    def _write(self, change: Change) -> None:
        self._connection.execute(
            "INSERT INTO records (owner, principal_id, task_id, key, version, value) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT (owner, principal_id, task_id, key) "
            "DO UPDATE SET version = excluded.version, value = excluded.value",
            (
                *_scope_params(change.scope),
                change.key,
                change.expected_version + 1,
                json.dumps(thaw(change.value)),
            ),
        )

    async def _run(self, operation: Callable[[], _T]) -> _T:
        def locked() -> _T:
            with self._lock:
                return operation()

        try:
            return await asyncio.to_thread(locked)
        except sqlite3.Error as exc:
            raise StateUnavailableError(f"state database error: {exc}") from exc
