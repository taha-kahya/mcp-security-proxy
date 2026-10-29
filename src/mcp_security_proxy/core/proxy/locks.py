"""Serialize security transitions per task.

Deciding a call and reserving it in History happen under the task's lock, so
concurrent calls each decide against a history that already includes every
earlier reservation. The lock is released before the call is dispatched, so
a slow upstream does not stall the task's other calls. Locks are
per-process: one proxy process per state database.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from mcp_security_proxy.services.state import TaskRef


class TaskLocks:
    def __init__(self) -> None:
        self._locks: dict[TaskRef, asyncio.Lock] = {}
        self._users: dict[TaskRef, int] = {}

    @asynccontextmanager
    async def hold(self, task: TaskRef) -> AsyncIterator[None]:
        lock = self._locks.setdefault(task, asyncio.Lock())
        self._users[task] = self._users.get(task, 0) + 1
        try:
            async with lock:
                yield
        finally:
            self._users[task] -= 1
            if not self._users[task]:
                del self._users[task], self._locks[task]
