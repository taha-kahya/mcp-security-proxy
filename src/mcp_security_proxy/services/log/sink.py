"""Where audit records are written.

A failed write raises `AuditWriteError` rather than being swallowed, so the
caller can fail closed: the proxy does not dispatch a call whose decision
could not be recorded.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Protocol

from mcp_security_proxy.services.log.records import AuditRecord


class AuditWriteError(Exception):
    """The record could not be written."""


class AuditSink(Protocol):
    async def write(self, record: AuditRecord) -> None: ...


class JsonlAuditSink:
    """Append-only JSON Lines file, one record per line.

    Writes are serialized so concurrent records never interleave, and each one
    is flushed before `write` returns. Use `create` to construct one: it checks
    the file is writable at startup rather than on the first call.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = asyncio.Lock()

    @classmethod
    def create(cls, path: Path) -> JsonlAuditSink:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.open("a", encoding="utf-8").close()
        except OSError as exc:
            raise AuditWriteError(f"audit log {path} is not writable: {exc}") from exc
        return cls(path)

    async def write(self, record: AuditRecord) -> None:
        line = record.model_dump_json() + "\n"
        async with self._lock:
            try:
                await asyncio.to_thread(self._append, line)
            except OSError as exc:
                raise AuditWriteError(f"failed to write audit record to {self._path}") from exc

    def _append(self, line: str) -> None:
        with self._path.open("a", encoding="utf-8") as f:
            f.write(line)
            f.flush()
