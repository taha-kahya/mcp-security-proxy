"""Where audit records are written.

A failed write raises `AuditWriteError` rather than being swallowed, so the
caller can fail closed: the proxy does not dispatch a call whose decision
could not be recorded.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Protocol

from mcp_security_proxy.services.log.chain import (
    AuditChainError,
    ChainHead,
    chained_line,
    read_head,
)
from mcp_security_proxy.services.log.records import AuditRecord


class AuditWriteError(Exception):
    """The record could not be written."""


class AuditSink(Protocol):
    async def write(self, record: AuditRecord) -> None: ...


class JsonlAuditSink:
    """Append-only JSON Lines file, one record per line, hash-chained.

    Writes are serialized so concurrent records never interleave, and each one
    is flushed before `write` returns. Each line links to the one before it
    (`services.log.chain`), and a sink continues the chain of the file it
    opens. Use `create` to construct one: it checks the file is writable and
    can be extended at startup rather than on the first call.

    After a failed write the file may end with part of a line, so every later
    write fails too, rather than chaining onto damage. One sink, in one
    process, must own a file: two writers would fork the chain.
    """

    def __init__(self, path: Path, head: ChainHead | None = None) -> None:
        self._path = path
        self._head = head or ChainHead.start()
        self._broken = False
        self._lock = asyncio.Lock()

    @classmethod
    def create(cls, path: Path) -> JsonlAuditSink:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.open("a", encoding="utf-8").close()
            head = read_head(path)
        except (OSError, UnicodeDecodeError) as exc:
            raise AuditWriteError(f"audit log {path} is not writable: {exc}") from exc
        except AuditChainError as exc:
            raise AuditWriteError(f"audit log {path} can't be extended: {exc}") from exc
        return cls(path, head)

    async def write(self, record: AuditRecord) -> None:
        async with self._lock:
            if self._broken:
                raise AuditWriteError(f"audit log {self._path} is unusable after a failed write")
            line = chained_line(record.model_dump(mode="json"), self._head)
            try:
                await asyncio.to_thread(self._append, line + "\n")
            except OSError as exc:
                self._broken = True
                raise AuditWriteError(f"failed to write audit record to {self._path}") from exc
            self._head = self._head.after(line)

    def _append(self, line: str) -> None:
        # `newline="\n"`: the same bytes on every platform.
        with self._path.open("a", encoding="utf-8", newline="\n") as f:
            f.write(line)
            f.flush()
