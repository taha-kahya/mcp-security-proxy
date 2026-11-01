"""In-memory fakes for the upstream server and the audit sink."""

from __future__ import annotations

from typing import Any

from mcp import types

from mcp_security_proxy.services.log import AuditRecord, AuditWriteError


class FakeUpstream:
    def __init__(self, behavior: Any = None) -> None:
        self.calls: list[tuple[str, dict[str, Any] | None]] = []
        self._behavior = behavior

    async def call_tool(
        self, name: str, arguments: dict[str, Any] | None = None
    ) -> types.CallToolResult:
        self.calls.append((name, arguments))
        if isinstance(self._behavior, BaseException):
            raise self._behavior
        if callable(self._behavior):
            return await self._behavior()
        return types.CallToolResult(content=[types.TextContent(text="ok")])


class MemorySink:
    def __init__(self) -> None:
        self.records: list[AuditRecord] = []
        self.failing = False

    async def write(self, record: AuditRecord) -> None:
        if self.failing:
            raise AuditWriteError("disk full")
        self.records.append(record)

    def of_kind(self, kind: type[AuditRecord]) -> list[Any]:
        return [r for r in self.records if isinstance(r, kind)]
