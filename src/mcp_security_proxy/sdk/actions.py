"""Normalized tool semantics: what a tool call actually does.

Derived by Registry from operator configuration, never from tool names or
server-supplied descriptions. Anything not configured stays `unknown`.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Operation(StrEnum):
    READ = "read"
    WRITE = "write"
    SEND = "send"
    EXECUTE = "execute"
    UNKNOWN = "unknown"


class Sensitivity(StrEnum):
    """Missing sensitivity evidence means `unknown`, never `public`."""

    PUBLIC = "public"
    SENSITIVE = "sensitive"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Action:
    operation: Operation
    adapter_id: str
    adapter_version: str
    resource: str | None = None
    destination: str | None = None
    sensitivity: Sensitivity = Sensitivity.UNKNOWN

    @classmethod
    def unknown(cls, adapter_id: str, adapter_version: str) -> Action:
        return cls(Operation.UNKNOWN, adapter_id, adapter_version)
