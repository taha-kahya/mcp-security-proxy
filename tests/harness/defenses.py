"""A configurable in-test defense: its manifest and behavior are set per test."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from mcp_security_proxy.sdk import (
    Capability,
    Context,
    Event,
    Finding,
    Manifest,
    Result,
    Severity,
    Stage,
)

Behavior = Callable[[Event, Context], Awaitable[Any]]


async def clean(event: Event, context: Context) -> Result:
    return Result.completed()


def finds(rule_id: str, severity: Severity = Severity.HIGH) -> Behavior:
    async def behavior(event: Event, context: Context) -> Result:
        return Result.completed([Finding(rule_id, "test", severity, "test finding")])

    return behavior


async def raises(event: Event, context: Context) -> Result:
    raise RuntimeError("defense bug")


@dataclass
class ScriptedDefense:
    id: str
    behavior: Behavior = clean
    stages: frozenset[Stage] = frozenset({Stage.BEFORE_EXECUTION})
    capabilities: frozenset[Capability] = frozenset()
    requires: frozenset[str] = frozenset()
    produces: frozenset[str] = frozenset()
    sdk_range: str = ">=1.0,<2"
    seen_contexts: list[Context] = field(default_factory=list)
    seen_events: list[Event] = field(default_factory=list)

    def manifest(self) -> Manifest:
        return Manifest(
            id=self.id,
            version="1.0.0",
            sdk_version_range=self.sdk_range,
            stages=self.stages,
            required_capabilities=self.capabilities,
            required_signals=self.requires,
            produced_signals=self.produces,
        )

    async def evaluate(self, event: Event, context: Context) -> Result:
        self.seen_events.append(event)
        self.seen_contexts.append(context)
        result: Result = await self.behavior(event, context)
        return result
