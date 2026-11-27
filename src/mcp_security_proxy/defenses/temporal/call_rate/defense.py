"""Limit how many side-effecting calls a task makes within a time window (plan MR T1).

An injected or looping agent can call an allowed tool hundreds of times in a
minute: spam, cost, quota exhaustion, data loss. Each call alone is fine, so
the check is on volume. Before each counted call, this defense counts the
task's operations that started within the last `window_seconds` and reports
`exceeded` once `max_operations` of them are already in the window.

Counted operations are pending, completed and outcome-unknown ones: anything
that may have taken effect. Pending calls count, and the proxy serializes
decide-and-reserve per task, so concurrent calls can't all slip under the
limit. Definitively failed calls don't count. Unclassified tools count by
default, because an unknown tool may write or send.

`call_budget` caps the whole task; this adds a time window. Both can run.

Does not cover: rates across tasks, principals or sessions (a core limit, if
needed), slow abuse paced just under the rate (`call_budget` and the
Cross-tool rules), or reads, which aren't counted unless the operator adds
them to `operations`.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import timedelta
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from mcp_security_proxy.sdk import (
    Capability,
    Context,
    Event,
    Finding,
    Manifest,
    Operation,
    OperationStatus,
    Result,
    Severity,
    Stage,
)

DEFENSE_ID = "temporal_call_rate"
CATEGORY = "temporal"
EXCEEDED_RULE = f"{DEFENSE_ID}.exceeded"

MANIFEST = Manifest(
    id=DEFENSE_ID,
    version="0.1.0",
    sdk_version_range=">=1.0,<2",
    stages=frozenset({Stage.BEFORE_EXECUTION}),
    required_capabilities=frozenset({Capability.HISTORY}),
)

_COUNTED_STATUSES = frozenset(
    {OperationStatus.PENDING, OperationStatus.COMPLETED, OperationStatus.UNKNOWN}
)


class CallRateSettings(BaseModel):
    """`max_operations` and `window_seconds` have no defaults: a rate limit
    that fits one deployment blocks another, so the operator sets both."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_operations: int = Field(ge=1)
    window_seconds: float = Field(gt=0, le=86_400)
    operations: frozenset[Operation] = frozenset(
        {Operation.WRITE, Operation.SEND, Operation.EXECUTE}
    )
    count_unknown: bool = True


class CallRateDefense:
    def __init__(self, settings: CallRateSettings) -> None:
        self._settings = settings

    def manifest(self) -> Manifest:
        return MANIFEST

    async def evaluate(self, event: Event, context: Context) -> Result:
        if event.stage is not Stage.BEFORE_EXECUTION:
            return Result.not_applicable()
        if event.action is None or not self._counts(event.action.operation):
            return Result.not_applicable()
        since = event.timestamp - timedelta(seconds=self._settings.window_seconds)
        used = sum(
            1
            for record in context.history.operations
            if record.status in _COUNTED_STATUSES
            and record.started_at > since
            and self._counts(record.action.operation)
        )
        if used < self._settings.max_operations:
            return Result.completed()
        reason = (
            f"task started {used} counted operations in the last "
            f"{self._settings.window_seconds:g} s (limit {self._settings.max_operations})"
        )
        return Result.completed([Finding(EXCEEDED_RULE, CATEGORY, Severity.HIGH, reason)])

    def _counts(self, operation: Operation) -> bool:
        if operation is Operation.UNKNOWN:
            return self._settings.count_unknown
        return operation in self._settings.operations


def create(settings: Mapping[str, Any]) -> CallRateDefense:
    """Entry point: raises `ValueError` (pydantic's ValidationError) for bad settings."""
    return CallRateDefense(CallRateSettings.model_validate(settings))
