"""Sample defense: cap the number of side-effecting operations per task.

Exists to validate the extension mechanism end to end, not as a real attack
defense. It reads only the task history in its context, so it is a pure
function of the snapshot; the proxy serializes decide-and-reserve per task,
which is what stops concurrent calls from all slipping under the cap.

Counted operations are pending, completed, and outcome-unknown ones:
anything that may have taken effect. Definitively failed calls are not
counted.
"""

from __future__ import annotations

from collections.abc import Mapping
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

DEFENSE_ID = "call_budget"
EXCEEDED_RULE = "call_budget.exceeded"

_COUNTED_STATUSES = frozenset(
    {OperationStatus.PENDING, OperationStatus.COMPLETED, OperationStatus.UNKNOWN}
)

MANIFEST = Manifest(
    id=DEFENSE_ID,
    version="1.0.0",
    sdk_version_range=">=1.0,<2",
    stages=frozenset({Stage.BEFORE_EXECUTION}),
    required_capabilities=frozenset({Capability.HISTORY}),
)


class CallBudgetSettings(BaseModel):
    """`count_unknown` treats unclassified tools as side-effecting, because
    an unknown tool may write or send."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_operations: int = Field(ge=0)
    operations: frozenset[Operation] = frozenset(
        {Operation.WRITE, Operation.SEND, Operation.EXECUTE}
    )
    count_unknown: bool = True


class CallBudgetDefense:
    def __init__(self, settings: CallBudgetSettings) -> None:
        self._settings = settings

    def manifest(self) -> Manifest:
        return MANIFEST

    async def evaluate(self, event: Event, context: Context) -> Result:
        if event.action is None or not self._counts(event.action.operation):
            return Result.not_applicable()

        used = sum(
            1
            for record in context.history.operations
            if record.status in _COUNTED_STATUSES and self._counts(record.action.operation)
        )
        if used < self._settings.max_operations:
            return Result.completed()
        return Result.completed(
            [
                Finding(
                    rule_id=EXCEEDED_RULE,
                    category="sample",
                    severity=Severity.HIGH,
                    reason=f"task used {used} of {self._settings.max_operations} operations",
                )
            ]
        )

    def _counts(self, operation: Operation) -> bool:
        if operation is Operation.UNKNOWN:
            return self._settings.count_unknown
        return operation in self._settings.operations


def create(settings: Mapping[str, Any]) -> CallBudgetDefense:
    """Entry point: raises `ValueError` (pydantic's ValidationError) for bad settings."""
    return CallBudgetDefense(CallBudgetSettings.model_validate(settings))
