"""Call budget, tested with SDK helpers only: no proxy, no servers."""

from __future__ import annotations

from typing import Any

import pytest

from mcp_security_proxy.defenses.samples.call_budget import EXCEEDED_RULE, create
from mcp_security_proxy.sdk import (
    CapabilityNotGrantedError,
    Context,
    InspectionStatus,
    Operation,
    OperationRecord,
    OperationStatus,
    Result,
    Stage,
)
from mcp_security_proxy.sdk.testing import action, history, make_context, make_event, operation


async def _evaluate(op: Operation, *past: OperationRecord, **settings: Any) -> Result:
    defense = create({"max_operations": 2} | settings)
    context = make_context(defense.manifest(), history=history(*past))
    return await defense.evaluate(make_event(action=action(op)), context)


async def test_allows_side_effects_under_the_budget() -> None:
    result = await _evaluate(Operation.WRITE, operation(op=Operation.SEND))
    assert result.status is InspectionStatus.COMPLETED and result.findings == ()


async def test_blocks_once_the_budget_is_used() -> None:
    result = await _evaluate(
        Operation.SEND, operation(op=Operation.WRITE), operation(op=Operation.SEND)
    )
    [finding] = result.findings
    assert finding.rule_id == EXCEEDED_RULE


async def test_pending_and_unknown_operations_count_but_failed_ones_do_not() -> None:
    pending = operation(status=OperationStatus.PENDING)
    unknown = operation(status=OperationStatus.UNKNOWN)
    failed = operation(status=OperationStatus.FAILED)

    assert (await _evaluate(Operation.WRITE, pending, unknown)).findings
    assert not (await _evaluate(Operation.WRITE, pending, failed)).findings


async def test_reads_are_not_applicable_and_not_counted() -> None:
    reads = [operation(op=Operation.READ) for _ in range(5)]
    assert (await _evaluate(Operation.READ, *reads)).status is InspectionStatus.NOT_APPLICABLE
    assert not (await _evaluate(Operation.WRITE, *reads)).findings


@pytest.mark.parametrize(("count_unknown", "blocked"), [(True, True), (False, False)])
async def test_unknown_operations_count_only_when_configured(
    count_unknown: bool, blocked: bool
) -> None:
    past = [operation(op=Operation.UNKNOWN), operation(op=Operation.UNKNOWN)]
    result = await _evaluate(Operation.WRITE, *past, count_unknown=count_unknown)
    assert bool(result.findings) is blocked


async def test_calls_without_an_action_are_not_applicable() -> None:
    defense = create({"max_operations": 0})
    result = await defense.evaluate(make_event(), make_context(defense.manifest()))
    assert result.status is InspectionStatus.NOT_APPLICABLE


@pytest.mark.parametrize(
    "settings",
    [{}, {"max_operations": -1}, {"max_operations": 1, "operations": ["delete"]}, {"x": 1}],
)
def test_invalid_settings_raise_value_error(settings: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        create(settings)


def test_manifest_declares_only_what_the_defense_uses() -> None:
    manifest = create({"max_operations": 1}).manifest()
    assert manifest.stages == {Stage.BEFORE_EXECUTION}
    context: Context = make_context(manifest)
    with pytest.raises(CapabilityNotGrantedError):
        _ = context.registry
