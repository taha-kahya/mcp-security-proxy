"""CallRate, tested with SDK helpers only: no proxy, no servers.

Cases follow docs/attacks/temporal.md (T0), written from public descriptions
of runaway agents, never from the evaluation experiments. All cases use
`max_operations: 10`, `window_seconds: 60`.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta
from typing import Any

import pytest

from mcp_security_proxy.defenses.temporal.call_rate import DEFENSE_ID, EXCEEDED_RULE, create
from mcp_security_proxy.defenses.temporal.call_rate.defense import MANIFEST
from mcp_security_proxy.sdk import (
    Capability,
    Event,
    InspectionStatus,
    Operation,
    OperationRecord,
    OperationStatus,
    Result,
    Severity,
    Stage,
)
from mcp_security_proxy.sdk.testing import action, history, make_context, make_event, operation

LIMITS = {"max_operations": 10, "window_seconds": 60}


def _call(op: Operation = Operation.SEND, stage: Stage = Stage.BEFORE_EXECUTION) -> Event:
    return make_event(stage, action=action(op))


def _ops(
    count: int,
    now: datetime,
    *,
    op: Operation = Operation.SEND,
    status: OperationStatus = OperationStatus.COMPLETED,
    age_seconds: float = 5,
) -> list[OperationRecord]:
    return [
        replace(operation(op=op, status=status), started_at=now - timedelta(seconds=age_seconds))
        for _ in range(count)
    ]


async def _evaluate(event: Event, records: list[OperationRecord], **settings: Any) -> Result:
    defense = create({**LIMITS, **settings})
    context = make_context(defense.manifest(), history=history(*records))
    return await defense.evaluate(event, context)


def _cases() -> list[Any]:
    return [
        pytest.param(lambda now: _ops(10, now), Operation.SEND, {}, id="10 sends, 11th send"),
        pytest.param(
            lambda now: (
                _ops(8, now, op=Operation.WRITE)
                + _ops(2, now, op=Operation.WRITE, status=OperationStatus.PENDING)
            ),
            Operation.WRITE,
            {},
            id="8 completed + 2 pending writes",
        ),
        pytest.param(
            lambda now: _ops(10, now, status=OperationStatus.UNKNOWN),
            Operation.SEND,
            {},
            id="10 unknown-outcome sends",
        ),
        pytest.param(
            lambda now: _ops(10, now, op=Operation.UNKNOWN),
            Operation.UNKNOWN,
            {"count_unknown": True},
            id="10 unclassified calls",
        ),
        pytest.param(
            lambda now: _ops(5, now, op=Operation.WRITE) + _ops(5, now, op=Operation.EXECUTE),
            Operation.SEND,
            {},
            id="counted operations of mixed kinds",
        ),
    ]


def _benign() -> list[Any]:
    return [
        pytest.param(lambda now: _ops(9, now), Operation.SEND, {}, id="9 sends, 10th send"),
        pytest.param(
            lambda now: _ops(10, now, age_seconds=61), Operation.SEND, {}, id="10 sends, all old"
        ),
        pytest.param(
            lambda now: _ops(10, now, status=OperationStatus.FAILED),
            Operation.SEND,
            {},
            id="10 failed sends",
        ),
        pytest.param(
            lambda now: _ops(300, now, op=Operation.READ),
            Operation.SEND,
            {},
            id="300 reads, then a send",
        ),
        pytest.param(
            lambda now: _ops(10, now, op=Operation.UNKNOWN),
            Operation.SEND,
            {"count_unknown": False},
            id="unclassified not counted",
        ),
    ]


@pytest.mark.parametrize(("records", "op", "settings"), _cases())
async def test_flags_bursts(records: Any, op: Operation, settings: dict[str, Any]) -> None:
    event = _call(op)
    result = await _evaluate(event, records(event.timestamp), **settings)
    assert result.status is InspectionStatus.COMPLETED
    assert [(f.rule_id, f.severity) for f in result.findings] == [(EXCEEDED_RULE, Severity.HIGH)]


@pytest.mark.parametrize(("records", "op", "settings"), _benign())
async def test_allows_matched_benign_cases(
    records: Any, op: Operation, settings: dict[str, Any]
) -> None:
    event = _call(op)
    result = await _evaluate(event, records(event.timestamp), **settings)
    assert result.status is InspectionStatus.COMPLETED and result.findings == ()


@pytest.mark.parametrize(
    ("op", "settings"),
    [
        pytest.param(Operation.READ, {}, id="a read"),
        pytest.param(Operation.UNKNOWN, {"count_unknown": False}, id="unclassified, not counted"),
    ],
)
async def test_uncounted_calls_are_not_applicable(op: Operation, settings: dict[str, Any]) -> None:
    event = _call(op)
    result = await _evaluate(event, _ops(300, event.timestamp), **settings)
    assert result.status is InspectionStatus.NOT_APPLICABLE


async def test_the_window_boundary_is_exclusive() -> None:
    event = _call()
    result = await _evaluate(event, _ops(10, event.timestamp, age_seconds=60))
    assert result.findings == ()


async def test_reads_count_when_the_operator_adds_them() -> None:
    event = _call(Operation.READ)
    records = _ops(10, event.timestamp, op=Operation.READ)
    result = await _evaluate(event, records, operations=["read"])
    assert [f.rule_id for f in result.findings] == [EXCEEDED_RULE]


async def test_reason_states_counts_not_content() -> None:
    event = _call()
    result = await _evaluate(event, _ops(12, event.timestamp))
    assert (
        result.findings[0].reason
        == "task started 12 counted operations in the last 60 s (limit 10)"
    )
    assert result.findings[0].evidence_refs == ()


async def test_other_stages_are_not_applicable() -> None:
    for other in set(Stage) - MANIFEST.stages:
        event = _call(stage=other)
        result = await _evaluate(event, _ops(20, event.timestamp))
        assert result.status is InspectionStatus.NOT_APPLICABLE


@pytest.mark.parametrize(
    "event",
    [
        pytest.param(make_event(Stage.BEFORE_EXECUTION), id="no action"),
    ],
)
async def test_missing_action_is_not_applicable(event: Event) -> None:
    result = await _evaluate(event, [])
    assert result.status is InspectionStatus.NOT_APPLICABLE


async def test_empty_history_is_clean() -> None:
    result = await _evaluate(_call(), [])
    assert result.status is InspectionStatus.COMPLETED and result.findings == ()


@pytest.mark.parametrize(
    "settings",
    [
        pytest.param({}, id="no limits"),
        pytest.param({"max_operations": 10}, id="no window"),
        pytest.param({"window_seconds": 60}, id="no max"),
        pytest.param({**LIMITS, "max_operations": 0}, id="zero max"),
        pytest.param({**LIMITS, "window_seconds": 0}, id="zero window"),
        pytest.param({**LIMITS, "window_seconds": 100_000}, id="window over a day"),
        pytest.param({**LIMITS, "operations": ["teleport"]}, id="unknown operation"),
        pytest.param({**LIMITS, "unknown_setting": 1}, id="unknown setting"),
    ],
)
def test_invalid_settings_raise_value_error(settings: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        create(settings)


async def test_rule_ids_are_namespaced_by_the_defense() -> None:
    event = _call()
    result = await _evaluate(event, _ops(10, event.timestamp))
    assert result.findings
    assert all(f.rule_id.startswith(DEFENSE_ID + ".") for f in result.findings)


def test_manifest_reads_only_history() -> None:
    assert MANIFEST.required_capabilities == {Capability.HISTORY}
    assert not MANIFEST.produced_signals
