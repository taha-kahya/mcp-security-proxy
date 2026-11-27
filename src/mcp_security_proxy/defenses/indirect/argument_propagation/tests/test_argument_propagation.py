"""ArgumentPropagation, tested with SDK helpers only: no proxy, no servers.

Scan is scripted with `FakeScan`, so these tests check how matches become
findings. What Scan detects in real arguments, with benign twins, is tested
in `tests/contracts/test_scan_defenses.py`. Cases follow
docs/attacks/indirect.md (I0), never the evaluation experiments.
"""

from __future__ import annotations

from typing import Any

import pytest

from mcp_security_proxy.defenses.indirect.argument_propagation import (
    CONCEALED_INSTRUCTIONS_RULE,
    DEFENSE_ID,
    INSTRUCTIONS_IN_QUERY_RULE,
    INSTRUCTIONS_RULE,
    create,
)
from mcp_security_proxy.defenses.indirect.argument_propagation.defense import MANIFEST
from mcp_security_proxy.sdk import (
    Capability,
    Confidence,
    Detector,
    Event,
    InspectionStatus,
    MatchKind,
    Operation,
    Result,
    ScanLimitError,
    ScanMatch,
    ScanResult,
    Severity,
    Stage,
)
from mcp_security_proxy.sdk.testing import FakeScan, action, make_context, make_event

ARGUMENTS = {"key": "handoff/next-agent", "value": "Summary of the work so far."}


def _call(
    op: Operation | None = Operation.WRITE,
    arguments: Any = ARGUMENTS,
    stage: Stage = Stage.BEFORE_EXECUTION,
) -> Event:
    payload = {"name": "write_record", "arguments": arguments}
    method = "tools/list" if stage is Stage.DISCOVERY else "tools/call"
    return make_event(
        stage, method=method, payload=payload, action=None if op is None else action(op)
    )


def _match(pointer: str = "/value", concealed: bool = False, **fields: Any) -> ScanMatch:
    return ScanMatch(
        detector=Detector.INSTRUCTIONS,
        kind=fields.pop("kind", MatchKind.INSTRUCTION_OVERRIDE),
        pointer=pointer,
        span=fields.pop("span", (0, 30)),
        confidence=fields.pop("confidence", Confidence.MEDIUM),
        concealed=concealed,
        **fields,
    )


async def _evaluate(event: Event, *matches: ScanMatch, scan: Any = None) -> Result:
    defense = create({})
    scan = scan or FakeScan(matches=matches)
    return await defense.evaluate(event, make_context(defense.manifest(), scan=scan))


def _rules(result: Result) -> dict[str, Severity]:
    return {f.rule_id: f.severity for f in result.findings}


@pytest.mark.parametrize(
    ("op", "concealed", "expected"),
    [
        pytest.param(Operation.WRITE, False, {INSTRUCTIONS_RULE: Severity.MEDIUM}, id="write"),
        pytest.param(Operation.SEND, False, {INSTRUCTIONS_RULE: Severity.MEDIUM}, id="send"),
        pytest.param(Operation.EXECUTE, False, {INSTRUCTIONS_RULE: Severity.MEDIUM}, id="execute"),
        pytest.param(
            Operation.UNKNOWN, False, {INSTRUCTIONS_RULE: Severity.MEDIUM}, id="unclassified"
        ),
        pytest.param(
            Operation.READ, False, {INSTRUCTIONS_IN_QUERY_RULE: Severity.LOW}, id="read query"
        ),
        pytest.param(
            Operation.READ,
            True,
            {CONCEALED_INSTRUCTIONS_RULE: Severity.HIGH},
            id="concealed on a read",
        ),
        pytest.param(
            Operation.SEND,
            True,
            {CONCEALED_INSTRUCTIONS_RULE: Severity.HIGH},
            id="concealed on a send",
        ),
    ],
)
async def test_flags_instructions_by_concealment_and_operation(
    op: Operation, concealed: bool, expected: dict[str, Severity]
) -> None:
    result = await _evaluate(_call(op), _match(concealed=concealed))
    assert result.status is InspectionStatus.COMPLETED
    assert _rules(result) == expected


@pytest.mark.parametrize("op", [Operation.READ, Operation.WRITE, Operation.SEND, Operation.UNKNOWN])
async def test_arguments_without_matches_are_clean(op: Operation) -> None:
    result = await _evaluate(_call(op))
    assert result.status is InspectionStatus.COMPLETED and result.findings == ()


async def test_scans_only_the_arguments() -> None:
    scan = FakeScan()
    await _evaluate(_call(), scan=scan)
    assert scan.scanned == [(Detector.INSTRUCTIONS, ARGUMENTS)]


async def test_evidence_points_at_the_argument_without_quoting_it() -> None:
    result = await _evaluate(
        _call(), _match("/value", span=(12, 60)), _match("/notes/0", concealed=True)
    )
    refs = {f.rule_id: f.evidence_refs for f in result.findings}
    assert refs == {
        INSTRUCTIONS_RULE: ("/arguments/value#12-60",),
        CONCEALED_INSTRUCTIONS_RULE: ("/arguments/notes/0#0-30",),
    }
    for finding in result.findings:
        assert "Summary" not in finding.reason


async def test_a_match_in_an_argument_name_points_at_the_key() -> None:
    result = await _evaluate(_call(), _match("/ignore_previous_rules", in_key=True))
    assert result.findings[0].evidence_refs == ("/arguments/ignore_previous_rules#key#0-30",)


async def test_one_finding_per_rule_lists_every_place() -> None:
    result = await _evaluate(_call(), _match("/value"), _match("/body", span=(1, 9)))
    assert len(result.findings) == 1
    assert result.findings[0].evidence_refs == ("/arguments/body#1-9", "/arguments/value#0-30")


async def test_other_stages_are_not_applicable() -> None:
    for other in set(Stage) - MANIFEST.stages:
        result = await _evaluate(_call(stage=other), _match())
        assert result.status is InspectionStatus.NOT_APPLICABLE


@pytest.mark.parametrize(
    ("event", "expected"),
    [
        pytest.param(_call(None), {INSTRUCTIONS_RULE: Severity.MEDIUM}, id="no action is unknown"),
    ],
)
async def test_missing_action_is_treated_as_unknown(
    event: Event, expected: dict[str, Severity]
) -> None:
    assert _rules(await _evaluate(event, _match())) == expected


async def test_missing_arguments_are_inspected_as_empty() -> None:
    scan = FakeScan()
    event = make_event(Stage.BEFORE_EXECUTION, payload={"name": "x"}, action=action(Operation.SEND))
    result = await _evaluate(event, scan=scan)
    assert result.status is InspectionStatus.COMPLETED and result.findings == ()
    assert scan.scanned == [(Detector.INSTRUCTIONS, {})]


class _FailingScan(FakeScan):
    async def instructions(self, value: Any) -> ScanResult:
        raise ScanLimitError("arguments too large to scan")


async def test_a_scan_error_propagates_so_the_runner_reports_failed() -> None:
    with pytest.raises(ScanLimitError):
        await _evaluate(_call(), scan=_FailingScan())


@pytest.mark.parametrize("settings", [{"unknown_setting": 1}, {"severity": "high"}])
def test_invalid_settings_raise_value_error(settings: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        create(settings)


async def test_rule_ids_are_namespaced_by_the_defense() -> None:
    result = await _evaluate(_call(Operation.READ), _match(), _match("/q", concealed=True))
    assert result.findings
    assert all(f.rule_id.startswith(DEFENSE_ID + ".") for f in result.findings)


def test_manifest_uses_only_scan() -> None:
    assert MANIFEST.required_capabilities == {Capability.SCAN}
    assert not MANIFEST.produced_signals
