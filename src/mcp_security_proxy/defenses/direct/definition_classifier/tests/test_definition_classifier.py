"""DefinitionClassifier, tested with SDK helpers only: no proxy, no model.

Scan is scripted with `FakeScan`, so these tests check how the classifier's
grade becomes a finding. The classifier stage itself is tested in
`tests/contracts/test_scan_classifier.py`.
"""

from __future__ import annotations

from typing import Any

import pytest

from mcp_security_proxy.defenses.direct.definition_classifier import (
    CRITICAL_RULE,
    DEFENSE_ID,
    HIGH_RULE,
    MEDIUM_RULE,
    create,
)
from mcp_security_proxy.defenses.direct.definition_classifier.defense import LEVELS
from mcp_security_proxy.sdk import (
    Confidence,
    Detector,
    Event,
    InspectionStatus,
    MatchKind,
    Result,
    ScanError,
    ScanMatch,
    ScanStage,
    Severity,
    Stage,
)
from mcp_security_proxy.sdk.testing import FakeScan, make_context, make_event

DEFINITION = {
    "name": "get_weather",
    "description": "Current weather for a city.",
    "inputSchema": {"type": "object", "properties": {"city": {"type": "string"}}},
}


def _event(stage: Stage = Stage.DISCOVERY, **fields: Any) -> Event:
    """Like the proxy's events: discovery events are `tools/list`."""
    method = "tools/list" if stage is Stage.DISCOVERY else "tools/call"
    return make_event(stage, method=method, payload=fields.pop("payload", DEFINITION), **fields)


def _graded(level: str) -> ScanMatch:
    return ScanMatch(
        Detector.POISONING,
        MatchKind.POISONED_DEFINITION,
        "",
        (0, 0),
        Confidence.MEDIUM,
        stage=ScanStage.CLASSIFIER,
        label=level,
    )


async def _evaluate(event: Event, scan: FakeScan | None = None) -> Result:
    defense = create({})
    return await defense.evaluate(event, make_context(defense.manifest(), scan=scan or FakeScan()))


@pytest.mark.parametrize(
    ("level", "rule", "severity"),
    [
        pytest.param("critical", CRITICAL_RULE, Severity.CRITICAL, id="critical"),
        pytest.param("high", HIGH_RULE, Severity.HIGH, id="high"),
        pytest.param("medium", MEDIUM_RULE, Severity.MEDIUM, id="medium"),
    ],
)
async def test_each_grade_becomes_a_finding(level: str, rule: str, severity: Severity) -> None:
    result = await _evaluate(_event(), FakeScan(matches=(_graded(level),)))
    assert result.status is InspectionStatus.COMPLETED
    [finding] = result.findings
    assert (finding.rule_id, finding.severity, finding.category) == (rule, severity, "direct")
    assert finding.evidence_refs == ("",)


async def test_a_definition_graded_clean_is_completed_without_findings() -> None:
    result = await _evaluate(_event())
    assert result.status is InspectionStatus.COMPLETED and result.findings == ()


async def test_the_whole_definition_is_scored() -> None:
    scan = FakeScan()
    await _evaluate(_event(), scan)
    assert scan.scanned == [(Detector.POISONING, _event().payload)]


async def test_other_stages_are_not_applicable() -> None:
    result = await _evaluate(_event(Stage.BEFORE_EXECUTION))
    assert result.status is InspectionStatus.NOT_APPLICABLE


async def test_discovery_of_something_other_than_tools_is_not_applicable() -> None:
    result = await _evaluate(make_event(Stage.DISCOVERY, method="prompts/list"))
    assert result.status is InspectionStatus.NOT_APPLICABLE


async def test_an_unscored_definition_propagates_so_it_is_reported_failed() -> None:
    with pytest.raises(ScanError):
        await _evaluate(_event(), FakeScan(unscored=True))


async def test_an_unknown_grade_is_never_clean() -> None:
    with pytest.raises(ValueError):
        await _evaluate(_event(), FakeScan(matches=(_graded("severe"),)))


@pytest.mark.parametrize("settings", [{"operating_point": "balanced"}, {"unknown": 1}])
def test_invalid_settings_raise_value_error(settings: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        create(settings)


def test_rule_ids_are_namespaced_and_reasons_hold_no_content() -> None:
    for rule, severity, reason in LEVELS.values():
        assert rule.startswith(DEFENSE_ID + ".")
        assert isinstance(severity, Severity) and reason
