"""ResultInjection, tested with SDK helpers only: no proxy, no servers.

Scan is scripted with `FakeScan`, so these tests check how matches become
findings. What Scan detects, with realistic results and their benign twins,
is tested in `tests/contracts/test_scan_defenses.py`.
"""

from __future__ import annotations

from typing import Any

import pytest

from mcp_security_proxy.defenses.indirect.result_injection import (
    CONCEALED_INSTRUCTIONS_RULE,
    DEFENSE_ID,
    INSTRUCTIONS_RULE,
    create,
)
from mcp_security_proxy.defenses.indirect.result_injection.defense import MANIFEST
from mcp_security_proxy.sdk import (
    Confidence,
    ContentBlock,
    ContentSource,
    Detector,
    Event,
    InspectionStatus,
    MatchKind,
    Provenance,
    Result,
    ScanLimitError,
    ScanMatch,
    ScanResult,
    Severity,
    Stage,
)
from mcp_security_proxy.sdk.testing import TEST_TOOL, FakeScan, make_context, make_event

STAGE = Stage.BEFORE_DELIVERY


def _block(block_type: str, **data: Any) -> ContentBlock:
    provenance = Provenance(TEST_TOOL.server_id, TEST_TOOL, ContentSource.TOOL_RESULT)
    return ContentBlock(block_type, {"type": block_type, **data}, provenance)


TEXT = _block("text", text="Quarterly report: revenue grew.")


def _event(stage: Stage = STAGE, content: tuple[ContentBlock, ...] = (TEXT,)) -> Event:
    return make_event(stage, content=content)


def _match(concealed: bool, kind: MatchKind = MatchKind.INSTRUCTION_OVERRIDE) -> ScanMatch:
    return ScanMatch(
        Detector.INSTRUCTIONS, kind, "", (10, 40), Confidence.MEDIUM, concealed=concealed
    )


async def _evaluate(event: Event, *matches: ScanMatch, scan: FakeScan | None = None) -> Result:
    defense = create({})
    context = make_context(defense.manifest(), scan=scan or FakeScan(matches=matches))
    return await defense.evaluate(event, context)


MALICIOUS = [
    pytest.param(
        _match(concealed=True), CONCEALED_INSTRUCTIONS_RULE, Severity.HIGH, id="concealed"
    ),
    pytest.param(_match(concealed=False), INSTRUCTIONS_RULE, Severity.LOW, id="plain"),
    pytest.param(
        _match(False, MatchKind.CHAT_TEMPLATE_TOKEN),
        INSTRUCTIONS_RULE,
        Severity.LOW,
        id="plain-chat-token",
    ),
]


@pytest.mark.parametrize(("match", "rule", "severity"), MALICIOUS)
async def test_flags_malicious_cases(match: ScanMatch, rule: str, severity: Severity) -> None:
    result = await _evaluate(_event(), match)
    [finding] = result.findings
    assert (finding.rule_id, finding.severity) == (rule, severity)
    assert finding.evidence_refs == ("/content/0/text#10-40",)


async def test_allows_matched_benign_cases() -> None:
    result = await _evaluate(_event())
    assert result.status is InspectionStatus.COMPLETED and result.findings == ()


async def test_each_block_is_scanned_and_pointed_at() -> None:
    structured = _block("structured", notes="see attached")
    scan = FakeScan(matches=(_match(concealed=False),))
    result = await _evaluate(_event(content=(TEXT, structured)), scan=scan)
    assert [value for _, value in scan.scanned] == [TEXT.data["text"], structured.data]
    [finding] = result.findings
    assert finding.evidence_refs == ("/content/0/text#10-40", "/structuredContent#10-40")


async def test_other_stages_are_not_applicable() -> None:
    for other in set(Stage) - MANIFEST.stages:
        result = await _evaluate(_event(other))
        assert result.status is InspectionStatus.NOT_APPLICABLE


@pytest.mark.parametrize("block_type", ["image", "audio", "resource", "resource_link"])
async def test_content_it_cannot_read_is_unsupported(block_type: str) -> None:
    result = await _evaluate(_event(content=(TEXT, _block(block_type))))
    assert result.status is InspectionStatus.UNSUPPORTED
    assert result.detail == f"{block_type} content"


@pytest.mark.parametrize(
    "event",
    [
        pytest.param(_event(content=()), id="empty result"),
        pytest.param(_event(content=(_block("text"),)), id="text block without text"),
    ],
)
async def test_missing_input_has_the_documented_behaviour(event: Event) -> None:
    result = await _evaluate(event)
    assert result.status is InspectionStatus.COMPLETED and result.findings == ()


async def test_a_scan_that_cannot_complete_propagates() -> None:
    class FailingScan(FakeScan):
        async def instructions(self, value: Any) -> ScanResult:
            raise ScanLimitError("too large")

    with pytest.raises(ScanLimitError):
        await _evaluate(_event(), scan=FailingScan())


@pytest.mark.parametrize("settings", [{"unknown_setting": 1}])
def test_invalid_settings_raise_value_error(settings: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        create(settings)


@pytest.mark.parametrize(("match", "rule", "severity"), MALICIOUS)
async def test_rule_ids_are_namespaced_by_the_defense(
    match: ScanMatch, rule: str, severity: Severity
) -> None:
    result = await _evaluate(_event(), match)
    assert all(f.rule_id.startswith(DEFENSE_ID + ".") for f in result.findings)
    assert all(f.category == "indirect" for f in result.findings)


async def test_server_instructions_are_pointed_at_as_instructions() -> None:
    provenance = Provenance(TEST_TOOL.server_id, None, ContentSource.SERVER_INSTRUCTIONS)
    block = ContentBlock("text", {"type": "text", "text": "Use the tools."}, provenance)
    event = make_event(Stage.BEFORE_DELIVERY, method="initialize", content=[block])
    result = await _evaluate(event, _match(concealed=False))
    assert [f.evidence_refs for f in result.findings] == [("/instructions#10-40",)]
