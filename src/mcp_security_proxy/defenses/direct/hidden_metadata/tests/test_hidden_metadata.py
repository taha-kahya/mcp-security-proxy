"""HiddenMetadata, tested with SDK helpers only: no proxy, no servers.

Scan is scripted with `FakeScan`, so these tests check how matches become
findings. What Scan detects, with real tool definitions and their benign
twins, is tested in `tests/contracts/test_scan_defenses.py`.
"""

from __future__ import annotations

from typing import Any

import pytest

from mcp_security_proxy.defenses.direct.hidden_metadata import (
    CONCEALED_INSTRUCTIONS_RULE,
    DEFENSE_ID,
    create,
)
from mcp_security_proxy.defenses.direct.hidden_metadata.defense import (
    CONTROL_CHARACTERS_RULE,
    DATA_URI_RULE,
    ENCODED_TEXT_RULE,
    HIDDEN_COMMENT_RULE,
    INVISIBLE_CHARACTERS_RULE,
    MANIFEST,
    PADDING_RULE,
    RULES,
    TAG_CHARACTERS_RULE,
)
from mcp_security_proxy.sdk import (
    Confidence,
    Decoding,
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

DEFINITION = {"name": "read_file", "description": "Reads a file."}


def _event(stage: Stage = Stage.DISCOVERY, **fields: Any) -> Event:
    """Like the proxy's events: discovery events are `tools/list`."""
    method = "tools/list" if stage is Stage.DISCOVERY else "tools/call"
    return make_event(stage, method=method, payload=fields.pop("payload", DEFINITION), **fields)


def _match(
    kind: MatchKind,
    detector: Detector = Detector.HIDDEN,
    pointer: str = "/description",
    concealed: bool = True,
    **fields: Any,
) -> ScanMatch:
    return ScanMatch(
        detector, kind, pointer, (0, 5), Confidence.HIGH, concealed=concealed, **fields
    )


async def _evaluate(event: Event, *matches: ScanMatch, **settings: Any) -> Result:
    defense = create(settings)
    scan = FakeScan(matches=matches)
    return await defense.evaluate(event, make_context(defense.manifest(), scan=scan))


MALICIOUS = [
    pytest.param(_match(MatchKind.HTML_COMMENT), HIDDEN_COMMENT_RULE, id="html-comment"),
    pytest.param(_match(MatchKind.MARKDOWN_COMMENT), HIDDEN_COMMENT_RULE, id="md-comment"),
    pytest.param(_match(MatchKind.INVISIBLE_CHARACTER), INVISIBLE_CHARACTERS_RULE, id="zero-width"),
    pytest.param(_match(MatchKind.BIDI_CONTROL), INVISIBLE_CHARACTERS_RULE, id="bidi"),
    pytest.param(_match(MatchKind.TAG_CHARACTER), TAG_CHARACTERS_RULE, id="tags"),
    pytest.param(_match(MatchKind.CONTROL_CHARACTER), CONTROL_CHARACTERS_RULE, id="ansi"),
    pytest.param(_match(MatchKind.ENCODED_TEXT), ENCODED_TEXT_RULE, id="base64"),
    pytest.param(_match(MatchKind.PADDING), PADDING_RULE, id="padding"),
    pytest.param(_match(MatchKind.DATA_URI), DATA_URI_RULE, id="data-uri"),
    pytest.param(
        _match(
            MatchKind.INSTRUCTION_OVERRIDE,
            Detector.INSTRUCTIONS,
            decoded_by=(Decoding.BASE64,),
        ),
        CONCEALED_INSTRUCTIONS_RULE,
        id="concealed-instructions",
    ),
]
BENIGN_TWINS = [
    pytest.param((), id="nothing-found"),
    pytest.param(
        (_match(MatchKind.INSTRUCTION_OVERRIDE, Detector.INSTRUCTIONS, concealed=False),),
        id="plain-phrase-is-left-to-d3",
    ),
    pytest.param((_match(MatchKind.SECRET, Detector.SECRETS),), id="other-detectors-are-ignored"),
]


@pytest.mark.parametrize(("match", "rule"), MALICIOUS)
async def test_flags_malicious_cases(match: ScanMatch, rule: str) -> None:
    result = await _evaluate(_event(), match)
    assert [f.rule_id for f in result.findings] == [rule]
    [finding] = result.findings
    assert finding.severity is RULES[rule][0]
    assert finding.evidence_refs == ("/description#0-5",)


@pytest.mark.parametrize("matches", BENIGN_TWINS)
async def test_allows_matched_benign_cases(matches: tuple[ScanMatch, ...]) -> None:
    result = await _evaluate(_event(), *matches)
    assert result.status is InspectionStatus.COMPLETED and result.findings == ()


async def test_concealed_instructions_are_high_severity() -> None:
    match = _match(MatchKind.CHAT_TEMPLATE_TOKEN, Detector.INSTRUCTIONS)
    [finding] = (await _evaluate(_event(), match)).findings
    assert finding.severity is Severity.HIGH


async def test_one_finding_per_rule_lists_every_location() -> None:
    result = await _evaluate(
        _event(),
        _match(MatchKind.HTML_COMMENT, pointer="/description"),
        _match(MatchKind.MARKDOWN_COMMENT, pointer="/inputSchema/properties/path/description"),
    )
    [finding] = result.findings
    assert finding.evidence_refs == (
        "/description#0-5",
        "/inputSchema/properties/path/description#0-5",
    )


async def test_the_whole_definition_is_scanned() -> None:
    defense = create({})
    scan = FakeScan()
    await defense.evaluate(_event(), make_context(defense.manifest(), scan=scan))
    assert {detector for detector, _ in scan.scanned} == {Detector.HIDDEN, Detector.INSTRUCTIONS}
    assert all(dict(value) == DEFINITION for _, value in scan.scanned)


async def test_other_stages_are_not_applicable() -> None:
    for other in set(Stage) - MANIFEST.stages:
        result = await _evaluate(_event(other))
        assert result.status is InspectionStatus.NOT_APPLICABLE


async def test_discovery_of_something_other_than_tools_is_not_applicable() -> None:
    result = await _evaluate(make_event(Stage.DISCOVERY, method="prompts/list"))
    assert result.status is InspectionStatus.NOT_APPLICABLE


@pytest.mark.parametrize(
    "event",
    [pytest.param(_event(payload={}), id="empty definition")],
)
async def test_missing_input_has_the_documented_behaviour(event: Event) -> None:
    result = await _evaluate(event)
    assert result.status is InspectionStatus.COMPLETED and result.findings == ()


async def test_a_scan_that_cannot_complete_propagates() -> None:
    class FailingScan(FakeScan):
        async def hidden(self, value: Any) -> ScanResult:
            raise ScanLimitError("too large")

    defense = create({})
    context = make_context(defense.manifest(), scan=FailingScan())
    with pytest.raises(ScanLimitError):
        await defense.evaluate(_event(), context)


@pytest.mark.parametrize("settings", [{"unknown_setting": 1}])
def test_invalid_settings_raise_value_error(settings: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        create(settings)


@pytest.mark.parametrize(("match", "rule"), MALICIOUS)
async def test_rule_ids_are_namespaced_by_the_defense(match: ScanMatch, rule: str) -> None:
    result = await _evaluate(_event(), match)
    assert all(f.rule_id.startswith(DEFENSE_ID + ".") for f in result.findings)
    assert all(f.category == "direct" for f in result.findings)


def test_every_rule_has_a_severity_and_a_reason_without_content() -> None:
    assert set(RULES) >= {CONCEALED_INSTRUCTIONS_RULE}
    for severity, reason in RULES.values():
        assert isinstance(severity, Severity) and reason
