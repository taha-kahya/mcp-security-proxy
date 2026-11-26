"""ClaimMismatch, tested with SDK helpers only: no proxy, no servers.

Cases come from the attack taxonomy and public descriptions (the MCP
specification's tool annotations), never from the evaluation experiments.
"""

from __future__ import annotations

from typing import Any

import pytest

from mcp_security_proxy.defenses.direct.claim_mismatch import (
    CLOSED_WORLD_RULE,
    DEFENSE_ID,
    NON_DESTRUCTIVE_RULE,
    READ_ONLY_RULE,
    UNCLASSIFIED_RULE,
    create,
)
from mcp_security_proxy.defenses.direct.claim_mismatch.defense import MANIFEST
from mcp_security_proxy.sdk import (
    Capability,
    Event,
    InspectionStatus,
    Operation,
    Result,
    Severity,
    Stage,
)
from mcp_security_proxy.sdk.testing import TEST_TOOL, FakeRegistry, action, make_context, make_event


def _definition(**annotations: Any) -> dict[str, Any]:
    definition: dict[str, Any] = {"name": "sync_contacts", "description": "Syncs contacts."}
    if annotations:
        definition["annotations"] = annotations
    return definition


def _event(stage: Stage = Stage.DISCOVERY, **fields: Any) -> Event:
    """Like the proxy's events: discovery events are `tools/list`."""
    method = "tools/list" if stage is Stage.DISCOVERY else "tools/call"
    return make_event(stage, method=method, **fields)


async def _evaluate(event: Event, operation: Operation | None = None, **settings: Any) -> Result:
    actions = {} if operation is None else {TEST_TOOL: action(operation)}
    defense = create(settings)
    context = make_context(defense.manifest(), registry=FakeRegistry(actions=actions))
    return await defense.evaluate(event, context)


MALICIOUS = [
    pytest.param({"readOnlyHint": True}, Operation.SEND, READ_ONLY_RULE, id="read-only send"),
    pytest.param({"readOnlyHint": True}, Operation.WRITE, READ_ONLY_RULE, id="read-only write"),
    pytest.param({"readOnlyHint": True}, Operation.EXECUTE, READ_ONLY_RULE, id="read-only execute"),
    pytest.param(
        {"destructiveHint": False}, Operation.WRITE, NON_DESTRUCTIVE_RULE, id="harmless write"
    ),
    pytest.param(
        {"destructiveHint": False},
        Operation.EXECUTE,
        NON_DESTRUCTIVE_RULE,
        id="harmless execute",
    ),
    pytest.param({"openWorldHint": False}, Operation.SEND, CLOSED_WORLD_RULE, id="closed send"),
    pytest.param({"readOnlyHint": True}, None, UNCLASSIFIED_RULE, id="read-only unclassified"),
    pytest.param(
        {"openWorldHint": False}, Operation.UNKNOWN, UNCLASSIFIED_RULE, id="closed unknown"
    ),
]
BENIGN_TWINS = [
    pytest.param({"readOnlyHint": True}, Operation.READ, id="read-only read"),
    pytest.param({"destructiveHint": False}, Operation.READ, id="harmless read"),
    pytest.param({"destructiveHint": False}, Operation.SEND, id="harmless send"),
    pytest.param({"openWorldHint": False}, Operation.WRITE, id="closed write"),
    pytest.param({}, Operation.SEND, id="no annotations, send"),
    pytest.param({}, None, id="no annotations, unclassified"),
    # The cautious values claim nothing, whatever the operation.
    pytest.param(
        {"readOnlyHint": False, "destructiveHint": True, "openWorldHint": True},
        None,
        id="cautious values, unclassified",
    ),
    # Not compared: tools.yaml has no idempotence. A title is not a claim.
    pytest.param({"idempotentHint": True, "title": "Read only!"}, Operation.SEND, id="other"),
]


@pytest.mark.parametrize(("annotations", "operation", "rule"), MALICIOUS)
async def test_flags_malicious_cases(
    annotations: dict[str, Any], operation: Operation | None, rule: str
) -> None:
    result = await _evaluate(_event(payload=_definition(**annotations)), operation)
    assert result.status is InspectionStatus.COMPLETED
    assert [f.rule_id for f in result.findings] == [rule]


@pytest.mark.parametrize(("annotations", "operation"), BENIGN_TWINS)
async def test_allows_matched_benign_cases(
    annotations: dict[str, Any], operation: Operation | None
) -> None:
    result = await _evaluate(_event(payload=_definition(**annotations)), operation)
    assert result.status is InspectionStatus.COMPLETED and result.findings == ()


@pytest.mark.parametrize(
    ("rule", "severity"),
    [
        (READ_ONLY_RULE, Severity.HIGH),
        (NON_DESTRUCTIVE_RULE, Severity.MEDIUM),
        (CLOSED_WORLD_RULE, Severity.MEDIUM),
        (UNCLASSIFIED_RULE, Severity.LOW),
    ],
)
async def test_severities(rule: str, severity: Severity) -> None:
    claims = {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False}
    operation = {
        READ_ONLY_RULE: Operation.SEND,
        NON_DESTRUCTIVE_RULE: Operation.WRITE,
        CLOSED_WORLD_RULE: Operation.SEND,
        UNCLASSIFIED_RULE: None,
    }[rule]
    result = await _evaluate(_event(payload=_definition(**claims)), operation)
    assert {f.rule_id: f.severity for f in result.findings}[rule] is severity


async def test_every_contradicted_claim_is_reported_with_its_pointer() -> None:
    claims = {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False}
    result = await _evaluate(_event(payload=_definition(**claims)), Operation.SEND)
    assert {f.rule_id: f.evidence_refs for f in result.findings} == {
        READ_ONLY_RULE: ("/annotations/readOnlyHint",),
        CLOSED_WORLD_RULE: ("/annotations/openWorldHint",),
    }


async def test_unclassified_names_every_claim_once() -> None:
    claims = {"readOnlyHint": True, "openWorldHint": False}
    result = await _evaluate(_event(payload=_definition(**claims)))
    assert [f.evidence_refs for f in result.findings] == [
        ("/annotations/openWorldHint", "/annotations/readOnlyHint")
    ]


async def test_evidence_never_quotes_the_definition() -> None:
    definition = _definition(readOnlyHint=True)
    definition["description"] = "SECRET-DESCRIPTION-TEXT"
    result = await _evaluate(_event(payload=definition), Operation.SEND)
    for finding in result.findings:
        assert "SECRET" not in finding.reason
        assert all("SECRET" not in ref for ref in finding.evidence_refs)


async def test_other_stages_are_not_applicable() -> None:
    for other in set(Stage) - MANIFEST.stages:
        result = await _evaluate(_event(other, payload=_definition(readOnlyHint=True)))
        assert result.status is InspectionStatus.NOT_APPLICABLE


async def test_other_discovery_methods_are_not_applicable() -> None:
    event = make_event(Stage.DISCOVERY, method="prompts/list", payload=_definition(readOnlyHint=1))
    result = await _evaluate(event)
    assert result.status is InspectionStatus.NOT_APPLICABLE


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param({}, id="empty definition"),
        pytest.param({"name": "x", "annotations": None}, id="null annotations"),
        pytest.param(
            {"name": "x", "annotations": ["readOnlyHint"]}, id="annotations not an object"
        ),
        pytest.param({"name": "x", "annotations": {"readOnlyHint": "true"}}, id="string hint"),
        pytest.param({"name": "x", "annotations": {"readOnlyHint": 1}}, id="number hint"),
    ],
)
async def test_missing_or_malformed_annotations_claim_nothing(payload: dict[str, Any]) -> None:
    result = await _evaluate(_event(payload=payload), Operation.SEND)
    assert result.status is InspectionStatus.COMPLETED and result.findings == ()


@pytest.mark.parametrize("settings", [{"unknown_setting": 1}, {"report_unclassified": False}])
def test_invalid_settings_raise_value_error(settings: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        create(settings)


@pytest.mark.parametrize(("annotations", "operation", "rule"), MALICIOUS)
async def test_rule_ids_are_namespaced_by_the_defense(
    annotations: dict[str, Any], operation: Operation | None, rule: str
) -> None:
    result = await _evaluate(_event(payload=_definition(**annotations)), operation)
    assert result.findings
    assert all(f.rule_id.startswith(DEFENSE_ID + ".") for f in result.findings)


def test_manifest_declares_only_the_registry() -> None:
    assert MANIFEST.required_capabilities == {Capability.REGISTRY}
    assert not MANIFEST.produced_signals
