"""Behavior of the public SDK contract types."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from typing import Any

import pytest

from mcp_security_proxy.sdk import (
    Capability,
    CapabilityNotGrantedError,
    Finding,
    InspectionStatus,
    Manifest,
    Operation,
    PrivateState,
    Result,
    Severity,
    Signal,
    Stage,
    VersionedValue,
    freeze,
    thaw,
)
from mcp_security_proxy.sdk.testing import (
    FakePolicy,
    history,
    make_context,
    make_event,
    operation,
)

FINDING = Finding("rule", "sample", Severity.HIGH, "reason")


def _manifest(**overrides: Any) -> Manifest:
    fields: dict[str, Any] = {
        "id": "sample",
        "version": "1.0.0",
        "sdk_version_range": ">=1.0,<2",
        "stages": {Stage.BEFORE_EXECUTION},
    }
    return Manifest(**(fields | overrides))


def test_event_payload_is_deeply_immutable() -> None:
    source = {"arguments": {"items": [1, {"k": "v"}]}}
    event = make_event(payload=source)
    source["arguments"]["items"].append(2)

    assert event.payload["arguments"]["items"] == (1, freeze({"k": "v"}))
    with pytest.raises(TypeError):
        event.payload["arguments"]["new"] = 1  # type: ignore[index]
    with pytest.raises(FrozenInstanceError):
        event.stage = Stage.DISCOVERY  # type: ignore[misc]


def test_thaw_restores_plain_json() -> None:
    value = {"a": [1, {"b": (2, 3)}]}
    assert thaw(freeze(value)) == {"a": [1, {"b": [2, 3]}]}


@pytest.mark.parametrize(
    "status",
    [InspectionStatus.FAILED, InspectionStatus.UNSUPPORTED, InspectionStatus.NOT_APPLICABLE],
)
def test_only_completed_results_carry_findings(status: InspectionStatus) -> None:
    with pytest.raises(ValueError):
        Result(status, findings=(FINDING,))


def test_result_statuses_are_distinguishable_from_a_clean_inspection() -> None:
    clean = Result.completed()
    assert clean.status is InspectionStatus.COMPLETED and clean.findings == ()
    assert Result.failed("boom").status is InspectionStatus.FAILED
    assert Result.unsupported("image").status is InspectionStatus.UNSUPPORTED


def test_signal_value_is_frozen() -> None:
    signal = Signal("sensitivity", 1, "sample", {"level": ["high"]})
    assert signal.value["level"] == ("high",)


@pytest.mark.parametrize("bad_id", ["", "Sample", "has-dash", "1st"])
def test_manifest_rejects_invalid_ids(bad_id: str) -> None:
    with pytest.raises(ValueError):
        _manifest(id=bad_id)


def test_manifest_requires_a_stage() -> None:
    with pytest.raises(ValueError):
        _manifest(stages=set())


def test_context_grants_only_declared_capabilities() -> None:
    manifest = _manifest(required_capabilities={Capability.HISTORY})
    context = make_context(manifest, history=history(operation(op=Operation.SEND)))

    assert len(context.history.operations) == 1
    with pytest.raises(CapabilityNotGrantedError):
        _ = context.registry
    with pytest.raises(CapabilityNotGrantedError):
        _ = context.private_state


def test_make_context_refuses_capabilities_the_manifest_did_not_declare() -> None:
    with pytest.raises(ValueError):
        make_context(_manifest(), policy=FakePolicy())


def test_context_only_exposes_required_signal_types() -> None:
    manifest = _manifest(required_signals={"wanted"})
    signals = [Signal("wanted", 1, "p", True), Signal("other", 1, "p", True)]
    context = make_context(manifest, signals=signals)

    assert [s.type for s in context.signals] == ["wanted"]


def test_private_state_reports_missing_keys_as_version_zero() -> None:
    state = PrivateState({"seen": VersionedValue(3, ["x"])})
    assert state.get("seen").version == 3 and state.get("seen").exists
    assert state.get("missing").version == 0 and not state.get("missing").exists
