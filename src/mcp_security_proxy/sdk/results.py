"""What a defense returns: an explicit inspection status plus its observations.

An empty findings list alone cannot tell a clean inspection from a skipped
or failed one, so every result carries a status. Only a `completed`
inspection may report findings, signals, or state changes.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from mcp_security_proxy.sdk.frozen import freeze


class InspectionStatus(StrEnum):
    COMPLETED = "completed"
    NOT_APPLICABLE = "not_applicable"
    UNSUPPORTED = "unsupported"
    FAILED = "failed"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class Finding:
    """A concern. Findings never grant permission; Policy decides what they mean."""

    rule_id: str
    category: str
    severity: Severity
    reason: str
    evidence_refs: tuple[str, ...] = ()


@dataclass(frozen=True)
class Signal:
    """A reusable observation, such as sensitive data being seen.

    Not automatically a trusted fact: `producer` (the producing defense's id)
    is checked by the Runner, and consumers decide which producers to trust.
    """

    type: str
    schema_version: int
    producer: str
    value: Any
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", freeze(self.value))


@dataclass(frozen=True)
class StateChange:
    """A proposed update to one key of the defense's own private state.

    `expected_version` is the version the defense read from its context; the
    core commits the change only if the stored version still matches.
    """

    key: str
    expected_version: int
    value: Any

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", freeze(self.value))


@dataclass(frozen=True)
class Result:
    status: InspectionStatus
    findings: tuple[Finding, ...] = ()
    signals: tuple[Signal, ...] = ()
    state_changes: tuple[StateChange, ...] = ()
    detail: str | None = None

    def __post_init__(self) -> None:
        for name in ("findings", "signals", "state_changes"):
            object.__setattr__(self, name, tuple(getattr(self, name)))
        carries_output = self.findings or self.signals or self.state_changes
        if carries_output and self.status is not InspectionStatus.COMPLETED:
            raise ValueError(f"a {self.status} result cannot carry findings, signals, or state")

    @classmethod
    def completed(
        cls,
        findings: Iterable[Finding] = (),
        signals: Iterable[Signal] = (),
        state_changes: Iterable[StateChange] = (),
    ) -> Result:
        return cls(
            InspectionStatus.COMPLETED, tuple(findings), tuple(signals), tuple(state_changes)
        )

    @classmethod
    def not_applicable(cls, detail: str | None = None) -> Result:
        return cls(InspectionStatus.NOT_APPLICABLE, detail=detail)

    @classmethod
    def unsupported(cls, detail: str) -> Result:
        return cls(InspectionStatus.UNSUPPORTED, detail=detail)

    @classmethod
    def failed(cls, detail: str) -> Result:
        return cls(InspectionStatus.FAILED, detail=detail)
