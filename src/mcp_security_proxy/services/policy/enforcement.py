"""What defense findings and inspection statuses mean for enforcement.

Defenses only report; the operator decides what a report means. The policy
file's `enforcement` section sets the defaults, and a defense's own config
file (also operator-written) may override them for that defense alone.
Anything left unspecified is `block`, so a crashed, timed-out, or
unsupported inspection never fails open by omission.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType

from pydantic import BaseModel, ConfigDict

from mcp_security_proxy.sdk import Finding, InspectionStatus, Severity


class Enforcement(StrEnum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    BLOCK = "block"


_STRICTNESS = {Enforcement.ALLOW: 0, Enforcement.REQUIRE_APPROVAL: 1, Enforcement.BLOCK: 2}


class EnforcementEntry(BaseModel):
    """The YAML shape, shared by the policy file and defense configs.

    Every field is optional so an override can change just one setting.
    `findings` maps a finding's `rule_id` to its enforcement and takes
    precedence over `by_severity`.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    by_severity: dict[Severity, Enforcement] = {}
    findings: dict[str, Enforcement] = {}
    on_failure: Enforcement | None = None
    on_unsupported: Enforcement | None = None


@dataclass(frozen=True)
class DefenseEnforcement:
    """Resolved enforcement for one defense."""

    by_severity: Mapping[Severity, Enforcement] = field(
        default_factory=lambda: MappingProxyType({s: Enforcement.BLOCK for s in Severity})
    )
    findings: Mapping[str, Enforcement] = field(default_factory=lambda: MappingProxyType({}))
    on_failure: Enforcement = Enforcement.BLOCK
    on_unsupported: Enforcement = Enforcement.BLOCK

    def for_finding(self, finding: Finding) -> Enforcement:
        return self.findings.get(finding.rule_id, self.by_severity[finding.severity])

    def for_status(self, status: InspectionStatus) -> Enforcement:
        """Enforcement for an inspection that did not complete."""
        if status is InspectionStatus.FAILED:
            return self.on_failure
        if status is InspectionStatus.UNSUPPORTED:
            return self.on_unsupported
        return Enforcement.ALLOW

    def overlaid_with(self, entry: EnforcementEntry) -> DefenseEnforcement:
        return DefenseEnforcement(
            by_severity=MappingProxyType({**self.by_severity, **entry.by_severity}),
            findings=MappingProxyType({**self.findings, **entry.findings}),
            on_failure=entry.on_failure or self.on_failure,
            on_unsupported=entry.on_unsupported or self.on_unsupported,
        )

    def loosened_from(self, baseline: DefenseEnforcement) -> list[str]:
        """Settings less strict here than in `baseline`, for startup warnings."""
        loosened = [
            f"{name}: {mine} (default {theirs})"
            for name, mine, theirs in (
                ("on_failure", self.on_failure, baseline.on_failure),
                ("on_unsupported", self.on_unsupported, baseline.on_unsupported),
                *(
                    (f"severity {s}", self.by_severity[s], baseline.by_severity[s])
                    for s in Severity
                ),
            )
            if _STRICTNESS[mine] < _STRICTNESS[theirs]
        ]
        loosened += [
            f"finding {rule_id}: {enforcement}"
            for rule_id, enforcement in sorted(self.findings.items())
            if enforcement is not Enforcement.BLOCK
        ]
        return loosened


class EnforcementPolicy:
    def __init__(
        self,
        defaults: DefenseEnforcement | None = None,
        overrides: Mapping[str, DefenseEnforcement] | None = None,
    ) -> None:
        self._defaults = defaults or DefenseEnforcement()
        self._overrides = MappingProxyType(dict(overrides or {}))

    @classmethod
    def from_entries(
        cls, defaults: EnforcementEntry | None, overrides: Mapping[str, EnforcementEntry]
    ) -> EnforcementPolicy:
        base = DefenseEnforcement().overlaid_with(defaults or EnforcementEntry())
        return cls(base, {d: base.overlaid_with(entry) for d, entry in overrides.items()})

    def for_defense(self, defense_id: str) -> DefenseEnforcement:
        return self._overrides.get(defense_id, self._defaults)

    def loosened_overrides(self) -> dict[str, list[str]]:
        return {
            defense_id: loosened
            for defense_id, enforcement in sorted(self._overrides.items())
            if (loosened := enforcement.loosened_from(self._defaults))
        }
