"""The single authorization decision made for each agent request."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from uuid import uuid4


class Outcome(StrEnum):
    ALLOW = "allow"
    REDACT = "redact"
    BLOCK = "block"
    REQUIRE_APPROVAL = "require_approval"


@dataclass(frozen=True)
class Decision:
    outcome: Outcome
    rule_refs: tuple[str, ...]
    reason: str
    policy_version: str
    decision_id: str = field(default_factory=lambda: uuid4().hex)
    # For `redact`: the evidence references of every finding mapped to it (D5).
    redactions: tuple[str, ...] = ()

    @property
    def permits_dispatch(self) -> bool:
        """Only `allow` dispatches. `require_approval` stays blocked until
        Approval exists (V5): the architecture requires default deny while
        no approval mechanism is available."""
        return self.outcome is Outcome.ALLOW
