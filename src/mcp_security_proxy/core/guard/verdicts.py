"""Turn each input to a decision into a verdict: an outcome and the rule behind it.

Policy rules and inspection reports are mapped separately, then Guard takes
the strictest verdict. Reasons are fixed strings, never text supplied by a
defense, server, or agent, because they are shown to the agent.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass

from mcp_security_proxy.core.guard.decision import Outcome
from mcp_security_proxy.core.runner import InspectionReport
from mcp_security_proxy.sdk import InspectionStatus, ToolId
from mcp_security_proxy.services.policy import (
    Effect,
    Enforcement,
    EnforcementPolicy,
    PrincipalPolicy,
)

UNKNOWN_TOOL_RULE = "routing:unknown_tool"
DEFAULT_DENY_RULE = "policy:default_deny"

_STRICTNESS = {Outcome.ALLOW: 0, Outcome.REDACT: 1, Outcome.REQUIRE_APPROVAL: 2, Outcome.BLOCK: 3}

_OUTCOME_BY_EFFECT = {
    Effect.ALLOW: Outcome.ALLOW,
    Effect.REQUIRE_APPROVAL: Outcome.REQUIRE_APPROVAL,
}
_OUTCOME_BY_ENFORCEMENT = {
    Enforcement.ALLOW: Outcome.ALLOW,
    Enforcement.REDACT: Outcome.REDACT,
    Enforcement.REQUIRE_APPROVAL: Outcome.REQUIRE_APPROVAL,
    Enforcement.BLOCK: Outcome.BLOCK,
}

_POLICY_REASONS = {
    Outcome.ALLOW: "permitted by policy",
    Outcome.REQUIRE_APPROVAL: "requires approval, and no approval mechanism is available",
}
_FINDING_REASONS = {
    Outcome.ALLOW: "finding recorded",
    Outcome.REDACT: "flagged content withheld by a security check",
    Outcome.REQUIRE_APPROVAL: "a security check requires approval, and no approval "
    "mechanism is available",
    Outcome.BLOCK: "blocked by a security check",
}
_INCOMPLETE_REASONS = {
    Outcome.ALLOW: "security check incomplete, allowed by policy",
    Outcome.REDACT: "a security check could not complete; content exposed for approval only",
    Outcome.REQUIRE_APPROVAL: "a security check could not complete and approval is unavailable",
    Outcome.BLOCK: "a security check could not complete",
}


@dataclass(frozen=True)
class Verdict:
    outcome: Outcome
    rule_ref: str
    reason: str
    # Evidence references to redact, for a `redact` verdict on a finding.
    redactions: tuple[str, ...] = ()

    @property
    def strictness(self) -> int:
        return _STRICTNESS[self.outcome]


def policy_verdict(tool_id: ToolId | None, policy: PrincipalPolicy) -> Verdict:
    """`tool_id` is None when the requested name resolves to no known tool."""
    if tool_id is None:
        return Verdict(Outcome.BLOCK, UNKNOWN_TOOL_RULE, "no such tool")
    rule = policy.rule_for(tool_id)
    if rule is None:
        return Verdict(Outcome.BLOCK, DEFAULT_DENY_RULE, "not permitted by policy")
    outcome = _OUTCOME_BY_EFFECT[rule.effect]
    return Verdict(outcome, rule.rule_id, _POLICY_REASONS[outcome])


def inspection_verdicts(
    reports: Iterable[InspectionReport], enforcement: EnforcementPolicy
) -> Iterator[Verdict]:
    for report in reports:
        rules = enforcement.for_defense(report.defense_id)
        if report.status in (InspectionStatus.FAILED, InspectionStatus.UNSUPPORTED):
            outcome = _OUTCOME_BY_ENFORCEMENT[rules.for_status(report.status)]
            rule_ref = f"inspection:{report.defense_id}:{report.status}"
            yield Verdict(outcome, rule_ref, _INCOMPLETE_REASONS[outcome])
        for finding in report.result.findings:
            outcome = _OUTCOME_BY_ENFORCEMENT[rules.for_finding(finding)]
            rule_ref = f"defense:{report.defense_id}:{finding.rule_id}"
            redactions = finding.evidence_refs if outcome is Outcome.REDACT else ()
            yield Verdict(outcome, rule_ref, _FINDING_REASONS[outcome], redactions)
