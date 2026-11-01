"""Combine policy, inspection reports, and authorization context into one decision.

Guard neither inspects content nor calls servers. It maps every input to a
verdict and takes the strictest: `block` beats `require_approval`, which
beats `allow`. A defense that reports nothing therefore cannot cancel
another defense's finding, and no finding can loosen what policy denies.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from mcp_security_proxy.core.guard.decision import Decision, Outcome
from mcp_security_proxy.core.guard.verdicts import Verdict, inspection_verdicts, policy_verdict
from mcp_security_proxy.core.runner import InspectionReport
from mcp_security_proxy.sdk import ToolId
from mcp_security_proxy.services.policy import PrincipalPolicy

_NO_OBJECTION = "no security check objected"


class Guard:
    def decide(
        self,
        tool_id: ToolId | None,
        policy: PrincipalPolicy,
        reports: Sequence[InspectionReport] = (),
    ) -> Decision:
        """A tool call: the policy rule for the tool, then every inspection."""
        verdict = policy_verdict(tool_id, policy)
        return _combine([verdict, *inspection_verdicts(reports, policy.enforcement)], policy)

    def review(self, policy: PrincipalPolicy, reports: Sequence[InspectionReport]) -> Decision:
        """Content with no policy rule of its own (a tool definition or a call
        result): only inspections can object."""
        return _combine(inspection_verdicts(reports, policy.enforcement), policy)


def _combine(verdicts: Iterable[Verdict], policy: PrincipalPolicy) -> Decision:
    verdicts = list(verdicts)
    if not verdicts:
        return Decision(Outcome.ALLOW, (), _NO_OBJECTION, policy.policy_version)

    strictest = max(verdict.strictness for verdict in verdicts)
    deciding = [verdict for verdict in verdicts if verdict.strictness == strictest]
    return Decision(
        outcome=deciding[0].outcome,
        rule_refs=tuple(verdict.rule_ref for verdict in deciding),
        reason=deciding[0].reason,
        policy_version=policy.policy_version,
    )
