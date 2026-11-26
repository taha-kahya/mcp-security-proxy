"""Combine policy, inspection reports, and authorization context into one decision.

Guard neither inspects content nor calls servers. It maps every input to a
verdict and takes the strictest: `block` beats `require_approval`, which
beats `redact`, which beats `allow`. A defense that reports nothing therefore cannot cancel
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
        """A tool call: the policy rule for the tool, then every inspection.

        A call can't be redacted: a `redact` verdict on the tool's definition
        means its calls need approval (ADR 0016), which blocks until V5.
        """
        verdict = policy_verdict(tool_id, policy)
        inspections = [_for_calls(v) for v in inspection_verdicts(reports, policy.enforcement)]
        return _combine([verdict, *inspections], policy)

    def review(self, policy: PrincipalPolicy, reports: Sequence[InspectionReport]) -> Decision:
        """Content with no policy rule of its own (a tool definition or a call
        result): only inspections can object. A `redact` decision lists the
        evidence references to redact."""
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
        redactions=tuple(sorted({ref for v in deciding for ref in v.redactions})),
    )


_REDACTED_CALL_REASON = (
    "this tool's definition was redacted by a security check; calls require approval, "
    "and no approval mechanism is available"
)


def _for_calls(verdict: Verdict) -> Verdict:
    if verdict.outcome is not Outcome.REDACT:
        return verdict
    return Verdict(Outcome.REQUIRE_APPROVAL, verdict.rule_ref, _REDACTED_CALL_REASON)
