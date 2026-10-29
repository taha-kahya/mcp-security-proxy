"""Guard: combine policy, inspection results, and authorization context into one decision."""

from mcp_security_proxy.core.guard.decision import Decision, Outcome
from mcp_security_proxy.core.guard.guard import Guard
from mcp_security_proxy.core.guard.verdicts import DEFAULT_DENY_RULE, UNKNOWN_TOOL_RULE

__all__ = ["DEFAULT_DENY_RULE", "UNKNOWN_TOOL_RULE", "Decision", "Guard", "Outcome"]
