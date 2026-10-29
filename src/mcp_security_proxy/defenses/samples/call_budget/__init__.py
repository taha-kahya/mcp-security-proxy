"""Sample defense: cap side-effecting operations per task."""

from mcp_security_proxy.defenses.samples.call_budget.defense import (
    DEFENSE_ID,
    EXCEEDED_RULE,
    CallBudgetDefense,
    CallBudgetSettings,
    create,
)

__all__ = ["DEFENSE_ID", "EXCEEDED_RULE", "CallBudgetDefense", "CallBudgetSettings", "create"]
