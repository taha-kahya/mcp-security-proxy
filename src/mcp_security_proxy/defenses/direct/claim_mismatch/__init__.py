"""Direct defense: tool annotations that contradict the operator's classification."""

from mcp_security_proxy.defenses.direct.claim_mismatch.defense import (
    CLOSED_WORLD_RULE,
    DEFENSE_ID,
    NON_DESTRUCTIVE_RULE,
    READ_ONLY_RULE,
    UNCLASSIFIED_RULE,
    ClaimMismatchDefense,
    ClaimMismatchSettings,
    create,
)

__all__ = [
    "CLOSED_WORLD_RULE",
    "DEFENSE_ID",
    "NON_DESTRUCTIVE_RULE",
    "READ_ONLY_RULE",
    "UNCLASSIFIED_RULE",
    "ClaimMismatchDefense",
    "ClaimMismatchSettings",
    "create",
]
