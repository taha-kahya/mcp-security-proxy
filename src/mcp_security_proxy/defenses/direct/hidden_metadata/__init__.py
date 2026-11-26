"""Direct defense: content hidden in tool definitions."""

from mcp_security_proxy.defenses.direct.hidden_metadata.defense import (
    CONCEALED_INSTRUCTIONS_RULE,
    DEFENSE_ID,
    HiddenMetadataDefense,
    HiddenMetadataSettings,
    create,
)

__all__ = [
    "CONCEALED_INSTRUCTIONS_RULE",
    "DEFENSE_ID",
    "HiddenMetadataDefense",
    "HiddenMetadataSettings",
    "create",
]
