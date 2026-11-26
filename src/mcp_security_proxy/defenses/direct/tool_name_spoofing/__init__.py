"""Direct defense: tool names that impersonate other tools."""

from mcp_security_proxy.defenses.direct.tool_name_spoofing.defense import (
    CONFUSABLE_NAME_RULE,
    DEFENSE_ID,
    MIXED_SCRIPT_RULE,
    OTHER_SERVER_TOOL_RULE,
    ToolNameSpoofingDefense,
    ToolNameSpoofingSettings,
    create,
)

__all__ = [
    "CONFUSABLE_NAME_RULE",
    "DEFENSE_ID",
    "MIXED_SCRIPT_RULE",
    "OTHER_SERVER_TOOL_RULE",
    "ToolNameSpoofingDefense",
    "ToolNameSpoofingSettings",
    "create",
]
