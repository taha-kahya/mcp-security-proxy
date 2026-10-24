"""Individual policy rules: which tools a rule targets and what it permits."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from mcp_security_proxy.sdk import ToolId

_SEPARATOR = "/"
WILDCARD = "*"


class Effect(StrEnum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"


@dataclass(frozen=True)
class ToolPattern:
    """`server_id/tool_name` (one tool) or `server_id/*` (every tool on a server).

    Server ids are never wildcarded: granting access to "every server" would
    silently extend to servers added to the config later.
    """

    server_id: str
    tool_name: str

    @classmethod
    def parse(cls, text: str) -> ToolPattern:
        server_id, separator, tool_name = text.partition(_SEPARATOR)
        if not separator or not server_id or not tool_name or _SEPARATOR in tool_name:
            raise ValueError(f"tool pattern must look like 'server_id/tool_name': {text!r}")
        if server_id == WILDCARD:
            raise ValueError(f"server ids cannot be wildcarded: {text!r}")
        return cls(server_id=server_id, tool_name=tool_name)

    @property
    def is_wildcard(self) -> bool:
        return self.tool_name == WILDCARD

    def matches(self, tool_id: ToolId) -> bool:
        if tool_id.server_id != self.server_id:
            return False
        return self.is_wildcard or tool_id.name == self.tool_name

    def __str__(self) -> str:
        return f"{self.server_id}{_SEPARATOR}{self.tool_name}"


@dataclass(frozen=True)
class ToolRule:
    principal_id: str
    pattern: ToolPattern
    effect: Effect

    @property
    def rule_id(self) -> str:
        return f"policy:{self.principal_id}:{self.pattern}"
