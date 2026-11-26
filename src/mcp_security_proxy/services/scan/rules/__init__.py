"""Scan's rule stage: one rule per detector, each a pure function of the text."""

from mcp_security_proxy.services.scan.rules.base import Evidence, Rule
from mcp_security_proxy.services.scan.rules.commands import CommandsRule
from mcp_security_proxy.services.scan.rules.hidden import HiddenContentRule, hidden_regions
from mcp_security_proxy.services.scan.rules.instructions import InstructionsRule
from mcp_security_proxy.services.scan.rules.lookalikes import LookalikesRule
from mcp_security_proxy.services.scan.rules.secrets import SecretsRule

__all__ = [
    "CommandsRule",
    "Evidence",
    "HiddenContentRule",
    "InstructionsRule",
    "LookalikesRule",
    "Rule",
    "SecretsRule",
    "hidden_regions",
]
