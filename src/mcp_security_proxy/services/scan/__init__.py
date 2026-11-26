"""Scan: shared content analysis that defenses call through `context.scan`.

Only the rule stage exists so far; see `scanner.py`.
"""

from mcp_security_proxy.services.scan.scanner import (
    DEFAULT_MAX_CHARS,
    RULES_VERSION,
    RuleScanner,
)

__all__ = ["DEFAULT_MAX_CHARS", "RULES_VERSION", "RuleScanner"]
