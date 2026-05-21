from mcp_security_tester.core.logger import ToolCall
from mcp_security_tester.core.models import Finding


class AttackDetector:
    attack_type: str = ""

    def scan_manifest(self, tools: list[dict]) -> list[Finding]:
        return []

    def scan_output(self, tool_name: str, text: str) -> list[Finding]:
        return []

    def check_sequence(self, recent_calls: list[ToolCall]) -> list[Finding]:
        return []
