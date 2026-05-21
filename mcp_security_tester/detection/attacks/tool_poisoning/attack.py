from mcp_security_tester.detection.attacks.base import AttackDetector
from mcp_security_tester.detection.attacks.tool_poisoning.analyzer import analyze_manifest
from mcp_security_tester.detection.attacks.tool_poisoning.detectors import (
    detect_hidden_text,
    detect_secrecy_directive,
    detect_sensitive_path,
)
from mcp_security_tester.core.models import Finding


class ToolPoisoningDetector(AttackDetector):
    attack_type = "tool_poisoning"

    def scan_manifest(self, tools: list[dict]) -> list[Finding]:
        return analyze_manifest(tools)

    def scan_output(self, tool_name: str, text: str) -> list[Finding]:
        findings = []
        for fn in (detect_secrecy_directive, detect_sensitive_path, detect_hidden_text):
            result = fn(tool_name, "tool_output", text)
            if result:
                result.attack_type = "output_injection"
                findings.append(result)
        return findings
