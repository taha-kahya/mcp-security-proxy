from mcp_security_tester.detection.attacks.base import AttackDetector
from mcp_security_tester.detection.attacks.credential_leak.patterns import CREDENTIAL_PATTERNS
from mcp_security_tester.core.models import Finding


class CredentialLeakDetector(AttackDetector):
    attack_type = "credential_leak"

    def scan_output(self, tool_name: str, text: str) -> list[Finding]:
        findings = []
        for signal_name, pattern in CREDENTIAL_PATTERNS:
            match = pattern.search(text)
            if match:
                findings.append(Finding(
                    attack_type="credential_leak",
                    severity="CRITICAL",
                    tool_name=tool_name,
                    field="tool_output",
                    evidence=f"Credential pattern '{signal_name}' found: {match.group()[:40]}...",
                    signal=f"credential_leak_{signal_name}",
                    reproduction_steps=[
                        f"Call tool '{tool_name}'.",
                        f"Response contains a {signal_name} credential in plain text.",
                        "Credentials in tool outputs can be exfiltrated via subsequent injection attacks.",
                    ],
                ))
        return findings
