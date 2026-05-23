from mcp_security_tester.detection.attacks.base import AttackDetector
from mcp_security_tester.detection.attacks.credential_leak.attack import CredentialLeakDetector
from mcp_security_tester.detection.attacks.rug_pull.attack import RugPullDetector
from mcp_security_tester.detection.attacks.tool_poisoning.attack import ToolPoisoningDetector
from mcp_security_tester.detection.attacks.unicode_injection.attack import UnicodeInjectionDetector
from mcp_security_tester.detection.attacks.exfil_url.attack import ExfilUrlDetector


def build_registry(server_name: str) -> list[AttackDetector]:
    return [
        ToolPoisoningDetector(),
        RugPullDetector(server_name),
        CredentialLeakDetector(),
        UnicodeInjectionDetector(),
        ExfilUrlDetector(),
    ]
