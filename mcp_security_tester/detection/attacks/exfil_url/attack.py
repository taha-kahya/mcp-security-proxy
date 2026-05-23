from urllib.parse import urlparse, parse_qs

from mcp_security_tester.detection.attacks.base import AttackDetector
from mcp_security_tester.detection.attacks.exfil_url.patterns import (
    CREDENTIAL_VALUE_PATTERNS,
    SUSPICIOUS_PARAM_NAMES,
    URL_PATTERN,
)
from mcp_security_tester.core.models import Finding


class ExfilUrlDetector(AttackDetector):
    attack_type = "exfil_url"

    def scan_output(self, tool_name: str, text: str) -> list[Finding]:
        findings = []
        for url in URL_PATTERN.findall(text):
            findings.extend(self._check_url(tool_name, url))
        return findings

    def _check_url(self, tool_name: str, url: str) -> list[Finding]:
        findings = []
        try:
            params = parse_qs(urlparse(url).query)
        except Exception:
            return findings

        for param_name, values in params.items():
            value = values[0] if values else ""

            if SUSPICIOUS_PARAM_NAMES.match(param_name):
                findings.append(Finding(
                    attack_type="exfil_url",
                    severity="HIGH",
                    tool_name=tool_name,
                    field="tool_output",
                    evidence=(
                        f"URL contains credential-named query param '{param_name}': "
                        f"{url[:120]}"
                    ),
                    signal=f"exfil_url_suspicious_param_{param_name.lower()}",
                    reproduction_steps=[
                        f"Call tool '{tool_name}'.",
                        f"Response contains a URL with query param '{param_name}'.",
                        "If the agent fetches this URL, the param value is transmitted to the remote host.",
                        f"Full URL: {url}",
                    ],
                ))
                continue

            for cred_name, pattern in CREDENTIAL_VALUE_PATTERNS:
                if pattern.match(value):
                    findings.append(Finding(
                        attack_type="exfil_url",
                        severity="CRITICAL",
                        tool_name=tool_name,
                        field="tool_output",
                        evidence=(
                            f"URL param '{param_name}' contains {cred_name}-shaped value: "
                            f"{url[:120]}"
                        ),
                        signal=f"exfil_url_credential_value_{cred_name}",
                        reproduction_steps=[
                            f"Call tool '{tool_name}'.",
                            f"Response embeds a {cred_name} credential in URL param '{param_name}'.",
                            "The credential bypasses plain-text scanners by being URL-encoded.",
                            f"Full URL: {url}",
                        ],
                    ))
                    break

        return findings
