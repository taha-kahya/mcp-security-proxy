from mcp_security_tester.detection.attacks.base import AttackDetector
from mcp_security_tester.detection.attacks.unicode_injection.patterns import (
    DIRECTIONAL_OVERRIDES,
    INSTRUCTION_PATTERN,
    INVISIBLE_CHARS,
    INVISIBLE_CLUSTER_THRESHOLD,
)
from mcp_security_tester.core.models import Finding


class UnicodeInjectionDetector(AttackDetector):
    attack_type = "unicode_injection"

    def scan_manifest(self, tools: list[dict]) -> list[Finding]:
        findings = []
        for tool in tools:
            for field in ("description", "name"):
                text = tool.get(field, "") or ""
                findings.extend(self._scan_text(tool.get("name", "?"), f"manifest.{field}", text))
        return findings

    def scan_output(self, tool_name: str, text: str) -> list[Finding]:
        return self._scan_text(tool_name, "tool_output", text)

    def _scan_text(self, tool_name: str, field: str, text: str) -> list[Finding]:
        findings = []

        for char, name in DIRECTIONAL_OVERRIDES.items():
            if char in text:
                findings.append(Finding(
                    attack_type="unicode_injection",
                    severity="HIGH",
                    tool_name=tool_name,
                    field=field,
                    evidence=f"Directional override U+{ord(char):04X} ({name}) in {field}",
                    signal=f"unicode_{name}",
                    reproduction_steps=[
                        f"Inspect raw bytes of '{tool_name}' {field}.",
                        f"U+{ord(char):04X} ({name}) flips text rendering direction.",
                        "Human reviewers see text in one direction; LLM processes the logical (reversed) string.",
                        "Run: python -c \"print(repr(output))\" to expose the raw character.",
                    ],
                ))

        invisible_found: dict[str, int] = {}
        for char, name in INVISIBLE_CHARS.items():
            count = text.count(char)
            if count > 0:
                invisible_found[name] = count

        total = sum(invisible_found.values())
        if total >= INVISIBLE_CLUSTER_THRESHOLD:
            has_instruction = bool(INSTRUCTION_PATTERN.search(text))
            severity = "HIGH" if has_instruction else "MEDIUM"
            char_summary = ", ".join(f"{n}×{name}" for name, n in invisible_found.items())
            findings.append(Finding(
                attack_type="unicode_injection",
                severity=severity,
                tool_name=tool_name,
                field=field,
                evidence=f"{total} invisible Unicode chars in {field}: {char_summary}",
                signal="unicode_invisible_cluster",
                reproduction_steps=[
                    f"Inspect raw bytes of '{tool_name}' {field}.",
                    f"Found {total} invisible characters ({char_summary}).",
                    "These characters are stripped by most terminals and log viewers.",
                    "The LLM processes the full string including any hidden instructions.",
                    "Run: python -c \"print(repr(output))\" to expose hidden content.",
                ],
            ))

        return findings
