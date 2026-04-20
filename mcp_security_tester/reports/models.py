from dataclasses import dataclass, field
from typing import Literal

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
AttackType = Literal["tool_poisoning", "rug_pull", "output_injection", "shadowing"]

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


@dataclass
class Finding:
    attack_type: AttackType
    severity: Severity
    tool_name: str
    field: str              # e.g. "description", "inputSchema.properties.path.enum[0]"
    evidence: str           # exact substring that triggered the finding
    signal: str             # detector that fired: "secrecy_directive", "sensitive_path", etc.
    layer: int = 1
    reproduction_steps: list[str] = field(default_factory=list)

    def __lt__(self, other: "Finding") -> bool:
        return _SEVERITY_ORDER[self.severity] < _SEVERITY_ORDER[other.severity]


@dataclass
class Report:
    target: str
    timestamp: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self.findings:
            counts[f.severity] += 1
        return counts

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings)
