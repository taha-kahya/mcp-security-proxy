import fnmatch
from collections import Counter

from mcp_security_tester.anomaly_detector.patterns import (
    HIGH_RISK_TOOLS,
    SEQUENCE_PATTERNS,
    SequencePattern,
)
from mcp_security_tester.call_logger.logger import ToolCall
from mcp_security_tester.reports.models import Finding



class AnomalyDetector:
    def __init__(self, approved_tools: list[str] | None = None):
        self._approved_tools = set(approved_tools or [])
        self._reported: set[str] = set()  # ← ADD THIS


    def set_approved_tools(self, tool_names: list[str]) -> None:
        self._approved_tools = set(tool_names)

    def check(self, recent_calls: list[ToolCall]) -> list[Finding]:
        all_findings: list[Finding] = []
        all_findings.extend(_check_sequences(recent_calls))
        all_findings.extend(_check_rapid_repeat(recent_calls))
        if self._approved_tools:
            all_findings.extend(_check_unapproved(recent_calls, self._approved_tools))

        new_findings = []
        for f in all_findings:
            key = f"{f.signal}:{f.tool_name}:{f.evidence}"
            if key not in self._reported:
                self._reported.add(key)
                new_findings.append(f)

        return new_findings

def _check_sequences(calls: list[ToolCall]) -> list[Finding]:
    findings: list[Finding] = []
    for i, call in enumerate(calls):
        for pattern in SEQUENCE_PATTERNS:
            if not pattern.matches_trigger(call.tool_name):
                continue
            window = calls[i + 1: i + 1 + pattern.max_gap_calls]
            for following in window:
                if pattern.matches_following(following.tool_name):
                    findings.append(Finding(
                        attack_type="tool_poisoning",
                        severity=pattern.severity,
                        tool_name=following.tool_name,
                        field="call_sequence",
                        evidence=f"'{call.tool_name}' → '{following.tool_name}' matches pattern '{pattern.name}'",
                        signal=f"anomaly_{pattern.name}",
                        reproduction_steps=[
                            f"Observed call sequence: {call.tool_name} → {following.tool_name}.",
                            f"Pattern: {pattern.description}",
                            "This sequence may indicate an injection-driven exfiltration attempt.",
                        ],
                    ))
                    break
    return findings


def _check_rapid_repeat(calls: list[ToolCall], window: int = 5, threshold: int = 4) -> list[Finding]:
    """Flag any tool called more than `threshold` times in the last `window` calls."""
    findings: list[Finding] = []
    recent = calls[-window:]
    counts = Counter(c.tool_name for c in recent)
    for tool_name, count in counts.items():
        if count >= threshold:
            findings.append(Finding(
                attack_type="tool_poisoning",
                severity="MEDIUM",
                tool_name=tool_name,
                field="call_sequence",
                evidence=f"'{tool_name}' called {count} times in last {window} calls",
                signal="anomaly_rapid_repeat",
                reproduction_steps=[
                    f"Tool '{tool_name}' was called {count} times in rapid succession.",
                    "This may indicate an injection-induced loop.",
                ],
            ))
    return findings


def _check_unapproved(calls: list[ToolCall], approved: set[str]) -> list[Finding]:
    """Flag tool calls that weren't in the approved manifest."""
    findings: list[Finding] = []
    seen: set[str] = set()
    for call in calls:
        if call.tool_name not in approved and call.tool_name not in seen:
            seen.add(call.tool_name)
            findings.append(Finding(
                attack_type="tool_poisoning",
                severity="CRITICAL",
                tool_name=call.tool_name,
                field="call_sequence",
                evidence=f"Tool '{call.tool_name}' was called but was not in the approved manifest",
                signal="anomaly_unapproved_tool",
                reproduction_steps=[
                    f"Tool '{call.tool_name}' was invoked by the agent.",
                    "This tool was not present in the manifest at connect time.",
                    "Possible injection-driven phantom tool call.",
                ],
            ))
    return findings
