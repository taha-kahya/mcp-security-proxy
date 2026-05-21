"""
Orchestrates all detectors across a full MCP tool manifest.
Scans every string field recursively — Full-Schema Poisoning coverage.
"""

from mcp_security_tester.detection.attacks.tool_poisoning.detectors import (
    detect_cross_tool_reference,
    detect_hidden_text,
    detect_imperative_verb,
    detect_secrecy_directive,
    detect_sensitive_path,
)
from mcp_security_tester.core.models import Finding

_SOLO_DETECTORS = [
    detect_imperative_verb,
    detect_secrecy_directive,
    detect_sensitive_path,
    detect_hidden_text,
]


def analyze_manifest(tools: list[dict]) -> list[Finding]:
    all_tool_names = [t.get("name", "") for t in tools]
    findings: list[Finding] = []
    for tool in tools:
        findings.extend(_analyze_tool(tool, all_tool_names))
    return sorted(findings)


def _analyze_tool(tool: dict, all_tool_names: list[str]) -> list[Finding]:
    tool_name = tool.get("name", "<unknown>")
    findings: list[Finding] = []

    for field_path, text in _iter_strings(tool):
        if field_path == "name":
            continue

        for detector in _SOLO_DETECTORS:
            result = detector(tool_name, field_path, text)
            if result:
                findings.append(result)

        result = detect_cross_tool_reference(tool_name, field_path, text, all_tool_names)
        if result:
            findings.append(result)

    return findings


def _iter_strings(obj: object, path: str = "") -> list[tuple[str, str]]:
    results: list[tuple[str, str]] = []

    if isinstance(obj, str):
        results.append((path, obj))
    elif isinstance(obj, dict):
        for key, value in obj.items():
            child_path = f"{path}.{key}" if path else key
            results.extend(_iter_strings(value, child_path))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            results.extend(_iter_strings(item, f"{path}[{i}]"))

    return results
