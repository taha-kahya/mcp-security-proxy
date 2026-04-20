"""Integration-style tests for the analyzer against fixture manifests."""

import json
from pathlib import Path

import pytest

from mcp_security_tester.manifest_collector.collector import load
from mcp_security_tester.static_analyzer.analyzer import analyze_manifest

FIXTURES = Path(__file__).parent.parent / "fixtures"


def test_clean_manifest_no_findings():
    tools = load(FIXTURES / "clean_manifest.json")
    findings = analyze_manifest(tools)
    assert findings == [], f"Expected no findings, got: {findings}"


def test_poisoned_manifest_has_critical():
    tools = load(FIXTURES / "poisoned_manifest.json")
    findings = analyze_manifest(tools)
    severities = {f.severity for f in findings}
    assert "CRITICAL" in severities, f"Expected CRITICAL finding, got severities: {severities}"


def test_poisoned_manifest_detects_secrecy():
    tools = load(FIXTURES / "poisoned_manifest.json")
    findings = analyze_manifest(tools)
    signals = {f.signal for f in findings}
    assert "secrecy_directive" in signals


def test_poisoned_manifest_detects_sensitive_path():
    tools = load(FIXTURES / "poisoned_manifest.json")
    findings = analyze_manifest(tools)
    signals = {f.signal for f in findings}
    assert "sensitive_path" in signals


def test_poisoned_manifest_detects_shadowing():
    tools = load(FIXTURES / "poisoned_manifest.json")
    findings = analyze_manifest(tools)
    signals = {f.signal for f in findings}
    assert "cross_tool_reference" in signals


def test_poisoned_manifest_detects_hidden_text():
    tools = load(FIXTURES / "poisoned_manifest.json")
    findings = analyze_manifest(tools)
    signals = {f.signal for f in findings}
    assert "hidden_text_unicode" in signals


def test_findings_sorted_by_severity():
    tools = load(FIXTURES / "poisoned_manifest.json")
    findings = analyze_manifest(tools)
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    for a, b in zip(findings, findings[1:]):
        assert order[a.severity] <= order[b.severity], "Findings not sorted by severity"


def test_full_schema_scan_catches_enum_poisoning():
    """Verify that poisoning inside enum values (not just description) is caught."""
    tools = load(FIXTURES / "poisoned_manifest.json")
    findings = analyze_manifest(tools)
    enum_findings = [f for f in findings if "enum" in f.field]
    assert enum_findings, "Expected findings from enum field scan (Full-Schema Poisoning)"
