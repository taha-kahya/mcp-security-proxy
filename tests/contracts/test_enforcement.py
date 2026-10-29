"""Enforcement defaults, per-defense overrides, and their effect on the policy version."""

from __future__ import annotations

from typing import Any

import pytest

from mcp_security_proxy.sdk import Finding, InspectionStatus, Severity
from mcp_security_proxy.services.policy import Enforcement, PolicyError, parse_policy

BASE: dict[str, Any] = {"schema_version": 1, "principals": {"alice": []}}


def _finding(rule_id: str = "sample.rule", severity: Severity = Severity.LOW) -> Finding:
    return Finding(rule_id, "sample", severity, "reason")


def test_everything_blocks_when_nothing_is_configured() -> None:
    rules = parse_policy(BASE).enforcement.for_defense("any")

    assert rules.for_finding(_finding(severity=Severity.LOW)) is Enforcement.BLOCK
    assert rules.for_status(InspectionStatus.FAILED) is Enforcement.BLOCK
    assert rules.for_status(InspectionStatus.UNSUPPORTED) is Enforcement.BLOCK
    assert rules.for_status(InspectionStatus.NOT_APPLICABLE) is Enforcement.ALLOW


def test_policy_defaults_apply_to_every_defense() -> None:
    policy = parse_policy(
        BASE | {"enforcement": {"by_severity": {"low": "allow"}, "on_unsupported": "allow"}}
    )
    rules = policy.enforcement.for_defense("any")

    assert rules.for_finding(_finding(severity=Severity.LOW)) is Enforcement.ALLOW
    assert rules.for_finding(_finding(severity=Severity.HIGH)) is Enforcement.BLOCK
    assert rules.for_status(InspectionStatus.UNSUPPORTED) is Enforcement.ALLOW


def test_defense_override_applies_to_that_defense_only_and_merges_with_defaults() -> None:
    policy = parse_policy(
        BASE | {"enforcement": {"on_unsupported": "allow"}},
        {"budget": {"findings": {"budget.exceeded": "require_approval"}}},
    )
    budget = policy.enforcement.for_defense("budget")
    other = policy.enforcement.for_defense("other")

    assert budget.for_finding(_finding("budget.exceeded")) is Enforcement.REQUIRE_APPROVAL
    assert budget.for_finding(_finding("budget.other")) is Enforcement.BLOCK
    assert budget.for_status(InspectionStatus.UNSUPPORTED) is Enforcement.ALLOW
    assert other.for_finding(_finding("budget.exceeded")) is Enforcement.BLOCK


def test_overrides_are_part_of_the_policy_version() -> None:
    plain = parse_policy(BASE)
    overridden = parse_policy(BASE, {"budget": {"on_failure": "allow"}})

    assert plain.version != overridden.version
    assert parse_policy(BASE).version == plain.version


def test_loosened_overrides_are_reported() -> None:
    policy = parse_policy(
        BASE,
        {
            "observer": {"on_failure": "allow", "findings": {"observer.seen": "allow"}},
            "strict": {"on_failure": "block"},
        },
    )
    assert policy.enforcement.loosened_overrides() == {
        "observer": ["on_failure: allow (default block)", "finding observer.seen: allow"]
    }


@pytest.mark.parametrize(
    "enforcement",
    [{"on_failure": "ignore"}, {"by_severity": {"extreme": "block"}}, {"unknown_field": 1}],
)
def test_invalid_enforcement_is_rejected(enforcement: dict[str, Any]) -> None:
    with pytest.raises(PolicyError):
        parse_policy(BASE | {"enforcement": enforcement})
    with pytest.raises(PolicyError):
        parse_policy(BASE, {"budget": enforcement})
