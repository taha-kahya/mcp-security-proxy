"""Pure-logic tests for policy parsing, versioning, and default-deny matching."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from mcp_security_proxy.sdk import Principal, ToolId
from mcp_security_proxy.services.policy import (
    Effect,
    PolicyError,
    ToolPattern,
    load_policy,
    parse_policy,
)

ALICE = Principal(id="alice", authenticated_by="test")
BOB = Principal(id="bob", authenticated_by="test")


def _policy(principals: dict[str, list[dict[str, str]]]) -> dict[str, Any]:
    return {"schema_version": 1, "principals": principals}


def _rule(tool: str, effect: str = "allow") -> dict[str, str]:
    return {"tool": tool, "effect": effect}


def test_tool_pattern_parses_exact_and_wildcard_forms() -> None:
    assert ToolPattern.parse("server_a/read_record") == ToolPattern("server_a", "read_record")
    assert ToolPattern.parse("server_a/*").is_wildcard


@pytest.mark.parametrize("text", ["server_a", "/read", "server_a/", "a/b/c", "*/read_record"])
def test_tool_pattern_rejects_malformed_or_server_wildcards(text: str) -> None:
    with pytest.raises(ValueError):
        ToolPattern.parse(text)


def test_wildcard_matches_only_its_own_server() -> None:
    pattern = ToolPattern.parse("server_a/*")
    assert pattern.matches(ToolId("server_a", "send_message"))
    assert not pattern.matches(ToolId("server_b", "send_message"))


def test_unlisted_principal_and_unlisted_tool_are_denied_by_default() -> None:
    snapshot = parse_policy(_policy({"alice": [_rule("server_a/read_record")]}))

    assert snapshot.for_principal(ALICE).rule_for(ToolId("server_a", "write_record")) is None
    assert snapshot.for_principal(BOB).rule_for(ToolId("server_a", "read_record")) is None
    assert not snapshot.for_principal(BOB).can_discover(ToolId("server_a", "read_record"))


def test_exact_rule_takes_precedence_over_wildcard_regardless_of_order() -> None:
    snapshot = parse_policy(
        _policy(
            {
                "alice": [
                    {"tool": "server_a/*", "effect": "allow"},
                    {"tool": "server_a/write_record", "effect": "require_approval"},
                ]
            }
        )
    )
    policy = snapshot.for_principal(ALICE)

    write_rule = policy.rule_for(ToolId("server_a", "write_record"))
    read_rule = policy.rule_for(ToolId("server_a", "read_record"))
    assert write_rule is not None and write_rule.effect == Effect.REQUIRE_APPROVAL
    assert read_rule is not None and read_rule.effect == Effect.ALLOW


def test_rule_ids_name_the_principal_and_pattern() -> None:
    snapshot = parse_policy(_policy({"alice": [{"tool": "server_a/*", "effect": "allow"}]}))
    rule = snapshot.for_principal(ALICE).rule_for(ToolId("server_a", "read_record"))
    assert rule is not None and rule.rule_id == "policy:alice:server_a/*"


def test_version_ignores_formatting_but_changes_with_content(tmp_path: Path) -> None:
    compact = tmp_path / "compact.yaml"
    spaced = tmp_path / "spaced.yaml"
    compact.write_text(
        "schema_version: 1\nprincipals: {alice: [{tool: server_a/*, effect: allow}]}\n",
        encoding="utf-8",
    )
    spaced.write_text(
        "# comment\nschema_version: 1\nprincipals:\n  alice:\n"
        "    - tool: server_a/*\n      effect: allow\n",
        encoding="utf-8",
    )
    changed = parse_policy(_policy({"alice": [_rule("server_a/*", "require_approval")]}))

    assert load_policy(compact).version == load_policy(spaced).version
    assert load_policy(compact).version != changed.version
    assert changed.version.startswith("sha256:")


@pytest.mark.parametrize(
    "document",
    [
        {"principals": {}},
        {"schema_version": 2, "principals": {}},
        _policy({"alice": [{"tool": "server_a/*", "effect": "deny"}]}),
        _policy({"alice": [{"tool": "not-a-pattern", "effect": "allow"}]}),
        _policy({"alice": [{"tool": "server_a/*", "effect": "allow", "extra": "x"}]}),
        _policy(
            {
                "alice": [
                    {"tool": "server_a/*", "effect": "allow"},
                    {"tool": "server_a/*", "effect": "require_approval"},
                ]
            }
        ),
    ],
)
def test_invalid_documents_are_rejected(document: dict[str, Any]) -> None:
    with pytest.raises(PolicyError):
        parse_policy(document)


def test_missing_policy_file_is_a_policy_error(tmp_path: Path) -> None:
    with pytest.raises(PolicyError):
        load_policy(tmp_path / "missing.yaml")


def test_unmatched_patterns_reports_unknown_servers_and_tools() -> None:
    snapshot = parse_policy(
        _policy(
            {
                "alice": [
                    {"tool": "server_a/read_record", "effect": "allow"},
                    {"tool": "server_a/typo", "effect": "allow"},
                    {"tool": "server_z/*", "effect": "allow"},
                ]
            }
        )
    )
    known = [ToolId("server_a", "read_record"), ToolId("server_b", "read_record")]

    assert [str(p) for p in snapshot.unmatched_patterns(known)] == [
        "server_a/typo",
        "server_z/*",
    ]
