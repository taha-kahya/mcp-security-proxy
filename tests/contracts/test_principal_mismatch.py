"""Startup warns, without refusing, when policy and identity principals disagree."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from mcp_security_proxy.app.config import BearerTokenConfig, IdentityConfig, ProxyConfig
from mcp_security_proxy.app.wiring import warn_about_principal_mismatches
from mcp_security_proxy.services.policy import PolicySnapshot, parse_policy


def _policy_for(*principal_ids: str) -> PolicySnapshot:
    return parse_policy(
        {
            "schema_version": 1,
            "principals": {
                principal_id: [{"tool": "server_a/*", "effect": "allow"}]
                for principal_id in principal_ids
            },
        }
    )


def _config(**overrides: object) -> ProxyConfig:
    return ProxyConfig.model_validate(
        {"policy_path": Path("p.yaml"), "audit_log_path": Path("a.jsonl"), "servers": []}
        | overrides
    )


def test_stdio_config_authenticates_only_its_static_principal() -> None:
    config = _config(identity=IdentityConfig(stdio_principal="local-agent"))
    assert config.agent_principal_ids() == {"local-agent"}


def test_http_config_authenticates_its_token_principals() -> None:
    config = _config(
        agent_transport="streamable-http",
        identity=IdentityConfig(
            stdio_principal="unused",
            bearer_tokens=[
                BearerTokenConfig(principal="alice", token_sha256="0" * 64),
                BearerTokenConfig(principal="bob", token_sha256="1" * 64),
            ],
        ),
    )
    assert config.agent_principal_ids() == {"alice", "bob"}


def test_matching_principals_do_not_warn(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING):
        warn_about_principal_mismatches(_policy_for("alice"), frozenset({"alice"}))
    assert not caplog.records


def test_policy_principal_without_identity_warns(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING):
        warn_about_principal_mismatches(_policy_for("alice", "alcie"), frozenset({"alice"}))
    assert "'alcie' matches no configured identity" in caplog.text


def test_identity_without_policy_warns(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING):
        warn_about_principal_mismatches(_policy_for("alice"), frozenset({"alice", "bob"}))
    assert "'bob' has no policy entry" in caplog.text
