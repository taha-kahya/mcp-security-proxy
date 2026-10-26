"""The agent-facing HTTP listener warns when it is not bound to loopback (0014)."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from mcp_security_proxy.app.agent_facing import build_agent_facing, is_loopback_host
from mcp_security_proxy.app.config import BearerTokenConfig, IdentityConfig, ProxyConfig


def _http_config(agent_host: str) -> ProxyConfig:
    return ProxyConfig(
        agent_transport="streamable-http",
        agent_host=agent_host,
        identity=IdentityConfig(
            bearer_tokens=[BearerTokenConfig(principal="alice", token_sha256="0" * 64)]
        ),
        policy_path=Path("policy.yaml"),
        audit_log_path=Path("audit.jsonl"),
        servers=[],
    )


@pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.2", "::1", "localhost"])
def test_loopback_hosts_are_recognised(host: str) -> None:
    assert is_loopback_host(host)


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.1.10", "proxy.example.com"])
def test_other_hosts_are_not_loopback(host: str) -> None:
    assert not is_loopback_host(host)


def test_http_listener_on_loopback_does_not_warn(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING):
        build_agent_facing(_http_config("127.0.0.1"))
    assert not caplog.records


def test_http_listener_off_loopback_warns(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING):
        build_agent_facing(_http_config("0.0.0.0"))
    assert "not a loopback address" in caplog.text
