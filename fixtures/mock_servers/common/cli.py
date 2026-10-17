"""Shared CLI argument parsing for the mock MCP servers."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import Literal


@dataclass(frozen=True)
class MockServerArgs:
    audit_log: Path
    transport: Literal["stdio", "streamable-http"]
    host: str
    port: int


def parse_mock_server_args(
    *, description: str, default_audit_log: Path, default_port: int
) -> MockServerArgs:
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--audit-log", type=Path, default=default_audit_log)
    parser.add_argument("--transport", choices=["stdio", "streamable-http"], default="stdio")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=default_port)
    args = parser.parse_args()
    return MockServerArgs(
        audit_log=args.audit_log,
        transport=args.transport,
        host=args.host,
        port=args.port,
    )
