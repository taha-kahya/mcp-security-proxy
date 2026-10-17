from __future__ import annotations

import argparse
from pathlib import Path

from mock_servers.server_b.server import build_server


def main() -> None:
    parser = argparse.ArgumentParser(description="Mock MCP server B (stdio)")
    parser.add_argument(
        "--audit-log",
        type=Path,
        default=Path("server_b_audit.jsonl"),
        help="Path to the append-only JSONL audit log.",
    )
    args = parser.parse_args()
    build_server(args.audit_log).run(transport="stdio")


if __name__ == "__main__":
    main()
