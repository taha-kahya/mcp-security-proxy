from __future__ import annotations

from pathlib import Path

from fixtures.mock_servers.common.cli import parse_mock_server_args
from fixtures.mock_servers.server_a.server import build_server


def main() -> None:
    args = parse_mock_server_args(
        description="Mock MCP server A (stdio or streamable-http)",
        default_audit_log=Path("server_a_audit.jsonl"),
        default_port=8001,
    )
    server = build_server(args.audit_log)
    if args.transport == "stdio":
        server.run(transport="stdio")
    else:
        server.run(transport="streamable-http", host=args.host, port=args.port)


if __name__ == "__main__":
    main()
