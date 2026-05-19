import dataclasses
import json
import shlex
import sys
import time
from datetime import datetime, timezone

import mcp.types as types
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.server import Server
from mcp.server.stdio import stdio_server

from mcp_security_tester.anomaly_detector.detector import AnomalyDetector
from mcp_security_tester.call_logger.logger import CallLogger, ToolCall
from mcp_security_tester.proxy.manifest_watcher import ManifestWatcher
from mcp_security_tester.proxy.output_scanner import OutputScanner
from mcp_security_tester.reports.models import Finding


class MCPSecurityProxy:
    def __init__(
        self,
        upstream_command: list[str],
        server_name: str = "proxy",
        log_path: str | None = None,
    ):
        self.upstream_command = upstream_command
        self.server_name = server_name
        self.manifest_watcher = ManifestWatcher(server_name)
        self.output_scanner = OutputScanner()
        self.call_logger = CallLogger(log_path=log_path)
        self.anomaly_detector = AnomalyDetector()

    async def run(self) -> None:
        params = StdioServerParameters(
            command=self.upstream_command[0],
            args=self.upstream_command[1:],
        )

        async with stdio_client(params) as (upstream_read, upstream_write):
            async with ClientSession(upstream_read, upstream_write) as upstream:
                await upstream.initialize()

                app = Server(f"mcp-security-proxy:{self.server_name}")

                @app.list_tools()
                async def handle_list_tools() -> list[types.Tool]:
                    result = await upstream.list_tools()
                    tools_raw = [_tool_to_dict(t) for t in result.tools]

                    findings = self.manifest_watcher.watch(tools_raw)
                    for f in findings:
                        _alert(f)

                    self.anomaly_detector.set_approved_tools([t.name for t in result.tools])
                    return result.tools

                @app.call_tool()
                async def handle_call_tool(
                    name: str, arguments: dict
                ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
                    start = time.monotonic()
                    result = await upstream.call_tool(name, arguments)
                    duration_ms = (time.monotonic() - start) * 1000

                    output_findings = self.output_scanner.scan(name, result.content)
                    response_text = _extract_text(result.content)

                    call = ToolCall(
                        tool_name=name,
                        arguments=arguments or {},
                        response_text=response_text,
                        duration_ms=duration_ms,
                        findings=output_findings,
                    )
                    self.call_logger.log(call)

                    anomaly_findings = self.anomaly_detector.check(self.call_logger.recent())
                    for f in output_findings + anomaly_findings:
                        _alert(f)

                    # Return full result to preserve structuredContent (MCP protocol 2025-11-25)
                    return result

                async with stdio_server() as (read_stream, write_stream):
                    await app.run(
                        read_stream,
                        write_stream,
                        app.create_initialization_options(),
                    )


def _alert(finding: Finding) -> None:
    payload = {
        "alert": True,
        "level": finding.severity,
        "signal": finding.signal,
        "tool": finding.tool_name,
        "detail": finding.evidence,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    print(json.dumps(payload), file=sys.stderr)


def _tool_to_dict(tool) -> dict:
    try:
        return tool.model_dump()
    except AttributeError:
        return vars(tool)


def _extract_text(content: list) -> str:
    parts: list[str] = []
    for item in content:
        if isinstance(item, dict) and item.get("type") == "text":
            parts.append(item.get("text", ""))
        elif hasattr(item, "text"):
            parts.append(item.text)
    return " ".join(parts)
