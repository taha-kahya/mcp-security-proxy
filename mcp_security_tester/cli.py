"""
CLI entry point.

Commands:
  mcp-tester monitor --server "npx -y @modelcontextprotocol/server-filesystem ." --name filesystem
  mcp-tester scan    --manifest corpus/manifests/server.json   # offline static scan only
"""

import asyncio
import shlex
import sys
from datetime import datetime, timezone
from pathlib import Path

import click

from mcp_security_tester.core import collector
from mcp_security_tester.detection.attacks.tool_poisoning.analyzer import analyze_manifest
from mcp_security_tester.core.reporter import to_json, write_json
from mcp_security_tester.core.models import Report

_SEVERITY_COLORS = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "cyan", "LOW": "white"}


@click.group()
def main() -> None:
    """MCP Security Tester — runtime proxy and static scanner for MCP servers."""


@main.command()
@click.option("--server", "server_command", required=True,
              help="Command to spawn the real MCP server. E.g. 'npx -y @modelcontextprotocol/server-filesystem .'")
@click.option("--name", "server_name", default="proxy",
              help="Server name shown in alerts and logs.")
@click.option("--log", "log_path", default=None,
              help="Path to write JSONL call log. Defaults to mcp-security.jsonl in current dir.")
def monitor(server_command: str, server_name: str, log_path: str | None) -> None:
    """
    Start the security proxy. Point your MCP client at this instead of the real server.

    Update your Claude Desktop / Cursor config:

      "command": "mcp-tester",
      "args": ["monitor", "--name", "filesystem", "--server",
               "npx -y @modelcontextprotocol/server-filesystem ."]
    """
    from mcp_security_tester.proxy.server import MCPSecurityProxy

    command = shlex.split(server_command)
    resolved_log = log_path or "mcp-security.jsonl"

    click.echo(
        f"[mcp-security-proxy] Starting proxy for '{server_name}' → {server_command}",
        err=True,
    )
    click.echo(f"[mcp-security-proxy] Logging calls to {resolved_log}", err=True)

    proxy = MCPSecurityProxy(
        upstream_command=command,
        server_name=server_name,
        log_path=resolved_log,
    )
    asyncio.run(proxy.run())


@main.command()
@click.option("--manifest", "manifest_path", type=click.Path(exists=True), required=True,
              help="Path to a saved manifest JSON file.")
@click.option("--output", "output_path", default=None,
              help="Write JSON report to this file instead of stdout.")
def scan(manifest_path: str, output_path: str | None) -> None:
    """Offline static scan of a saved manifest file."""
    tools = collector.load(Path(manifest_path))
    click.echo(f"Scanning {manifest_path} ({len(tools)} tools)...", err=True)

    findings = analyze_manifest(tools)
    report = Report(
        target=Path(manifest_path).stem,
        timestamp=datetime.now(timezone.utc).isoformat(),
        findings=findings,
    )

    _print_summary(report)

    if output_path:
        write_json(report, output_path)
        click.echo(f"Report written to {output_path}", err=True)
    else:
        click.echo(to_json(report))

    if report.summary.get("CRITICAL", 0) > 0:
        sys.exit(2)
    if report.summary.get("HIGH", 0) > 0:
        sys.exit(1)


def _print_summary(report: Report) -> None:
    s = report.summary
    click.echo(
        f"\n{report.target}: "
        + click.style(f"{s['CRITICAL']} CRITICAL", fg="red", bold=True) + "  "
        + click.style(f"{s['HIGH']} HIGH", fg="yellow") + "  "
        + click.style(f"{s['MEDIUM']} MEDIUM", fg="cyan") + "  "
        + click.style(f"{s['LOW']} LOW", fg="white"),
        err=True,
    )
    for finding in report.sorted_findings():
        color = _SEVERITY_COLORS[finding.severity]
        click.echo(
            f"  [{click.style(finding.severity, fg=color)}] "
            f"{finding.tool_name} › {finding.field} "
            f"({finding.signal}): {finding.evidence[:80]}",
            err=True,
        )
