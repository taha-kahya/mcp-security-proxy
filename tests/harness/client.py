"""Scripted, deterministic MCP client used to drive proxy acceptance tests.

Spawns the real proxy process (over stdio or Streamable HTTP, matching
Config A/B), exactly as a real agent would, rather than importing proxy
internals directly. No LLM is involved: call sequences are exact and
assertions are on exact responses/errors.

Every config built here has an identity, a policy file, and a proxy audit
log. Unless a test passes its own, the policy allows `DEFAULT_PRINCIPAL`
everything on every configured server, and that principal authenticates
over stdio by configuration and over HTTP with `DEFAULT_TOKEN`.
"""

from __future__ import annotations

import asyncio
import socket
import sys
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx2
import yaml
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.client.streamable_http import streamable_http_client

from mcp_security_proxy.core.identity import hash_token
from mcp_security_proxy.core.proxy.transport.streamable_http_client import wait_until_listening

REPO_ROOT = Path(__file__).resolve().parents[2]

DEFAULT_PRINCIPAL = "test-agent"
DEFAULT_TOKEN = "test-agent-token"
PROXY_AUDIT_LOG = "proxy_audit.jsonl"

# Same defaults the SDK uses for its own HTTP client (30s, 5 min for SSE reads).
_HTTP_TIMEOUT = httpx2.Timeout(30.0, read=300.0)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def mock_server_entry(server_id: str, audit_log_path: Path, transport: str) -> dict[str, Any]:
    module = f"fixtures.mock_servers.{server_id}"
    if transport == "stdio":
        return {
            "id": server_id,
            "command": sys.executable,
            "args": ["-m", module, "--audit-log", str(audit_log_path)],
        }

    port = free_port()
    return {
        "id": server_id,
        "transport": "streamable-http",
        "command": sys.executable,
        "args": [
            "-m",
            module,
            "--transport",
            "streamable-http",
            "--port",
            str(port),
            "--audit-log",
            str(audit_log_path),
        ],
        "host": "127.0.0.1",
        "port": port,
        "url": f"http://127.0.0.1:{port}/mcp",
    }


def allow_all_policy(principal_id: str, server_ids: list[str]) -> dict[str, Any]:
    rules = [{"tool": f"{server_id}/*", "effect": "allow"} for server_id in server_ids]
    return {"schema_version": 1, "principals": {principal_id: rules}}


def build_proxy_config(
    servers: list[dict[str, Any]],
    agent_transport: str,
    workdir: Path,
    *,
    policy: dict[str, Any] | None = None,
    principals_by_token: Mapping[str, str] | None = None,
    stdio_principal: str = DEFAULT_PRINCIPAL,
    defenses: list[dict[str, Any]] | None = None,
    tool_operations: Mapping[str, str] | None = None,
    state_path: Path | None = None,
) -> dict[str, Any]:
    """Write the policy file into `workdir` and return a config referencing it.

    The proxy's own audit log is `workdir / PROXY_AUDIT_LOG`. `defenses` are
    defense config documents, written one file each; `tool_operations` maps
    `server_id/tool` to an operation; `state_path` selects SQLite state.
    """
    if policy is None:
        policy = allow_all_policy(DEFAULT_PRINCIPAL, [server["id"] for server in servers])
    if principals_by_token is None:
        principals_by_token = {DEFAULT_TOKEN: DEFAULT_PRINCIPAL}

    policy_path = workdir / "policy.yaml"
    policy_path.write_text(yaml.safe_dump(policy), encoding="utf-8")

    config: dict[str, Any] = {
        "agent_transport": agent_transport,
        "identity": {
            "stdio_principal": stdio_principal,
            "bearer_tokens": [
                {"principal": principal, "token_sha256": hash_token(token)}
                for token, principal in principals_by_token.items()
            ],
        },
        "policy_path": str(policy_path),
        "audit_log_path": str(workdir / PROXY_AUDIT_LOG),
        "servers": servers,
    }
    if defenses:
        defenses_dir = workdir / "defenses"
        defenses_dir.mkdir(exist_ok=True)
        for document in defenses:
            (defenses_dir / f"{document['id']}.yaml").write_text(
                yaml.safe_dump(document), encoding="utf-8"
            )
        config["defenses_path"] = str(defenses_dir)
    if tool_operations:
        tools_path = workdir / "tools.yaml"
        tools = {tool: {"operation": op} for tool, op in tool_operations.items()}
        tools_path.write_text(yaml.safe_dump({"schema_version": 1, "tools": tools}), "utf-8")
        config["tools_path"] = str(tools_path)
    if state_path is not None:
        config["state"] = {"backend": "sqlite", "path": str(state_path)}
    if agent_transport == "streamable-http":
        config["agent_host"] = "127.0.0.1"
        config["agent_port"] = free_port()
    return config


PROXY_MODULE_ARGS = ["-m", "mcp_security_proxy.app.main", "--config"]


def write_config(config: dict[str, Any], config_path: Path) -> None:
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")


@asynccontextmanager
async def running_http_proxy(config: dict[str, Any], config_path: Path) -> AsyncIterator[str]:
    """Run the proxy's Streamable HTTP listener and yield its MCP endpoint URL."""
    write_config(config, config_path)
    host, port = config["agent_host"], config["agent_port"]
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        *PROXY_MODULE_ARGS,
        str(config_path),
        cwd=str(REPO_ROOT),
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        await asyncio.to_thread(wait_until_listening, lambda: process.returncode, host, port)
        yield f"http://{host}:{port}/mcp"
    finally:
        if process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=5)
            except TimeoutError:
                process.kill()
                await process.wait()


@asynccontextmanager
async def proxy_session(
    config: dict[str, Any], config_path: Path, bearer_token: str | None = DEFAULT_TOKEN
) -> AsyncIterator[ClientSession]:
    """Start the proxy and yield an initialized client session to it.

    `bearer_token` is sent as the `Authorization` header over Streamable HTTP
    (None sends no header); it is ignored over stdio.
    """
    if config["agent_transport"] == "stdio":
        write_config(config, config_path)
        params = StdioServerParameters(
            command=sys.executable,
            args=[*PROXY_MODULE_ARGS, str(config_path)],
            cwd=str(REPO_ROOT),
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                yield session
        return

    headers = {"Authorization": f"Bearer {bearer_token}"} if bearer_token else {}
    async with (
        running_http_proxy(config, config_path) as url,
        httpx2.AsyncClient(headers=headers, timeout=_HTTP_TIMEOUT) as http_client,
        streamable_http_client(url, http_client=http_client) as streams,
    ):
        read, write = streams[0], streams[1]
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield session
