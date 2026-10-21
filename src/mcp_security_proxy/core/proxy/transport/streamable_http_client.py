"""Proxy's outbound Streamable HTTP connection to a single upstream MCP server.

Per 0003, the proxy still owns the upstream subprocess's lifecycle even over
HTTP. Unlike stdio, connecting doesn't reuse the subprocess's own stdio pipes:
the proxy must wait for the spawned process's HTTP listener to come up, then
connect by URL. Session resumption (Last-Event-ID) is explicitly out of scope
for V1 -- see 0008.
"""

from __future__ import annotations

import asyncio
import socket
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


class UpstreamProcessExited(RuntimeError):
    def __init__(self, exit_code: int) -> None:
        self.exit_code = exit_code
        super().__init__(f"upstream server process exited with code {exit_code} before listening")


def wait_until_listening(
    poll: Callable[[], int | None],
    host: str,
    port: int,
    timeout_seconds: float = 10.0,
    settle_seconds: float = 0.3,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        exit_code = poll()
        if exit_code is not None:
            raise UpstreamProcessExited(exit_code)
        try:
            with socket.create_connection((host, port), timeout=0.2):
                pass
        except OSError:
            time.sleep(0.05)
            continue
        time.sleep(settle_seconds)
        exit_code = poll()
        if exit_code is not None:
            raise UpstreamProcessExited(exit_code)
        return
    raise TimeoutError(f"upstream server did not start listening on {host}:{port}")


@asynccontextmanager
async def spawn_streamable_http_upstream(
    command: str, args: list[str], host: str, port: int, url: str
) -> AsyncIterator[ClientSession]:
    # stdout/stderr must never be inherited: if the proxy's own agent-facing
    # transport is stdio, an inherited stdout here would interleave this
    # subprocess's own output (e.g. uvicorn's access log) into the proxy's
    # stdio protocol stream and corrupt it.
    process = await asyncio.create_subprocess_exec(
        command,
        *args,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        await asyncio.to_thread(wait_until_listening, lambda: process.returncode, host, port)
        async with streamable_http_client(url) as streams:
            read, write = streams[0], streams[1]
            async with ClientSession(read, write) as session:
                await session.initialize()
                yield session
    finally:
        if process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=5)
            except TimeoutError:
                process.kill()
                await process.wait()
