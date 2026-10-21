"""Contract tests for the Streamable HTTP upstream launcher's handling of a
child process that exits before it ever starts listening.

Covers the two review findings on this path: a crashed upstream must fail
fast with its exit code instead of waiting out the full listen timeout and
then masking the real cause with a ProcessLookupError (issue 1), and that
same fast failure is also what prevents the proxy from silently adopting a
stale server left listening on the port from an earlier run (issue 2).
"""

from __future__ import annotations

import socket
import sys
import time

import pytest

from mcp_security_proxy.core.proxy.transport.streamable_http_client import (
    UpstreamProcessExited,
    spawn_streamable_http_upstream,
    wait_until_listening,
)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def test_wait_until_listening_fails_fast_on_exited_process() -> None:
    with pytest.raises(UpstreamProcessExited) as exc_info:
        wait_until_listening(lambda: 7, "127.0.0.1", _free_port(), timeout_seconds=10.0)
    assert exc_info.value.exit_code == 7


def test_wait_until_listening_still_times_out_while_process_is_alive() -> None:
    with pytest.raises(TimeoutError):
        wait_until_listening(lambda: None, "127.0.0.1", _free_port(), timeout_seconds=0.2)


async def test_spawn_fails_fast_with_exit_code_when_upstream_crashes_immediately() -> None:
    host, port = "127.0.0.1", _free_port()
    started = time.monotonic()

    with pytest.raises(UpstreamProcessExited) as exc_info:
        async with spawn_streamable_http_upstream(
            sys.executable,
            ["-c", "import sys; sys.exit(13)"],
            host,
            port,
            f"http://{host}:{port}/mcp",
        ):
            pass

    assert exc_info.value.exit_code == 13
    assert time.monotonic() - started < 5.0


async def test_spawn_does_not_adopt_a_stale_listener_on_the_configured_port() -> None:
    host, port = "127.0.0.1", _free_port()
    stale_listener = socket.socket()
    stale_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    stale_listener.bind((host, port))
    stale_listener.listen(1)
    try:
        with pytest.raises(UpstreamProcessExited):
            async with spawn_streamable_http_upstream(
                sys.executable,
                ["-c", "import sys; sys.exit(1)"],
                host,
                port,
                f"http://{host}:{port}/mcp",
            ):
                pass
    finally:
        stale_listener.close()


async def test_spawn_does_not_try_to_terminate_an_already_exited_process() -> None:
    host, port = "127.0.0.1", _free_port()

    try:
        async with spawn_streamable_http_upstream(
            sys.executable,
            ["-c", "import sys; sys.exit(1)"],
            host,
            port,
            f"http://{host}:{port}/mcp",
        ):
            pass
    except UpstreamProcessExited:
        pass
