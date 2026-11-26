"""Re-discover a server's tools when it announces a change (plan MR T2).

An upstream sends `notifications/tools/list_changed` when its tool list
changes. The proxy then lists that server's tools again, replaces its
routing entries, and registers each definition, so the Registry's current
version is what the server serves now. Approved versions (first sight,
kept in the state backend) don't change, so a drift defense can compare
the two. Calls are inspected against the current definition, so a change
is enforced on the next call even if the agent never re-lists.

The agent is not told about the change: from protocol 2026-07-28 change
notifications travel on `subscriptions/listen` streams, which the proxy
doesn't serve yet. Its next `tools/list` shows the new definitions.

A refresh that fails (the server errors or lists a colliding name) leaves
the previous listing in place and is logged.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable, Mapping
from typing import Any

import anyio
from mcp import ClientSession, types
from mcp.client.session import MessageHandlerFnT

from mcp_security_proxy.core.proxy.routing.table import RoutedTool, RoutingTable
from mcp_security_proxy.services.registry import DefinitionBaselines, Registry

logger = logging.getLogger(__name__)

TOOLS_LIST_CHANGED = "notifications/tools/list_changed"

# Lists one server's tools: the typed tools and, in transparent mode, their raw JSON.
ToolLister = Callable[
    [ClientSession], Awaitable[tuple[list[types.Tool], list[dict[str, Any]] | None]]
]


def definition_of(routed: RoutedTool) -> Mapping[str, Any]:
    """What defenses and the version digest see: the raw object when kept
    (transparent mode), otherwise the typed tool's JSON."""
    if routed.raw is not None:
        return routed.raw
    return routed.tool.model_dump(mode="json", by_alias=True, exclude_none=True)


def _method(message: object) -> str | None:
    method = getattr(message, "method", None)
    if method is None:
        method = getattr(getattr(message, "root", None), "method", None)
    return method if isinstance(method, str) else None


class UpstreamNotifications:
    """Message handlers for upstream sessions, bound to a refresher once the
    proxy has discovered tools; a notification before that is ignored, since
    the initial discovery lists everything anyway."""

    def __init__(self) -> None:
        self._on_tools_changed: Callable[[str], None] | None = None

    def handler(self, server_id: str) -> MessageHandlerFnT:
        async def handle(message: object) -> None:
            if _method(message) == TOOLS_LIST_CHANGED and self._on_tools_changed is not None:
                self._on_tools_changed(server_id)
            await anyio.lowlevel.checkpoint()

        return handle

    def bind(self, on_tools_changed: Callable[[str], None]) -> None:
        self._on_tools_changed = on_tools_changed


class ToolRefresher:
    def __init__(
        self,
        sessions: Mapping[str, ClientSession],
        routing: RoutingTable,
        registry: Registry,
        baselines: DefinitionBaselines,
        list_tools: ToolLister,
    ) -> None:
        self._sessions = sessions
        self._routing = routing
        self._registry = registry
        self._baselines = baselines
        self._list_tools = list_tools
        self._lock = asyncio.Lock()
        self._tasks: set[asyncio.Task[None]] = set()

    def schedule(self, server_id: str) -> None:
        """Called from the session's receive loop, which must not wait on a
        request to the same session, so the refresh runs as its own task."""
        task = asyncio.get_running_loop().create_task(self.refresh(server_id))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def refresh(self, server_id: str) -> None:
        async with self._lock:
            try:
                tools, raw = await self._list_tools(self._sessions[server_id])
                self._routing.replace_server_tools(server_id, tools, raw)
            except Exception:
                logger.exception("re-discovery of %r failed; keeping its previous tools", server_id)
                return
            listed = [r for r in self._routing.entries() if r.server_id == server_id]
            for gone in {t for t in self._registry.tool_ids() if t.server_id == server_id} - {
                r.tool_id for r in listed
            }:
                self._registry.unregister(gone)
            for routed in listed:
                current = self._registry.register(routed.tool_id, definition_of(routed))
                if self._registry.approved(routed.tool_id) is None:
                    self._registry.set_approved(await self._baselines.approve_if_new(current))
            logger.info("re-discovered %d tools from %r", len(listed), server_id)

    async def wait_idle(self) -> None:
        """Wait for scheduled refreshes; for tests and shutdown."""
        while self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)

    async def aclose(self) -> None:
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)


async def approve_current_definitions(registry: Registry, baselines: DefinitionBaselines) -> None:
    """At startup: each tool's approved version, stored on first sight."""
    for tool_id in registry.tool_ids():
        current = registry.current(tool_id)
        if current is not None:
            registry.set_approved(await baselines.approve_if_new(current))
