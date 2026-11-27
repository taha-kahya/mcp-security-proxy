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

from mcp_security_proxy.core.proxy.routing.table import RoutingTable
from mcp_security_proxy.sdk import ToolDefinition, ToolId, canonical_digest, thaw
from mcp_security_proxy.services.registry import DefinitionBaselines, Registry

logger = logging.getLogger(__name__)

TOOLS_LIST_CHANGED = "notifications/tools/list_changed"

# Lists one server's tools: the typed tools and, in transparent mode, their raw JSON.
ToolLister = Callable[
    [ClientSession], Awaitable[tuple[list[types.Tool], list[dict[str, Any]] | None]]
]


def canonical_form(transparent: bool) -> Callable[[Mapping[str, Any]], Mapping[str, Any]]:
    """The one form approved definitions are stored and compared in.

    Transparent mode inspects the upstream's raw JSON, so that is kept as is.
    Otherwise a definition is round-tripped through the current SDK's tool
    model, which is how the proxy builds the definitions it inspects, so a
    baseline stored by an older SDK, or in transparent mode, compares equal
    to an unchanged tool.
    """
    if transparent:
        return thaw

    def typed(definition: Mapping[str, Any]) -> Mapping[str, Any]:
        try:
            tool = types.Tool.model_validate(thaw(definition))
        except ValueError:
            return thaw(definition)
        return tool.model_dump(mode="json", by_alias=True, exclude_none=True)

    return typed


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
        """Everything that awaits (listing, building entries, approving new
        tools) happens first; the routing table and the Registry then change
        together with no await in between, so discovery and calls see the old
        listing or the new one, never a mix."""
        async with self._lock:
            try:
                tools, raw = await self._list_tools(self._sessions[server_id])
                entries = self._routing.entries_for(server_id, tools, raw)
            except Exception:
                logger.exception("re-discovery of %r failed; keeping its previous tools", server_id)
                return
            approvals: dict[ToolId, ToolDefinition] = {}
            for routed in entries:
                if self._registry.approved(routed.tool_id) is None:
                    body = routed.definition()
                    candidate = ToolDefinition(routed.tool_id, canonical_digest(body), body)
                    approvals[routed.tool_id] = await self._baselines.approve_if_new(candidate)

            listed = {routed.tool_id for routed in entries}
            gone = {t for t in self._registry.tool_ids() if t.server_id == server_id} - listed
            self._routing.replace_server_entries(server_id, entries)
            for tool_id in gone:
                self._registry.unregister(tool_id)
            for routed in entries:
                self._registry.register(routed.tool_id, routed.definition())
            for approved in approvals.values():
                self._registry.set_approved(approved)
            logger.info("re-discovered %d tools from %r", len(entries), server_id)

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
