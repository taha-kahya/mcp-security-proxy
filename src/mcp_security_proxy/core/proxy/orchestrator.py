"""The proxy's request lifecycle for tool discovery and tool calls.

For every call, under the task's lock: authorize it (inspection plus Guard),
record the decision, and either answer with a denial or reserve the
operation in History. Then, outside the lock: dispatch upstream, record the
outcome, inspect the result, and release or withhold it. The orchestrator
holds no policy rules and no detection logic of its own; it coordinates the
modules that do, and it is the only place that dispatches upstream.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable, Collection, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from types import MappingProxyType
from typing import Any, Protocol

import anyio
from mcp import types
from mcp.shared.exceptions import MCPError

from mcp_security_proxy.core.proxy.audit import (
    decision_record,
    delivery_record,
    discovery_record,
    outcome_record,
)
from mcp_security_proxy.core.proxy.codec.jsonrpc import (
    audit_unavailable_error,
    blocked_call_result,
    ensure_call_tool_result,
    state_unavailable_error,
    unknown_tool_error,
    withheld_error,
    withheld_result,
)
from mcp_security_proxy.core.proxy.control import CallAuthorization, ProxyControl
from mcp_security_proxy.core.proxy.routing.correlation import (
    CorrelationTracker,
    new_correlation_id,
)
from mcp_security_proxy.core.proxy.routing.table import RoutedTool, RoutingTable
from mcp_security_proxy.sdk import OperationRecord, OperationStatus, Principal
from mcp_security_proxy.services.log import AuditRecord, AuditSink, AuditWriteError
from mcp_security_proxy.services.state import StateUnavailableError

logger = logging.getLogger(__name__)

# Upstream errors after which the call may or may not have taken effect.
_OUTCOME_UNCERTAIN_ERROR_CODES = frozenset({types.CONNECTION_CLOSED, types.REQUEST_TIMEOUT})


_REDACTED_WIRE: ContextVar[Mapping[str, Mapping[str, Any]]] = ContextVar(
    "redacted_wire", default=MappingProxyType({})
)


class ProgressFnT(Protocol):
    """Receives an upstream `notifications/progress` for one call."""

    async def __call__(self, progress: float, total: float | None, message: str | None) -> None: ...


class ToolCaller(Protocol):
    """The one upstream capability the orchestrator needs (`ClientSession` satisfies it)."""

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        *,
        meta: types.RequestParamsMeta | None = None,
        progress_callback: ProgressFnT | None = None,
    ) -> types.CallToolResult: ...


class ProxyOrchestrator:
    def __init__(
        self,
        *,
        routing: RoutingTable,
        upstreams: Mapping[str, ToolCaller],
        control: ProxyControl,
        audit: AuditSink,
        correlation: CorrelationTracker,
        forward_meta: bool = False,
        unmasked_meta_keys: Collection[str] = (),
    ) -> None:
        self._routing = routing
        self._upstreams = upstreams
        self._control = control
        self._audit = audit
        self._correlation = correlation
        # `_meta` is opaque: it is forwarded and recorded, never consulted by
        # identity, policy, or any defense (0011). Off outside transparent mode.
        self._forward_meta = forward_meta
        self._unmasked_meta_keys = frozenset(unmasked_meta_keys)

    async def list_tools(self, principal: Principal) -> list[types.Tool]:
        with _state_required():
            async with self._control.serialized(principal):
                discovery = await self._control.discover(principal, self._routing.entries())
        await self._record_or_refuse(discovery_record(principal, discovery))
        # Transparent mode serializes the wire JSON; this request's redactions
        # (D5) must replace it too. The middleware runs in this same context.
        _REDACTED_WIRE.set(MappingProxyType(dict(discovery.redacted)))
        return [self._exposed(routed, discovery.redacted) for routed in discovery.visible]

    @staticmethod
    def _exposed(routed: RoutedTool, redacted: Mapping[str, Mapping[str, Any]]) -> types.Tool:
        definition = redacted.get(routed.external_name)
        if definition is None:
            return routed.external_tool()
        return types.Tool.model_validate({**definition, "name": routed.external_name})

    def wire_definition(self, external_name: str) -> Mapping[str, Any] | None:
        """The upstream's own JSON for an advertised tool, when captured, with
        this request's redactions applied."""
        routed = self._routing.find(external_name)
        if routed is None or routed.external_wire() is None:
            return None
        return _REDACTED_WIRE.get().get(external_name, routed.external_wire())

    async def call_tool(
        self,
        principal: Principal,
        external_name: str,
        arguments: dict[str, Any],
        meta: types.RequestParamsMeta | None = None,
        progress_callback: ProgressFnT | None = None,
    ) -> types.CallToolResult:
        """`progress_callback` relays the upstream's progress updates for this
        call to the agent, which asked for them with a progress token. It is
        used only where `_meta` is forwarded (transparent mode)."""
        meta = meta if self._forward_meta else None
        progress_callback = progress_callback if self._forward_meta else None
        routed = self._routing.find(external_name)
        with _state_required():
            async with self._control.serialized(principal):
                authorization = await self._control.authorize_call(
                    principal, routed, arguments, new_correlation_id()
                )
                await self._record_or_refuse(
                    decision_record(
                        authorization, external_name, arguments, meta, self._unmasked_meta_keys
                    )
                )
                if not authorization.permits_dispatch:
                    return self._deny(external_name, authorization)
                operation = await self._control.reserve(authorization)

        relay = self._progress_relay(authorization, progress_callback)
        try:
            result = await self._dispatch(authorization, operation, arguments, meta, relay)
        except MCPError as exc:
            raise await self._deliver_error(authorization, exc) from None
        finally:
            if relay is not None:
                await relay.aclose()
        return await self._deliver(authorization, result)

    @staticmethod
    def _deny(external_name: str, authorization: CallAuthorization) -> types.CallToolResult:
        """A tool the principal cannot discover gets the same error as a
        nonexistent one, so a hidden tool's existence never leaks (0012)."""
        if authorization.hidden:
            raise unknown_tool_error(external_name)
        decision = authorization.decision
        return blocked_call_result(decision.reason, decision.decision_id)

    async def _dispatch(
        self,
        authorization: CallAuthorization,
        operation: OperationRecord,
        arguments: dict[str, Any],
        meta: types.RequestParamsMeta | None,
        progress_callback: ProgressFnT | None,
    ) -> types.CallToolResult:
        routed = authorization.routed
        if routed is None:
            raise RuntimeError("_dispatch() requires an authorization that permits dispatch")
        self._correlation.begin(
            authorization.correlation_id, routed.server_id, routed.external_name
        )
        status, tool_error = OperationStatus.UNKNOWN, None
        try:
            upstream = self._upstreams[routed.server_id]
            call = upstream.call_tool(
                routed.bare_name, arguments, meta=meta, progress_callback=progress_callback
            )
            result = ensure_call_tool_result(routed.external_name, await call)
            status, tool_error = OperationStatus.COMPLETED, result.is_error
            return result
        except MCPError as exc:
            if exc.error.code not in _OUTCOME_UNCERTAIN_ERROR_CODES:
                status = OperationStatus.FAILED
            raise
        finally:
            # Anything else (cancellation included) leaves status UNKNOWN.
            self._correlation.end(authorization.correlation_id, status)
            await self._settle(authorization, routed, operation, status, tool_error)

    async def _settle(
        self,
        authorization: CallAuthorization,
        routed: RoutedTool,
        operation: OperationRecord,
        status: OperationStatus,
        tool_error: bool | None,
    ) -> None:
        """The call already happened and cannot be undone, so failures to
        record it are reported rather than raised. Shielded so a cancelled
        call still gets its outcome recorded. If History cannot be updated,
        the operation stays pending, which history rules still count."""
        with anyio.CancelScope(shield=True):
            try:
                await self._control.finish(authorization, operation, status)
            except StateUnavailableError:
                logger.exception("failed to finish operation %s", operation.operation_id)
            await self._record_after_dispatch(
                outcome_record(
                    principal=authorization.principal,
                    correlation_id=authorization.correlation_id,
                    decision_id=authorization.decision.decision_id,
                    tool_id=routed.tool_id,
                    status=status,
                    tool_error=tool_error,
                )
            )

    async def _deliver(
        self, authorization: CallAuthorization, result: types.CallToolResult
    ) -> types.CallToolResult:
        """Inspect a result before it reaches the agent. Withholding it does
        not undo the call, and the response says so."""
        with _state_required():
            async with self._control.serialized(authorization.principal):
                review = await self._control.review_result(authorization, result)
        if review.inspected:
            await self._record_or_refuse(delivery_record(authorization, review))
        if not review.releases_result:
            return withheld_result(review.decision.reason, review.decision.decision_id)
        return result

    async def _deliver_error(self, authorization: CallAuthorization, exc: MCPError) -> MCPError:
        """The error to raise for an upstream error: the upstream's own if
        inspection releases it, otherwise one that keeps its code but not its
        text (I3). Withholding it does not undo the call."""
        with _state_required():
            async with self._control.serialized(authorization.principal):
                review = await self._control.review_error(authorization, exc.error)
        if review.inspected:
            await self._record_or_refuse(delivery_record(authorization, review))
        if review.releases_result:
            return exc
        return withheld_error(exc.error.code, review.decision.reason, review.decision.decision_id)

    def _progress_relay(
        self, authorization: CallAuthorization, progress_callback: ProgressFnT | None
    ) -> _ProgressRelay | None:
        if progress_callback is None:
            return None

        async def review(progress: float, total: float | None, message: str) -> bool:
            async with self._control.serialized(authorization.principal):
                result = await self._control.review_progress(
                    authorization, progress, total, message
                )
            if result.inspected:
                await self._audit.write(delivery_record(authorization, result))
            return result.releases_result

        return _ProgressRelay(review, progress_callback)

    async def _record_or_refuse(self, record: AuditRecord) -> None:
        """Fail closed: nothing proceeds unless its record was written (0013)."""
        try:
            await self._audit.write(record)
        except AuditWriteError as exc:
            logger.error("refusing request: %s", exc)
            raise audit_unavailable_error() from exc

    async def _record_after_dispatch(self, record: AuditRecord) -> None:
        try:
            await self._audit.write(record)
        except AuditWriteError:
            logger.exception("failed to record outcome %s", record.record_id)


class _ProgressRelay:
    """Relays a call's progress updates to the agent, each message only if
    inspection releases it (I3).

    The upstream session calls this from its receive loop, which must not wait
    on the per-user lock, an inspection or an audit write: everything else that
    upstream sends, `tools/list` responses included, would wait too. So an
    update is queued and returns at once, and a worker task inspects and
    relays updates in order. The numbers carry no text and are always relayed;
    a message whose inspection or audit record fails is dropped, never relayed
    uninspected. `aclose` waits (briefly) for queued updates, so they reach the
    agent before the call's result.
    """

    DRAIN_SECONDS = 5.0

    def __init__(
        self,
        review: Callable[[float, float | None, str], Awaitable[bool]],
        forward: ProgressFnT,
    ) -> None:
        self._review = review
        self._forward = forward
        self._queue: asyncio.Queue[tuple[float, float | None, str | None] | None] = asyncio.Queue()
        self._worker: asyncio.Task[None] | None = None

    async def __call__(self, progress: float, total: float | None, message: str | None) -> None:
        if self._worker is None:
            self._worker = asyncio.get_running_loop().create_task(self._run())
        self._queue.put_nowait((progress, total, message))

    async def _run(self) -> None:
        while (update := await self._queue.get()) is not None:
            progress, total, message = update
            if message:
                try:
                    released = await self._review(progress, total, message)
                except Exception:
                    logger.exception("dropping a progress message that couldn't be inspected")
                    released = False
                if not released:
                    message = None
            try:
                await self._forward(progress, total, message)
            except Exception:
                logger.exception("failed to relay a progress update")

    async def aclose(self) -> None:
        if self._worker is None:
            return
        self._queue.put_nowait(None)
        try:
            await asyncio.wait_for(asyncio.shield(self._worker), self.DRAIN_SECONDS)
        except TimeoutError:
            logger.warning("progress updates still being inspected; no longer relaying them")
            self._worker.cancel()


@contextmanager
def _state_required() -> Iterator[None]:
    """Fail closed when History or defense state cannot be read or written."""
    try:
        yield
    except StateUnavailableError as exc:
        logger.error("refusing request: %s", exc)
        raise state_unavailable_error() from exc
