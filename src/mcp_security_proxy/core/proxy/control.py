"""The security half of the request lifecycle: inspect, decide, and reserve.

For each stage, ProxyControl assembles trusted context (Policy, Registry,
History), runs the Runner, commits the signals and private-state changes
the defenses proposed, and asks Guard for a decision. It never dispatches
anything; the orchestrator does that with what this returns.

Every method except `serialized` must be called while holding
`serialized(principal)`, so that deciding a call and reserving it in
History happen against the same history, even under concurrent calls.

Before definitions are inspected, `prescan` (Scan's classifier stage, ADR
0026) scores them outside the defense deadline, so a defense only reads the
cached result.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from contextlib import AbstractAsyncContextManager, nullcontext
from dataclasses import dataclass, field
from typing import Any, Protocol

from mcp import types

from mcp_security_proxy.core.guard import Decision, Guard, Outcome
from mcp_security_proxy.core.identity import TaskResolver
from mcp_security_proxy.core.proxy.events import (
    delivery_event,
    discovery_event,
    error_event,
    execution_event,
    progress_event,
)
from mcp_security_proxy.core.proxy.instructions import STARTUP_PRINCIPAL, instructions_event
from mcp_security_proxy.core.proxy.locks import TaskLocks
from mcp_security_proxy.core.proxy.redaction import redact
from mcp_security_proxy.core.proxy.routing.table import RoutedTool
from mcp_security_proxy.core.runner import InspectionReport, InspectionScope, Runner
from mcp_security_proxy.sdk import (
    Action,
    Event,
    InspectionStatus,
    OperationRecord,
    OperationStatus,
    Principal,
    Stage,
    ToolDefinition,
    ToolId,
)
from mcp_security_proxy.services.history import History
from mcp_security_proxy.services.policy import PolicySnapshot, PrincipalPolicy
from mcp_security_proxy.services.registry import Registry
from mcp_security_proxy.services.state import DefenseStateStore, StateUnavailableError, TaskRef

_EXPOSED = frozenset({Outcome.ALLOW, Outcome.REDACT})


class DefinitionPrescan(Protocol):
    """Work done once per tool definition before it is inspected; its
    results stay readable until the block exits. Must not raise for a failed
    scan: a definition left unscored is reported by the defense that reads
    it as failed."""

    def prepared(
        self, definitions: Iterable[Mapping[str, Any]]
    ) -> AbstractAsyncContextManager[None]: ...


@dataclass(frozen=True)
class Discovery:
    visible: tuple[RoutedTool, ...]
    hidden_by_inspection: tuple[RoutedTool, ...]
    policy_version: str
    # external name -> the definition to expose, flagged fields replaced (D5)
    redacted: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)


@dataclass(frozen=True)
class CallAuthorization:
    """`hidden` means the principal may not learn that the tool exists, so a
    denial must look exactly like a nonexistent tool (0012)."""

    principal: Principal
    task: TaskRef
    correlation_id: str
    routed: RoutedTool | None
    action: Action | None
    decision: Decision
    reports: tuple[InspectionReport, ...]
    hidden: bool
    # The definition resolved when the call was authorised. Result reviews use
    # it, so re-discovery removing the tool mid-call can't break them (T2).
    definition: ToolDefinition | None = None

    @property
    def permits_dispatch(self) -> bool:
        return self.routed is not None and self.decision.permits_dispatch


@dataclass(frozen=True)
class DeliveryReview:
    """`inspected` is False when no defense inspects results."""

    decision: Decision
    reports: tuple[InspectionReport, ...]
    inspected: bool

    @property
    def releases_result(self) -> bool:
        return self.decision.outcome is Outcome.ALLOW


class ProxyControl:
    def __init__(
        self,
        *,
        policy: PolicySnapshot,
        tasks: TaskResolver,
        registry: Registry,
        history: History,
        defense_state: DefenseStateStore,
        runner: Runner,
        guard: Guard,
        locks: TaskLocks | None = None,
        prescan: DefinitionPrescan | None = None,
    ) -> None:
        self._policy = policy
        self._tasks = tasks
        self._registry = registry
        self._history = history
        self._defense_state = defense_state
        self._runner = runner
        self._guard = guard
        self._locks = locks or TaskLocks()
        self._prescan = prescan
        # Keyed by (task, tool, tool definition version, policy version). A
        # repeat `discover`/`authorize_call` for the same combination (one
        # `tools/list` inspects every visible tool; a call re-checks its
        # tool's definition) is served from here instead of re-running the
        # Runner and re-committing a duplicate signal to this task's History.
        # That is only sound while the result depends on nothing else, so
        # see `_cacheable`. Entries are never evicted: they are bounded by
        # the tool and policy versions seen in this process (ADR 0020).
        self._definition_cache: dict[
            tuple[TaskRef, ToolId, str, str], tuple[InspectionReport, ...]
        ] = {}

    def serialized(self, principal: Principal) -> AbstractAsyncContextManager[None]:
        return self._locks.hold(self._tasks.task_for(principal))

    async def discover(self, principal: Principal, tools: Iterable[RoutedTool]) -> Discovery:
        policy, task = self._policy.for_principal(principal), self._tasks.task_for(principal)
        visible: list[RoutedTool] = []
        hidden: list[RoutedTool] = []
        redacted: dict[str, Mapping[str, Any]] = {}
        discoverable: list[tuple[RoutedTool, ToolDefinition]] = []
        for routed in tools:
            if not policy.can_discover(routed.tool_id):
                continue
            definition = self._registry.current(routed.tool_id)
            if definition is None:
                continue  # removed by re-discovery since the listing was taken
            discoverable.append((routed, definition))
        # One batch for the tools not inspected yet, so the model runs once
        # per listing and never for a tool whose reports are cached.
        uninspected = self._uninspected(task, policy, (d for _, d in discoverable))
        async with self._prepared(uninspected):
            for routed, definition in discoverable:
                reports = await self._inspect_definition(
                    principal, task, policy, definition, prepared=True
                )
                review = self._guard.review(policy, reports)
                if review.outcome is Outcome.REDACT:
                    exposed = redact(definition.definition, review.redactions)
                    if exposed is None:
                        hidden.append(routed)
                        continue
                    redacted[routed.external_name] = exposed
                (visible if review.outcome in _EXPOSED else hidden).append(routed)
        return Discovery(tuple(visible), tuple(hidden), policy.policy_version, redacted)

    async def authorize_call(
        self,
        principal: Principal,
        routed: RoutedTool | None,
        arguments: Mapping[str, Any],
        correlation_id: str,
    ) -> CallAuthorization:
        policy, task = self._policy.for_principal(principal), self._tasks.task_for(principal)

        def authorization(
            decision: Decision,
            reports: tuple[InspectionReport, ...] = (),
            action: Action | None = None,
            hidden: bool = True,
        ) -> CallAuthorization:
            return CallAuthorization(
                principal,
                task,
                correlation_id,
                routed,
                action,
                decision,
                reports,
                hidden,
                definition,
            )

        definition = self._registry.current(routed.tool_id) if routed is not None else None
        if routed is None or definition is None or not policy.can_discover(routed.tool_id):
            # No definition means re-discovery removed the tool: it no longer exists.
            tool_id = routed.tool_id if routed is not None and definition is not None else None
            return authorization(self._guard.decide(tool_id, policy))

        # The same definition check that hides a tool from discovery also
        # applies to calls, so a hidden tool cannot be called by name.
        definition_reports = await self._inspect_definition(principal, task, policy, definition)
        review = self._guard.review(policy, definition_reports)
        if review.outcome is not Outcome.ALLOW:
            decision = self._guard.decide(routed.tool_id, policy, definition_reports)
            # A redacted tool is visible, so its denial may say so.
            visible = (
                review.outcome is Outcome.REDACT
                and redact(definition.definition, review.redactions) is not None
            )
            return authorization(decision, definition_reports, hidden=not visible)

        action = self._registry.action(routed.tool_id, arguments)
        event = execution_event(correlation_id, routed.tool_id, arguments, action)
        reports = await self._inspect(event, principal, task, policy, definition)
        decision = self._guard.decide(routed.tool_id, policy, reports)
        return authorization(decision, reports, action, hidden=False)

    async def reserve(self, authorization: CallAuthorization) -> OperationRecord:
        if authorization.routed is None or authorization.action is None:
            raise RuntimeError("reserve() requires an authorization that permits dispatch")
        return await self._history.reserve(
            authorization.task,
            correlation_id=authorization.correlation_id,
            tool_id=authorization.routed.tool_id,
            action=authorization.action,
        )

    async def finish(
        self, authorization: CallAuthorization, operation: OperationRecord, status: OperationStatus
    ) -> None:
        await self._history.finish(authorization.task, operation.operation_id, status)

    async def review_result(
        self, authorization: CallAuthorization, result: types.CallToolResult
    ) -> DeliveryReview:
        return await self._review_delivery(
            authorization,
            lambda routed, action: delivery_event(
                authorization.correlation_id, routed.tool_id, result, action
            ),
        )

    async def review_error(
        self, authorization: CallAuthorization, error: types.ErrorData
    ) -> DeliveryReview:
        """An upstream JSON-RPC error goes through delivery inspection too (I3)."""
        return await self._review_delivery(
            authorization,
            lambda routed, action: error_event(
                authorization.correlation_id, routed.tool_id, error, action
            ),
        )

    async def review_progress(
        self, authorization: CallAuthorization, progress: float, total: float | None, message: str
    ) -> DeliveryReview:
        """A progress message goes through delivery inspection before it is relayed (I3)."""
        return await self._review_delivery(
            authorization,
            lambda routed, action: progress_event(
                authorization.correlation_id, routed.tool_id, progress, total, message, action
            ),
        )

    async def _review_delivery(
        self,
        authorization: CallAuthorization,
        build: Callable[[RoutedTool, Action], Event],
    ) -> DeliveryReview:
        routed, action = authorization.routed, authorization.action
        if routed is None or action is None:
            raise RuntimeError("delivery review requires an authorization that permits dispatch")
        policy = self._policy.for_principal(authorization.principal)
        if not self._runner.applies_to(Stage.BEFORE_DELIVERY):
            return DeliveryReview(self._guard.review(policy, ()), (), inspected=False)

        definition = authorization.definition or self._registry.current(routed.tool_id)
        if definition is None:
            raise RuntimeError(f"no definition for {routed.tool_id} to review its result against")
        event = build(routed, action)
        reports = await self._inspect(
            event, authorization.principal, authorization.task, policy, definition
        )
        return DeliveryReview(self._guard.review(policy, reports), reports, inspected=True)

    async def inspect_instructions(self, server_id: str, text: str) -> tuple[InspectionReport, ...]:
        """A server's `initialize` instructions, inspected once at startup (I4).

        They reach every agent, so they are inspected as the proxy's own
        startup principal rather than any agent's.
        """
        if not self._runner.applies_to(Stage.BEFORE_DELIVERY):
            return ()
        principal = STARTUP_PRINCIPAL
        policy, task = self._policy.for_principal(principal), self._tasks.task_for(principal)
        scope = InspectionScope(
            principal=principal,
            task=task,
            policy=policy,
            registry=self._registry,
            history=await self._history.snapshot(task),
        )
        reports = await self._runner.inspect(instructions_event(server_id, text), scope)
        await self._commit(task, reports)
        return reports

    async def _inspect_definition(
        self,
        principal: Principal,
        task: TaskRef,
        policy: PrincipalPolicy,
        definition: ToolDefinition,
        *,
        prepared: bool = False,
    ) -> tuple[InspectionReport, ...]:
        """`prepared`: the caller holds a prescan of this tool, as
        `discover` does for its listing. Otherwise, for a call, the tool is
        prescanned on its own (a no-op when a listing already scored it)."""
        if not self._runner.applies_to(Stage.DISCOVERY):
            return ()
        cached = self._cached(task, policy, definition)
        if cached is not None:
            return cached
        async with nullcontext() if prepared else self._prepared([definition]):
            reports = await self._inspect(
                discovery_event(definition), principal, task, policy, definition
            )
        if self._cacheable(reports):
            key = (task, definition.tool_id, definition.version, policy.policy_version)
            self._definition_cache[key] = reports
        return reports

    def _cached(
        self, task: TaskRef, policy: PrincipalPolicy, definition: ToolDefinition
    ) -> tuple[InspectionReport, ...] | None:
        key = (task, definition.tool_id, definition.version, policy.policy_version)
        return self._definition_cache.get(key)

    def _uninspected(
        self, task: TaskRef, policy: PrincipalPolicy, definitions: Iterable[ToolDefinition]
    ) -> list[ToolDefinition]:
        if self._prescan is None or not self._runner.applies_to(Stage.DISCOVERY):
            return []
        return [d for d in definitions if self._cached(task, policy, d) is None]

    def _prepared(self, definitions: Iterable[ToolDefinition]) -> AbstractAsyncContextManager[None]:
        if self._prescan is None or not self._runner.applies_to(Stage.DISCOVERY):
            return nullcontext()
        return self._prescan.prepared([d.definition for d in definitions])

    def _cacheable(self, reports: Iterable[InspectionReport]) -> bool:
        """A failed inspection may be transient (a timeout, a raised error),
        so caching it would keep the tool hidden until its definition or the
        policy changes. A defense that reads History or private state may
        decide differently later for the same definition."""
        return self._runner.depends_only_on_event(Stage.DISCOVERY) and all(
            r.status is not InspectionStatus.FAILED for r in reports
        )

    async def _inspect(
        self,
        event: Event,
        principal: Principal,
        task: TaskRef,
        policy: PrincipalPolicy,
        definition: ToolDefinition,
    ) -> tuple[InspectionReport, ...]:
        scope = InspectionScope(
            principal=principal,
            task=task,
            policy=policy,
            registry=self._registry,
            history=await self._history.snapshot(task),
            tool_version=definition.version,
        )
        reports = await self._runner.inspect(event, scope)
        await self._commit(task, reports)
        return reports

    async def _commit(self, task: TaskRef, reports: Iterable[InspectionReport]) -> None:
        """Commit what defenses proposed before anything is released.

        Signals and private-state changes go in one atomic update: if a
        private-state proposal is stale, the inspection's signals are not
        kept in History either.
        """
        reports = list(reports)
        proposals = {
            r.defense_id: r.result.state_changes for r in reports if r.result.state_changes
        }
        committed = await self._history.record_signals(
            task,
            (s for r in reports for s in r.result.signals),
            alongside=self._defense_state.changes(task, proposals),
        )
        if not committed.applied:
            stale = sorted({change.scope.owner for change in committed.conflicts})
            raise StateUnavailableError(f"stale private-state proposals from {stale}")
