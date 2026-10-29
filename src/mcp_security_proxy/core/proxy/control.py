"""The security half of the request lifecycle: inspect, decide, and reserve.

For each stage, ProxyControl assembles trusted context (Policy, Registry,
History), runs the Runner, commits the signals and private-state changes
the defenses proposed, and asks Guard for a decision. It never dispatches
anything; the orchestrator does that with what this returns.

Every method except `serialized` must be called while holding
`serialized(principal)`, so that deciding a call and reserving it in
History happen against the same history, even under concurrent calls.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from typing import Any

from mcp import types

from mcp_security_proxy.core.guard import Decision, Guard, Outcome
from mcp_security_proxy.core.identity import TaskResolver
from mcp_security_proxy.core.proxy.events import delivery_event, discovery_event, execution_event
from mcp_security_proxy.core.proxy.locks import TaskLocks
from mcp_security_proxy.core.proxy.routing.table import RoutedTool
from mcp_security_proxy.core.runner import InspectionReport, InspectionScope, Runner
from mcp_security_proxy.sdk import (
    Action,
    Event,
    OperationRecord,
    OperationStatus,
    Principal,
    Stage,
    ToolDefinition,
)
from mcp_security_proxy.services.history import History
from mcp_security_proxy.services.policy import PolicySnapshot, PrincipalPolicy
from mcp_security_proxy.services.registry import Registry
from mcp_security_proxy.services.state import DefenseStateStore, StateUnavailableError, TaskRef


@dataclass(frozen=True)
class Discovery:
    visible: tuple[RoutedTool, ...]
    hidden_by_inspection: tuple[RoutedTool, ...]
    policy_version: str


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
    ) -> None:
        self._policy = policy
        self._tasks = tasks
        self._registry = registry
        self._history = history
        self._defense_state = defense_state
        self._runner = runner
        self._guard = guard
        self._locks = locks or TaskLocks()

    def serialized(self, principal: Principal) -> AbstractAsyncContextManager[None]:
        return self._locks.hold(self._tasks.task_for(principal))

    async def discover(self, principal: Principal, tools: Iterable[RoutedTool]) -> Discovery:
        policy, task = self._policy.for_principal(principal), self._tasks.task_for(principal)
        visible: list[RoutedTool] = []
        hidden: list[RoutedTool] = []
        for routed in tools:
            if not policy.can_discover(routed.tool_id):
                continue
            reports = await self._inspect_definition(principal, task, policy, routed)
            review = self._guard.review(policy, reports)
            (visible if review.outcome is Outcome.ALLOW else hidden).append(routed)
        return Discovery(tuple(visible), tuple(hidden), policy.policy_version)

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
                principal, task, correlation_id, routed, action, decision, reports, hidden
            )

        if routed is None or not policy.can_discover(routed.tool_id):
            tool_id = routed.tool_id if routed is not None else None
            return authorization(self._guard.decide(tool_id, policy))

        # The same definition check that hides a tool from discovery also
        # applies to calls, so a hidden tool cannot be called by name.
        definition_reports = await self._inspect_definition(principal, task, policy, routed)
        if self._guard.review(policy, definition_reports).outcome is not Outcome.ALLOW:
            decision = self._guard.decide(routed.tool_id, policy, definition_reports)
            return authorization(decision, definition_reports)

        action = self._registry.action(routed.tool_id, arguments)
        event = execution_event(correlation_id, routed.tool_id, arguments, action)
        reports = await self._inspect(event, principal, task, policy, self._definition(routed))
        decision = self._guard.decide(routed.tool_id, policy, reports)
        return authorization(decision, reports, action, hidden=False)

    async def reserve(self, authorization: CallAuthorization) -> OperationRecord:
        assert authorization.routed is not None and authorization.action is not None
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
        routed, action = authorization.routed, authorization.action
        assert routed is not None and action is not None
        policy = self._policy.for_principal(authorization.principal)
        if not self._runner.applies_to(Stage.BEFORE_DELIVERY):
            return DeliveryReview(self._guard.review(policy, ()), (), inspected=False)

        event = delivery_event(authorization.correlation_id, routed.tool_id, result, action)
        reports = await self._inspect(
            event, authorization.principal, authorization.task, policy, self._definition(routed)
        )
        return DeliveryReview(self._guard.review(policy, reports), reports, inspected=True)

    def _definition(self, routed: RoutedTool) -> ToolDefinition:
        definition = self._registry.current(routed.tool_id)
        if definition is None:
            raise LookupError(f"routed tool {routed.tool_id} was never registered")
        return definition

    async def _inspect_definition(
        self, principal: Principal, task: TaskRef, policy: PrincipalPolicy, routed: RoutedTool
    ) -> tuple[InspectionReport, ...]:
        if not self._runner.applies_to(Stage.DISCOVERY):
            return ()
        definition = self._definition(routed)
        return await self._inspect(discovery_event(definition), principal, task, policy, definition)

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
        """Commit what defenses proposed before anything is released."""
        reports = list(reports)
        await self._history.record_signals(task, (s for r in reports for s in r.result.signals))
        proposals = {
            r.defense_id: r.result.state_changes for r in reports if r.result.state_changes
        }
        committed = await self._defense_state.commit(task, proposals)
        if not committed.applied:
            stale = sorted({change.scope.owner for change in committed.conflicts})
            raise StateUnavailableError(f"stale private-state proposals from {stale}")
